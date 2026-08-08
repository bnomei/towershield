//! Rule-set assembly, compile-time validation, and per-request evaluation.
//!
//! [`RuleSet`] is the serializable, mutable collection. [`CompiledRuleSet`]
//! is the startup-validated form used on the request path: disabled rules are
//! dropped, matchers are normalised for case policy, and regex patterns fail
//! fast via [`CompileError`].

use crate::{
    ShieldDecision, ShieldMatch,
    inspection::InspectionPath,
    matcher::{CaseSensitivity, MatchKind, PathMatcher},
    rule::{Rule, RuleDisposition},
};
use std::sync::Arc;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "regex")]
use regex::{Regex, RegexBuilder};

use thiserror::Error;

#[cfg(all(feature = "rayon", feature = "regex"))]
const PARALLEL_REGEX_COMPILE_THRESHOLD: usize = 256;

/// Schema version embedded in serialised rule files.
///
/// Bump when the on-disk / JSON shape of [`RuleSet`] changes incompatibly.
/// Rule *content* changes are covered by crate semver, not this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleSchemaVersion(pub u32);

impl RuleSchemaVersion {
    /// Schema version understood by this crate build.
    pub const CURRENT: Self = RuleSchemaVersion(1);
}

impl Default for RuleSchemaVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Versioned, ordered collection of declarative [`Rule`] values.
///
/// This is the authoring and serialization form. Call [`RuleSet::compile`]
/// once at process startup (or after a config reload) to obtain a
/// [`CompiledRuleSet`] for evaluation.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleSet {
    /// Schema version for forwards-compatibility checks by loaders.
    #[cfg_attr(feature = "serde", serde(rename = "schema-version"))]
    pub schema_version: RuleSchemaVersion,
    /// Ordered rules. Within each disposition pass, earlier list entries win.
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Empty rule set at [`RuleSchemaVersion::CURRENT`].
    ///
    /// Prefer [`crate::DEFAULT_RULES`] when you want the built-in denylist as
    /// a starting point rather than an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a rule at the end of the ordered list and return `self`.
    ///
    /// Within each disposition pass at evaluate time, earlier entries win.
    pub fn push(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Validate and lower all **enabled** rules into a [`CompiledRuleSet`].
    ///
    /// Disabled rules are omitted. Invalid regex patterns surface as
    /// [`CompileError::InvalidRegex`]. With the optional `rayon` feature,
    /// large custom sets compile in parallel; normal-sized sets stay
    /// sequential to avoid thread-pool scheduling overhead.
    pub fn compile(self) -> Result<CompiledRuleSet, CompileError> {
        #[cfg(feature = "rayon")]
        let lowered = {
            use rayon::prelude::*;

            if should_compile_in_parallel(&self.rules) {
                // Collect every result in indexed order before propagating an
                // error so multiple invalid regexes remain deterministic.
                self.rules
                    .into_par_iter()
                    .map(lower_rule)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                self.rules
                    .into_iter()
                    .map(lower_rule)
                    .collect::<Result<Vec<_>, _>>()?
            }
        };

        #[cfg(not(feature = "rayon"))]
        let lowered = self
            .rules
            .into_iter()
            .map(lower_rule)
            .collect::<Result<Vec<_>, _>>()?;

        let allow_count = lowered
            .iter()
            .flatten()
            .filter(|(disposition, _)| *disposition == RuleDisposition::Allow)
            .count();
        let deny_count = lowered.iter().flatten().count() - allow_count;
        let mut allow_rules = Vec::with_capacity(allow_count);
        let mut deny_rules = Vec::with_capacity(deny_count);
        for (disposition, compiled) in lowered.into_iter().flatten() {
            match disposition {
                RuleDisposition::Allow => allow_rules.push(compiled),
                RuleDisposition::Deny => deny_rules.push(compiled),
            }
        }
        Ok(CompiledRuleSet {
            allow_rules: allow_rules.into(),
            deny_rules: deny_rules.into(),
        })
    }
}

#[cfg(all(feature = "rayon", feature = "regex"))]
fn should_compile_in_parallel(rules: &[Rule]) -> bool {
    rules
        .iter()
        .filter(|rule| rule.enabled && matches!(&rule.matcher, PathMatcher::Regex(_)))
        .take(PARALLEL_REGEX_COMPILE_THRESHOLD)
        .count()
        == PARALLEL_REGEX_COMPILE_THRESHOLD
}

#[cfg(all(feature = "rayon", not(feature = "regex")))]
fn should_compile_in_parallel(_rules: &[Rule]) -> bool {
    false
}

fn lower_rule(rule: Rule) -> Result<Option<(RuleDisposition, CompiledRule)>, CompileError> {
    if !rule.enabled {
        return Ok(None);
    }
    let match_kind = MatchKind::from(&rule.matcher);
    let compiled = CompiledRule {
        id: rule.id,
        group: rule.group,
        match_kind,
        case: rule.case_sensitivity,
        inner: CompiledMatcher::new(rule.matcher, rule.case_sensitivity)?,
        builtin: rule.builtin,
    };
    Ok(Some((rule.disposition, compiled)))
}

/// Failure to lower a [`RuleSet`] into a [`CompiledRuleSet`].
///
/// Raised only for invalid regex patterns when the `regex` feature is
/// enabled. Exact, prefix, suffix, segment, contains, and wildcard matchers
/// always compile.
#[derive(Debug, Error)]
pub enum CompileError {
    /// A regex matcher pattern failed to compile (requires the `regex` feature).
    #[error("invalid regex in rule: {0}")]
    InvalidRegex(String),
}

/// One rule after compile-time normalisation (case fold, regex build).
#[derive(Debug, Clone)]
struct CompiledRule {
    id: crate::rule::RuleId,
    group: crate::rule::RuleGroup,
    match_kind: MatchKind,
    case: CaseSensitivity,
    inner: CompiledMatcher,
    builtin: bool,
}

#[derive(Debug, Clone)]
enum CompiledMatcher {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Segment(String),
    Contains(String),
    Wildcard(WildcardPattern),
    #[cfg(feature = "regex")]
    Regex(Regex),
}

impl CompiledMatcher {
    fn new(m: PathMatcher, case: CaseSensitivity) -> Result<Self, CompileError> {
        let normalize = |mut value: String| {
            if case == CaseSensitivity::Insensitive {
                value.make_ascii_lowercase();
            }
            value
        };
        Ok(match m {
            PathMatcher::Exact(s) => CompiledMatcher::Exact(normalize(s)),
            PathMatcher::Prefix(s) => CompiledMatcher::Prefix(normalize(s)),
            PathMatcher::Suffix(s) => CompiledMatcher::Suffix(normalize(s)),
            PathMatcher::Segment(s) => CompiledMatcher::Segment(normalize(s)),
            PathMatcher::Contains(s) => CompiledMatcher::Contains(normalize(s)),
            PathMatcher::Wildcard(s) => {
                CompiledMatcher::Wildcard(WildcardPattern::compile(normalize(s)))
            }
            #[cfg(feature = "regex")]
            PathMatcher::Regex(s) => {
                let re = RegexBuilder::new(&s)
                    .case_insensitive(case == CaseSensitivity::Insensitive)
                    .unicode(false)
                    .build()
                    .map_err(|e| CompileError::InvalidRegex(format!("{}: {}", s, e)))?;
                CompiledMatcher::Regex(re)
            }
        })
    }

    fn matches(&self, path: &str) -> bool {
        // Pattern strings were case-folded at compile; caller must pass the
        // form from InspectionPath::for_case so both sides agree.
        match self {
            CompiledMatcher::Exact(v) => path == v.as_str(),
            CompiledMatcher::Prefix(v) => path.starts_with(v.as_str()),
            CompiledMatcher::Suffix(v) => path.ends_with(v.as_str()),
            CompiledMatcher::Segment(v) => segment_match(path, v),
            CompiledMatcher::Contains(v) => path.contains(v.as_str()),
            CompiledMatcher::Wildcard(w) => w.matches(path),
            #[cfg(feature = "regex")]
            CompiledMatcher::Regex(re) => re.is_match(path),
        }
    }
}

/// Startup-compiled rules ready for per-request evaluation.
///
/// Cheap to clone: compiled allow and deny tables are shared via [`Arc`].
#[derive(Debug, Clone)]
pub struct CompiledRuleSet {
    allow_rules: Arc<[CompiledRule]>,
    deny_rules: Arc<[CompiledRule]>,
}

impl CompiledRuleSet {
    /// Decide allow/block for a path that has already been inspected.
    ///
    /// Evaluation order:
    /// 1. First matching **allow** → [`ShieldDecision::Allow`]
    /// 2. First matching **deny** → [`ShieldDecision::Block`]
    /// 3. No match → allow (fail open for unmatched application traffic)
    ///
    /// The request body and headers are never consulted; only
    /// [`InspectionPath`] forms participate.
    pub fn evaluate(&self, path: &InspectionPath<'_>) -> ShieldDecision {
        // Pass 1 – allow rules are absolute exclusions.
        for rule in self.allow_rules.iter() {
            if rule.inner.matches(path.for_case(rule.case)) {
                return ShieldDecision::Allow;
            }
        }

        // Pass 2 – deny rules.
        for rule in self.deny_rules.iter() {
            if rule.inner.matches(path.for_case(rule.case)) {
                return ShieldDecision::Block(ShieldMatch {
                    rule_id: rule.id.clone(),
                    group: rule.group.clone(),
                    match_kind: rule.match_kind,
                    is_builtin: rule.builtin,
                });
            }
        }

        ShieldDecision::Allow
    }
}

/// True when `segment` equals a complete `/`-delimited component of `path`.
///
/// The segment value itself must not contain `/`.
fn segment_match(path: &str, segment: &str) -> bool {
    path.split('/').any(|s| s == segment)
}

// ── Wildcard pattern ────────────────────────────────────────────────────────

/// Compiled `*` / `**` pattern used by [`PathMatcher::Wildcard`].
///
/// - `*` – any run of characters that does not include `/`
/// - `**` – any run of characters including `/`
#[derive(Debug, Clone)]
struct WildcardPattern {
    tokens: Vec<WildToken>,
}

#[derive(Debug, Clone)]
enum WildToken {
    Literal(String),
    /// `*` – non-slash run.
    Star,
    /// `**` – any run, may cross `/`.
    DoubleStar,
}

impl WildcardPattern {
    fn compile(pattern: String) -> Self {
        let mut tokens = Vec::new();
        let mut lit = String::new();
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '*' {
                if !lit.is_empty() {
                    tokens.push(WildToken::Literal(std::mem::take(&mut lit)));
                }
                if chars.peek() == Some(&'*') {
                    chars.next();
                    tokens.push(WildToken::DoubleStar);
                } else {
                    tokens.push(WildToken::Star);
                }
            } else {
                lit.push(c);
            }
        }
        if !lit.is_empty() {
            tokens.push(WildToken::Literal(lit));
        }
        WildcardPattern { tokens }
    }

    fn matches(&self, path: &str) -> bool {
        wildcard_match(&self.tokens, path)
    }
}

/// Recursive backtracking matcher for [`WildcardPattern`] tokens.
fn wildcard_match(tokens: &[WildToken], path: &str) -> bool {
    if tokens.is_empty() {
        return path.is_empty();
    }
    match &tokens[0] {
        WildToken::Literal(lit) => {
            if path.starts_with(lit.as_str()) {
                wildcard_match(&tokens[1..], &path[lit.len()..])
            } else {
                false
            }
        }
        WildToken::Star => {
            // Grow a non-`/` prefix until the remaining tokens match the tail.
            for n in 0..=path.len() {
                let (head, tail) = path.split_at(n);
                if head.contains('/') {
                    break;
                }
                if wildcard_match(&tokens[1..], tail) {
                    return true;
                }
            }
            false
        }
        WildToken::DoubleStar => {
            // Same, but the prefix may include `/` (split only on char boundaries).
            for n in 0..=path.len() {
                if !path.is_char_boundary(n) {
                    continue;
                }
                if wildcard_match(&tokens[1..], &path[n..]) {
                    return true;
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::DEFAULT_RULES;
    use crate::inspection::InspectionPath;
    use crate::matcher::{CaseSensitivity, PathMatcher};
    use crate::rule::{Rule, RuleGroup};

    fn eval(rules: Vec<Rule>, path: &str) -> ShieldDecision {
        let rs = rules
            .into_iter()
            .fold(RuleSet::new(), |rs, r| rs.push(r))
            .compile()
            .unwrap();
        rs.evaluate(&InspectionPath::new(path))
    }

    fn deny_exact(path: &str) -> Rule {
        Rule::deny(
            "t.exact",
            RuleGroup::Secrets,
            "test",
            PathMatcher::Exact(path.into()),
        )
    }
    fn deny_prefix(path: &str) -> Rule {
        Rule::deny(
            "t.prefix",
            RuleGroup::Secrets,
            "test",
            PathMatcher::Prefix(path.into()),
        )
    }
    fn deny_suffix(s: &str) -> Rule {
        Rule::deny(
            "t.suffix",
            RuleGroup::Secrets,
            "test",
            PathMatcher::Suffix(s.into()),
        )
    }
    fn deny_segment(s: &str) -> Rule {
        Rule::deny(
            "t.segment",
            RuleGroup::Secrets,
            "test",
            PathMatcher::Segment(s.into()),
        )
    }
    fn deny_contains(s: &str) -> Rule {
        Rule::deny(
            "t.contains",
            RuleGroup::Secrets,
            "test",
            PathMatcher::Contains(s.into()),
        )
    }
    fn deny_wildcard(s: &str) -> Rule {
        Rule::deny(
            "t.wildcard",
            RuleGroup::Secrets,
            "test",
            PathMatcher::Wildcard(s.into()),
        )
    }

    #[test]
    fn exact_match() {
        assert_eq!(eval(vec![deny_exact("/.env")], "/.env"), block());
        assert_ne!(eval(vec![deny_exact("/.env")], "/.env.local"), block());
    }

    #[test]
    fn prefix_match() {
        assert!(matches!(
            eval(vec![deny_prefix("/wp-admin/")], "/wp-admin/options.php"),
            ShieldDecision::Block(_)
        ));
        assert_eq!(
            eval(vec![deny_prefix("/wp-admin/")], "/wp-admin"),
            ShieldDecision::Allow
        );
    }

    #[test]
    fn suffix_match() {
        assert!(matches!(
            eval(vec![deny_suffix(".php")], "/shell.php"),
            ShieldDecision::Block(_)
        ));
        assert_eq!(
            eval(vec![deny_suffix(".php")], "/shell.php.bak"),
            ShieldDecision::Allow
        );
    }

    #[test]
    fn segment_match_test() {
        assert!(matches!(
            eval(vec![deny_segment(".git")], "/.git/config"),
            ShieldDecision::Block(_)
        ));
        assert_eq!(
            eval(vec![deny_segment(".git")], "/.gitconfig"),
            ShieldDecision::Allow
        );
    }

    #[test]
    fn contains_match() {
        assert!(matches!(
            eval(vec![deny_contains(".env")], "/dir/.env.backup"),
            ShieldDecision::Block(_)
        ));
    }

    #[test]
    fn wildcard_match_test() {
        assert!(matches!(
            eval(vec![deny_wildcard("/wp-content/*")], "/wp-content/themes"),
            ShieldDecision::Block(_)
        ));
        // ** crosses slashes
        assert!(matches!(
            eval(
                vec![deny_wildcard("/wp-content/**")],
                "/wp-content/plugins/foo"
            ),
            ShieldDecision::Block(_)
        ));
    }

    #[test]
    fn allow_overrides_deny() {
        let rules = vec![
            Rule::allow(
                "a.metrics",
                RuleGroup::Custom("app".into()),
                "allow",
                PathMatcher::Exact("/metrics".into()),
            ),
            Rule::deny(
                "d.metrics",
                RuleGroup::Debug,
                "deny",
                PathMatcher::Exact("/metrics".into()),
            ),
        ];
        assert_eq!(eval(rules, "/metrics"), ShieldDecision::Allow);
    }

    #[test]
    fn query_string_not_matched() {
        // The engine receives only the path component; query strings should
        // not affect matching. (Tested via InspectionPath which is given
        // only the path.)
        let p = InspectionPath::new("/safe");
        let rs = RuleSet::new().push(deny_exact("/.env")).compile().unwrap();
        assert_eq!(rs.evaluate(&p), ShieldDecision::Allow);
    }

    #[test]
    fn case_insensitive_default() {
        // All compiled matchers lowercase both value and path.
        assert!(matches!(
            eval(vec![deny_exact("/.env")], "/.ENV"),
            ShieldDecision::Block(_)
        ));
    }

    #[test]
    fn case_sensitive_rule_preserves_case() {
        let rule = deny_exact("/Admin").with_case_sensitivity(CaseSensitivity::Sensitive);

        assert!(matches!(
            eval(vec![rule.clone()], "/Admin"),
            ShieldDecision::Block(_)
        ));
        assert_eq!(eval(vec![rule], "/admin"), ShieldDecision::Allow);
    }

    #[cfg(feature = "regex")]
    #[test]
    fn regex_uses_ascii_case_insensitivity() {
        let rule = Rule::deny(
            "t.regex",
            RuleGroup::Secrets,
            "test",
            PathMatcher::Regex(r"^/admin/[a-z]+$".into()),
        );
        assert!(matches!(
            eval(vec![rule], "/ADMIN/Users"),
            ShieldDecision::Block(_)
        ));
    }

    #[cfg(all(feature = "rayon", feature = "regex"))]
    #[test]
    fn parallel_regex_compile_preserves_rule_order() {
        let rules = (0..PARALLEL_REGEX_COMPILE_THRESHOLD).fold(RuleSet::new(), |rules, index| {
            rules.push(Rule::deny(
                crate::RuleId::new(format!("t.regex_{index}")),
                RuleGroup::Secrets,
                "test",
                PathMatcher::Regex(if index < 2 {
                    r"^/match$".into()
                } else {
                    format!(r"^/no-match/{index}$")
                }),
            ))
        });
        let decision = rules
            .compile()
            .unwrap()
            .evaluate(&InspectionPath::new("/match"));
        let ShieldDecision::Block(matched) = decision else {
            panic!("expected block")
        };
        assert_eq!(matched.rule_id, crate::RuleId::new("t.regex_0"));
    }

    #[test]
    fn encoded_bypass_dotenv() {
        // %2e decodes to '.', so /%2eenv -> /.env
        assert!(matches!(
            eval(vec![deny_exact("/.env")], "/%2eenv"),
            ShieldDecision::Block(_)
        ));
    }

    #[test]
    fn root_path_allowed() {
        assert_eq!(eval(vec![], "/"), ShieldDecision::Allow);
    }

    #[test]
    fn default_rules_compile() {
        let rs = DEFAULT_RULES.get().compile().unwrap();
        // Spot check a few known blocked paths.
        let blocked = [
            "/.env",
            "/.git/config",
            "/.aws/credentials",
            "/wp-login.php",
            "/actuator/env",
            "/.ssh/id_rsa",
        ];
        for p in &blocked {
            let ip = InspectionPath::new(p);
            assert!(
                matches!(rs.evaluate(&ip), ShieldDecision::Block(_)),
                "Expected {} to be blocked",
                p
            );
        }
    }

    #[test]
    fn default_rules_do_not_block_app_paths() {
        let rs = DEFAULT_RULES.get().compile().unwrap();
        let safe = ["/", "/admin", "/api", "/graphql", "/health", "/dashboard"];
        for p in &safe {
            let ip = InspectionPath::new(p);
            assert_eq!(
                rs.evaluate(&ip),
                ShieldDecision::Allow,
                "Expected {} to be allowed",
                p
            );
        }
    }

    fn block() -> ShieldDecision {
        ShieldDecision::Block(ShieldMatch {
            rule_id: "t.exact".into(),
            group: RuleGroup::Secrets,
            match_kind: MatchKind::Exact,
            is_builtin: false,
        })
    }
}
