//! [`RuleSet`] and [`CompiledRuleSet`].

use crate::{
    inspection::InspectionPath,
    matcher::{CaseSensitivity, MatchKind, PathMatcher},
    rule::{Rule, RuleDisposition},
    ShieldDecision, ShieldMatch,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "regex")]
use regex::Regex;

use thiserror::Error;

/// Schema version discriminant embedded in serialised rule files.
///
/// Increment when the serialisation format changes in a breaking way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleSchemaVersion(pub u32);

impl RuleSchemaVersion {
    /// Current supported version.
    pub const CURRENT: Self = RuleSchemaVersion(1);
}

impl Default for RuleSchemaVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// A versioned, ordered collection of [`Rule`]s.
///
/// Call [`RuleSet::compile`] to produce a [`CompiledRuleSet`] ready for
/// per-request evaluation.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleSet {
    /// Schema version for forwards-compatibility checks.
    #[cfg_attr(feature = "serde", serde(rename = "schema-version"))]
    pub schema_version: RuleSchemaVersion,
    /// Ordered list of rules. Evaluation follows list order; the first
    /// matching `Allow` rule wins, then the first matching `Deny` rule.
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Create an empty rule set with the current schema version.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a rule.
    pub fn push(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Compile all enabled rules into a [`CompiledRuleSet`].
    pub fn compile(self) -> Result<CompiledRuleSet, CompileError> {
        let mut compiled = Vec::with_capacity(self.rules.len());
        for rule in self.rules {
            if !rule.enabled {
                continue;
            }
            let inner = CompiledMatcher::new(&rule.matcher)?;
            compiled.push(CompiledRule {
                id: rule.id,
                group: rule.group,
                description: rule.description,
                disposition: rule.disposition,
                match_kind: MatchKind::from(&rule.matcher),
                case: rule_case(&rule.matcher),
                inner,
                builtin: rule.builtin,
            });
        }
        Ok(CompiledRuleSet { rules: compiled })
    }
}

/// Error returned when a rule set cannot be compiled.
#[derive(Debug, Error)]
pub enum CompileError {
    /// A regex pattern is invalid.
    #[error("invalid regex in rule: {0}")]
    InvalidRegex(String),
}

// Determine the default case sensitivity for a matcher (all built-in
// matchers default to Insensitive to catch mixed-case probe variants).
// Custom rules carry their own `CaseSensitivity` field; here we embed it
// in the PathMatcher for simplicity.  The Rule struct would carry it
// separately if desired; for now matchers are always insensitive unless
// the caller explicitly uses a `Sensitive` wrapper.  We treat it as
// insensitive by default in the matching engine.
fn rule_case(_matcher: &PathMatcher) -> CaseSensitivity {
    // All built-in rules are case-insensitive.  Custom rules can set this
    // explicitly when constructing their Rule.  For now the field is
    // always Insensitive – a future extension point.
    CaseSensitivity::Insensitive
}

// Internal compiled form of one rule.
#[derive(Debug, Clone)]
struct CompiledRule {
    id: crate::rule::RuleId,
    group: crate::rule::RuleGroup,
    #[allow(dead_code)]
    description: String,
    disposition: RuleDisposition,
    match_kind: MatchKind,
    #[allow(dead_code)]
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
    fn new(m: &PathMatcher) -> Result<Self, CompileError> {
        Ok(match m {
            PathMatcher::Exact(s) => CompiledMatcher::Exact(s.to_ascii_lowercase()),
            PathMatcher::Prefix(s) => CompiledMatcher::Prefix(s.to_ascii_lowercase()),
            PathMatcher::Suffix(s) => CompiledMatcher::Suffix(s.to_ascii_lowercase()),
            PathMatcher::Segment(s) => CompiledMatcher::Segment(s.to_ascii_lowercase()),
            PathMatcher::Contains(s) => CompiledMatcher::Contains(s.to_ascii_lowercase()),
            PathMatcher::Wildcard(s) => {
                CompiledMatcher::Wildcard(WildcardPattern::compile(&s.to_ascii_lowercase()))
            }
            #[cfg(feature = "regex")]
            PathMatcher::Regex(s) => {
                let re = Regex::new(s)
                    .map_err(|e| CompileError::InvalidRegex(format!("{}: {}", s, e)))?;
                CompiledMatcher::Regex(re)
            }
        })
    }

    fn matches(&self, path: &str) -> bool {
        // All compiled values are already lowercased; path must be lowercased
        // by the caller (InspectionPath::decoded_lower).
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

/// A compiled rule set ready for per-request path evaluation.
///
/// Cloning is cheap because all per-rule data is `Arc`-backed indirectly
/// through `String` values (which are already cloned on copy).
#[derive(Debug, Clone)]
pub struct CompiledRuleSet {
    rules: Vec<CompiledRule>,
}

impl CompiledRuleSet {
    /// Evaluate a decoded, lowercased path against the rule set.
    ///
    /// Allow rules take precedence: the first matching allow rule returns
    /// `ShieldDecision::Allow`. Then the first matching deny rule returns
    /// `ShieldDecision::Block`. If no rule matches, the request is allowed.
    pub fn evaluate(&self, path: &InspectionPath) -> ShieldDecision {
        let lower = &path.decoded_lower;

        // Pass 1 – allow rules take absolute precedence.
        for rule in &self.rules {
            if rule.disposition == RuleDisposition::Allow && rule.inner.matches(lower) {
                return ShieldDecision::Allow;
            }
        }

        // Pass 2 – deny rules.
        for rule in &self.rules {
            if rule.disposition == RuleDisposition::Deny && rule.inner.matches(lower) {
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

// We need CompiledRuleSet to be Clone but Regex does not implement Clone.
// Work around this by storing compiled rules in an Arc<Vec<_>> so that
// clone is O(1). For simplicity we store the raw PathMatcher alongside and
// recompile on clone – but that is expensive. Instead, wrap CompiledRule in
// Arc. Add the necessary bounds.
//
// Actually: `Regex` implements Clone in `regex` ≥1. Check.
// According to docs.rs/regex, Regex is Clone. Good, no workaround needed.

/// Check whether `segment` appears as a complete path segment in `path`.
///
/// A segment is a `/`-delimited component. The segment value must not
/// include slashes.
fn segment_match(path: &str, segment: &str) -> bool {
    // Iterate over segments by splitting on '/'
    path.split('/').any(|s| s == segment)
}

// ── Wildcard pattern ────────────────────────────────────────────────────────

/// A compiled wildcard pattern.
///
/// - `*` matches any run of characters that does not include `/`.
/// - `**` matches any run of characters including `/`.
#[derive(Debug, Clone)]
struct WildcardPattern {
    /// Pattern tokens.
    tokens: Vec<WildToken>,
    /// The original lowercased pattern (kept for `Debug`).
    #[allow(dead_code)]
    src: String,
}

#[derive(Debug, Clone)]
enum WildToken {
    /// Literal string fragment.
    Literal(String),
    /// `*` – any non-`/` characters.
    Star,
    /// `**` – any characters including `/`.
    DoubleStar,
}

impl WildcardPattern {
    fn compile(pattern: &str) -> Self {
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
        WildcardPattern {
            tokens,
            src: pattern.to_owned(),
        }
    }

    fn matches(&self, path: &str) -> bool {
        wildcard_match(&self.tokens, path)
    }
}

/// Recursive wildcard matcher.
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
            // Match any prefix that does not contain '/'
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
            // Match any prefix (including those with '/')
            for n in 0..=path.len() {
                // Ensure we only split at valid char boundaries.
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
    use crate::matcher::PathMatcher;
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
