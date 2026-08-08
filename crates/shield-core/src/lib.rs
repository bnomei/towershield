//! Portable path-denylist rule model shared by the Tower middleware and
//! offline exporters.
//!
//! This crate owns the declarative rule vocabulary and the compile/evaluate
//! lifecycle. It has no HTTP runtime dependency: adapters supply a path
//! string (or [`InspectionPath`]) and receive a [`ShieldDecision`]. Use
//! [`towershield`](https://docs.rs/towershield) for the Tower layer, and
//! `towershield-cloudflare` for offline edge export of the same rules.
//!
//! # Domain map
//!
//! | Concept | Types |
//! |---|---|
//! | Rule identity / grouping | [`RuleId`], [`RuleGroup`], [`RuleDisposition`] |
//! | Declarative rule | [`Rule`], [`PathMatcher`], [`CaseSensitivity`] |
//! | Authoring collection | [`RuleSet`], [`RuleSchemaVersion`] |
//! | Hot-path evaluation | [`CompiledRuleSet`], [`InspectionPath`], [`ShieldDecision`], [`ShieldMatch`] |
//! | Built-in denylist | [`DEFAULT_RULES`], [`defaults::default_rules`] |
//! | Compile failure | [`ruleset::CompileError`] |
//!
//! # Lifecycle
//!
//! Build a [`RuleSet`] (or clone [`DEFAULT_RULES`]), call [`RuleSet::compile`]
//! once at startup (or config reload), then call [`CompiledRuleSet::evaluate`]
//! per request. Allow rules win over deny rules; no match means allow
//! (fail-open for unmatched application traffic). Disabled rules are dropped
//! at compile and never evaluated.
//!
//! # Encoding policy
//!
//! Path matching uses a *derived* inspection form — never a mutated request.
//! See [`InspectionPath`] for single-pass percent-decode rules, what is
//! excluded (query string, `..` collapse), and intentional `%2F` behaviour.
//! Match metadata in [`ShieldMatch`] is for server-side metrics only; do not
//! embed it in client-facing responses.
//!
//! # Features
//!
//! | Feature | Effect |
//! |---|---|
//! | `serde` (default) | Serialize/deserialize [`Rule`], [`RuleSet`], and matchers |
//! | `regex` (default) | Enable regex matchers and the broader built-in rule tier |
//! | `rayon` | Parallel compile of large regex-heavy rule sets (implies `regex`) |
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod defaults;
pub mod inspection;
pub mod matcher;
pub mod rule;
pub mod ruleset;

pub use defaults::DEFAULT_RULES;
pub use inspection::InspectionPath;
pub use matcher::{CaseSensitivity, MatchKind, PathMatcher};
pub use rule::{Rule, RuleDisposition, RuleGroup, RuleId};
pub use ruleset::{CompiledRuleSet, RuleSchemaVersion, RuleSet};

/// Outcome of evaluating an inspection path against a [`CompiledRuleSet`].
///
/// Adapters map `Allow` to “forward unchanged” and `Block` to a generic
/// rejection response that must not reveal which rule matched to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldDecision {
    /// No deny rule matched (or an allow rule matched first); continue.
    Allow,
    /// A deny rule matched; reject without calling protected handlers.
    Block(ShieldMatch),
}

/// Identity of the deny rule that produced a [`ShieldDecision::Block`].
///
/// Safe for metrics and observability callbacks. Do not put this payload
/// into client-facing HTTP bodies or headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldMatch {
    /// Stable rule identifier (e.g. `"secrets.dotenv"`).
    pub rule_id: RuleId,
    /// Logical category used for filtering, metrics, and export grouping.
    pub group: RuleGroup,
    /// Discriminant of the matcher that hit (without the pattern string).
    pub match_kind: MatchKind,
    /// Whether the matched rule shipped with the crate's built-in set.
    pub is_builtin: bool,
}
