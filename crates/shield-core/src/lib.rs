//! Portable path-denylist rule model shared by the Tower middleware and
//! offline exporters.
//!
//! This crate owns the declarative rule vocabulary and the compile/evaluate
//! lifecycle. It has no HTTP runtime dependency: adapters supply a path
//! string (or [`InspectionPath`]) and receive a [`ShieldDecision`].
//!
//! Core types:
//!
//! - [`Rule`] / [`RuleSet`] – versioned, ordered deny/allow rules
//! - [`CompiledRuleSet`] – startup-compiled form used on the hot path
//! - [`PathMatcher`] / [`CaseSensitivity`] – how a path is compared
//! - [`InspectionPath`] – single-pass percent-decoded inspection form
//! - [`DEFAULT_RULES`] – conservative built-in scanner-probe denylist
//! - [`ruleset::CompileError`] – fail-fast errors from rule compilation
//!
//! # Lifecycle
//!
//! Build a [`RuleSet`] (or clone [`DEFAULT_RULES`]), call [`RuleSet::compile`]
//! once at startup, then call [`CompiledRuleSet::evaluate`] per request.
//! Allow rules win over deny rules; no match means allow (fail-open for
//! unmatched application traffic).
//!
//! # Encoding policy
//!
//! Path matching uses a *derived* representation – never the mutated
//! request. See [`InspectionPath`] for single-pass decode rules, what is
//! excluded (query string, `..` collapse), and intentional `%2F` behaviour.
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
