//! # shield-core
//!
//! Portable, framework-neutral path-shield rule model.
//!
//! This crate defines:
//!
//! - [`Rule`] – a single path-matching rule with an ID, group, matcher, and disposition.
//! - [`RuleSet`] – a versioned, ordered collection of rules.
//! - [`PathMatcher`] – semantic match kinds (Exact, Prefix, Suffix, Segment, Contains,
//!   Wildcard, and optional Regex).
//! - [`CaseSensitivity`] – case handling per rule.
//! - [`RuleDisposition`] – allow or deny.
//! - [`RuleGroup`] – built-in and custom categories.
//! - [`ShieldDecision`] – outcome of evaluating a request path against a rule set.
//! - [`ShieldMatch`] – details of which rule matched.
//! - [`DEFAULT_RULES`] – conservative built-in rules.
//!
//! # Design
//!
//! Rules are declarative data that is validated once at construction time.
//! The matcher is compiled into an internal, pre-validated form so that
//! per-request evaluation is allocation-free on the hot path.
//!
//! Path inspection is done on a *derived representation* – the raw URI path
//! is never mutated, but percent-decoded and normalised forms are computed
//! once per request in the Tower service. See [`InspectionPath`] for the
//! documented policy.
//!
//! # Encoding policy
//!
//! See [`InspectionPath`].
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

/// The outcome of evaluating a path against a [`CompiledRuleSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldDecision {
    /// The request should be allowed to proceed to the inner service.
    Allow,
    /// The request matched a deny rule and should be rejected.
    Block(ShieldMatch),
}

/// Details of the rule that caused a [`ShieldDecision::Block`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldMatch {
    /// Stable rule identifier.
    pub rule_id: RuleId,
    /// Rule group / category.
    pub group: RuleGroup,
    /// The match kind that triggered.
    pub match_kind: MatchKind,
    /// `true` when the matched rule is a built-in rule.
    pub is_builtin: bool,
}
