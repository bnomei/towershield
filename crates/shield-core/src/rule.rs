//! Rule identity, grouping, disposition, and the declarative [`Rule`] value.
//!
//! Rules are pure data: collect them into a [`crate::RuleSet`], compile once,
//! then evaluate. Built-in rules ship via [`crate::DEFAULT_RULES`]; apps add
//! deny or allow rules with the same API.

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::matcher::{CaseSensitivity, PathMatcher};

/// Stable, opaque rule identifier suitable for metrics and export reports.
///
/// Convention is `group.name` (e.g. `"secrets.dotenv"`). Prefer keeping IDs
/// stable across crate versions so dashboards and Cloudflare diagnostics
/// remain comparable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleId(pub String);

impl RuleId {
    /// Create a rule identifier (convention: `group.name`, e.g. `"secrets.dotenv"`).
    pub fn new(id: impl Into<String>) -> Self {
        RuleId(id.into())
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        RuleId(s.to_owned())
    }
}

/// Logical category for filtering, metrics labels, and export organisation.
///
/// Built-in variants mirror the groups in [`crate::DEFAULT_RULES`]. Use
/// [`RuleGroup::Custom`] for application-specific rules. Disable whole CMS
/// groups (WordPress, Joomla, …) when the app legitimately serves those paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RuleGroup {
    /// Secrets and environment files (`.env`, `.env.local`, …).
    Secrets,
    /// Source-control metadata (`.git/`, `.svn/`, …).
    SourceControl,
    /// Cloud credentials (`.aws/credentials`, GCP keys, …).
    CloudCredentials,
    /// SSH private keys, certs, and common key path probes.
    SshKeys,
    /// Build and deployment manifests (`Dockerfile`, `terraform.tfstate`, …).
    BuildManifests,
    /// Framework config that often leaks credentials or internals.
    FrameworkConfig,
    /// JavaScript ecosystem manifests, build config, and dev-only endpoints.
    #[cfg_attr(feature = "serde", serde(rename = "javascript"))]
    JavaScript,
    /// WordPress admin, content, and login probe paths.
    WordPress,
    /// Joomla administrator and install probe paths.
    Joomla,
    /// Drupal sites/default and install/update probes.
    Drupal,
    /// Magento downloader, shell, and export probes.
    Magento,
    /// High-confidence PHP web-shell filename probes.
    PhpShell,
    /// Debug endpoints, profilers, actuators, server-status.
    Debug,
    /// AI / developer-tool credential and config probes.
    AiTools,
    /// Application-defined group label (string is the Display form).
    #[cfg_attr(feature = "serde", serde(untagged))]
    Custom(String),
}

impl fmt::Display for RuleGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleGroup::Secrets => f.write_str("secrets"),
            RuleGroup::SourceControl => f.write_str("source_control"),
            RuleGroup::CloudCredentials => f.write_str("cloud_credentials"),
            RuleGroup::SshKeys => f.write_str("ssh_keys"),
            RuleGroup::BuildManifests => f.write_str("build_manifests"),
            RuleGroup::FrameworkConfig => f.write_str("framework_config"),
            RuleGroup::JavaScript => f.write_str("javascript"),
            RuleGroup::WordPress => f.write_str("wordpress"),
            RuleGroup::Joomla => f.write_str("joomla"),
            RuleGroup::Drupal => f.write_str("drupal"),
            RuleGroup::Magento => f.write_str("magento"),
            RuleGroup::PhpShell => f.write_str("php_shell"),
            RuleGroup::Debug => f.write_str("debug"),
            RuleGroup::AiTools => f.write_str("ai_tools"),
            RuleGroup::Custom(s) => f.write_str(s),
        }
    }
}

/// Whether a matching path is blocked or explicitly permitted.
///
/// Evaluation is two-pass: any matching [`Allow`](Self::Allow) short-circuits
/// to allow before deny rules are considered. Use allow rules as narrow
/// exclusions for legitimate paths that overlap a denylist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RuleDisposition {
    /// Reject the request when the matcher hits (default).
    #[default]
    Deny,
    /// Permit the request even if a deny rule would also match.
    Allow,
}

/// One declarative path rule: identity, disposition, matcher, and flags.
///
/// Collect into a [`crate::RuleSet`] and compile once at startup. Constructors
/// [`Rule::deny`] / [`Rule::allow`] produce enabled, non-built-in rules with
/// case-**insensitive** matching; call [`Rule::with_case_sensitivity`] when
/// the router distinguishes path case.
///
/// # Versioning
///
/// Built-in rule additions are minor-version behavioural changes (more paths
/// may block). Removals or weakenings require a major version bump.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Rule {
    /// Stable identifier, e.g. `"secrets.dotenv"`.
    pub id: RuleId,
    /// Logical group / category for metrics and export packing.
    pub group: RuleGroup,
    /// Human-readable description (not shown to HTTP clients).
    pub description: String,
    /// Allow (exclusion) or deny (block).
    pub disposition: RuleDisposition,
    /// Comparison operator and pattern.
    pub matcher: PathMatcher,
    /// Case policy for this rule only.
    ///
    /// Defaults to insensitive so mixed-case probe variants still hit.
    #[cfg_attr(feature = "serde", serde(default = "default_case_sensitivity"))]
    pub case_sensitivity: CaseSensitivity,
    /// `true` when the rule shipped in the crate built-in set.
    #[cfg_attr(feature = "serde", serde(default))]
    pub builtin: bool,
    /// When `false`, the rule is kept for serialization but skipped at compile.
    #[cfg_attr(feature = "serde", serde(default = "default_true"))]
    pub enabled: bool,
}

#[cfg(feature = "serde")]
fn default_true() -> bool {
    true
}

#[cfg(feature = "serde")]
fn default_case_sensitivity() -> CaseSensitivity {
    CaseSensitivity::Insensitive
}

impl Rule {
    /// Build an enabled deny rule (ASCII case-insensitive, not marked built-in).
    ///
    /// Use [`Self::with_case_sensitivity`] when the application router treats
    /// path case as significant. Mark crate-shipped rules with [`Self::builtin`].
    pub fn deny(
        id: impl Into<RuleId>,
        group: RuleGroup,
        description: impl Into<String>,
        matcher: PathMatcher,
    ) -> Self {
        Rule {
            id: id.into(),
            group,
            description: description.into(),
            disposition: RuleDisposition::Deny,
            matcher,
            case_sensitivity: CaseSensitivity::Insensitive,
            builtin: false,
            enabled: true,
        }
    }

    /// Build an enabled allow rule used as a denylist exclusion.
    ///
    /// At evaluate time, any matching allow short-circuits before deny rules.
    /// Allow rules are Tower-side only: the Cloudflare exporter ignores them.
    pub fn allow(
        id: impl Into<RuleId>,
        group: RuleGroup,
        description: impl Into<String>,
        matcher: PathMatcher,
    ) -> Self {
        Rule {
            id: id.into(),
            group,
            description: description.into(),
            disposition: RuleDisposition::Allow,
            matcher,
            case_sensitivity: CaseSensitivity::Insensitive,
            builtin: false,
            enabled: true,
        }
    }

    /// Mark the rule as shipped with the crate (sets [`Rule::builtin`]).
    #[must_use]
    pub fn builtin(mut self) -> Self {
        self.builtin = true;
        self
    }

    /// Override the default case-insensitive policy for this rule only.
    #[must_use]
    pub fn with_case_sensitivity(mut self, case_sensitivity: CaseSensitivity) -> Self {
        self.case_sensitivity = case_sensitivity;
        self
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn javascript_group_serializes_stably() {
        assert_eq!(
            serde_json::to_string(&RuleGroup::JavaScript).unwrap(),
            r#""javascript""#
        );
    }

    #[test]
    fn serialized_rules_without_case_policy_remain_insensitive() {
        let json = r#"{
            "id": "test.legacy",
            "group": "secrets",
            "description": "legacy rule",
            "disposition": "deny",
            "matcher": { "match": "exact", "value": "/Admin" },
            "builtin": false,
            "enabled": true
        }"#;

        let rule: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.case_sensitivity, CaseSensitivity::Insensitive);
    }
}
