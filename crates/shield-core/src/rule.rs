//! Rule identifiers, groups, dispositions, and the [`Rule`] struct.

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::matcher::PathMatcher;

/// A stable, opaque rule identifier.
///
/// Identifiers follow a `group.name` convention, e.g. `"secrets.dotenv"`.
/// They are intended to be stable across crate versions and suitable
/// as metric labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleId(pub String);

impl RuleId {
    /// Create a new rule identifier.
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

/// Logical grouping for rules.
///
/// Groups are used for metrics, filtering, and Cloudflare export organisation.
/// `Custom` accepts a string label so applications can define their own groups.
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
    /// SSH keys and certificates.
    SshKeys,
    /// Build and deployment manifests (`Dockerfile`, `terraform.tfstate`, …).
    BuildManifests,
    /// Common framework configuration files.
    FrameworkConfig,
    /// WordPress probe paths.
    WordPress,
    /// Joomla probe paths.
    Joomla,
    /// Drupal probe paths.
    Drupal,
    /// Magento probe paths.
    Magento,
    /// PHP web-shell filename probes.
    PhpShell,
    /// Debug, profiler, metrics, actuator, and server-status probes.
    Debug,
    /// AI and developer-tool credential/configuration probes.
    AiTools,
    /// Application-defined custom group.
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

/// Whether a rule blocks or permits a matching request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RuleDisposition {
    /// Block the request (return the configured error response).
    #[default]
    Deny,
    /// Allow the request (override a preceding deny rule).
    Allow,
}

/// A single path-matching rule.
///
/// Rules are declarative data. They are collected into a [`crate::RuleSet`]
/// and compiled into a [`crate::CompiledRuleSet`] once at startup.
///
/// # Versioning
///
/// Built-in rule additions and removals are considered behavioural changes
/// and follow semantic versioning: additions may occur in minor versions,
/// removals require a major version bump.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Rule {
    /// Stable identifier, e.g. `"secrets.dotenv"`.
    pub id: RuleId,
    /// Logical group / category.
    pub group: RuleGroup,
    /// Human-readable description.
    pub description: String,
    /// Allow or deny.
    pub disposition: RuleDisposition,
    /// How the path is matched.
    pub matcher: PathMatcher,
    /// `true` = this is a built-in rule shipped with the crate.
    #[cfg_attr(feature = "serde", serde(default))]
    pub builtin: bool,
    /// `false` means this rule is loaded but never evaluated.
    #[cfg_attr(feature = "serde", serde(default = "default_true"))]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Rule {
    /// Create a new deny rule with `enabled = true`.
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
            builtin: false,
            enabled: true,
        }
    }

    /// Create a new allow rule with `enabled = true`.
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
            builtin: false,
            enabled: true,
        }
    }

    /// Mark this rule as a built-in rule.
    #[must_use]
    pub fn builtin(mut self) -> Self {
        self.builtin = true;
        self
    }
}
