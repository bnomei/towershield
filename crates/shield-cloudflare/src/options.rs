//! Host scope, action, and plan knobs for a Cloudflare export run.
//!
//! Defaults intentionally leave hostnames empty so accidental zone-wide
//! exports fail with [`crate::exporter::ExportError::MissingHostScope`] unless
//! the caller sets hostnames or opts into [`HostScope::AllHosts`].

use crate::plan::{CloudflareCapabilities, CloudflarePlan};

/// Cloudflare action applied when a generated expression matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloudflareAction {
    /// Hard block with Cloudflare's error page (default).
    #[default]
    Block,
    /// Log-only (dry-run / monitoring).
    Log,
    /// JavaScript challenge.
    JsChallenge,
    /// Managed challenge.
    ManagedChallenge,
}

impl CloudflareAction {
    /// Wire value for the Rulesets API `action` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudflareAction::Block => "block",
            CloudflareAction::Log => "log",
            CloudflareAction::JsChallenge => "js_challenge",
            CloudflareAction::ManagedChallenge => "managed_challenge",
        }
    }
}

/// Whether generated expressions are limited to named hosts.
///
/// Empty [`HostScope::Hostnames`] is treated as “not configured” by the
/// exporter. [`HostScope::AllHosts`] is an explicit opt-in to unscoped rules.
#[derive(Debug, Clone)]
pub enum HostScope {
    /// Restrict matches to these `http.host` values.
    Hostnames(Vec<String>),
    /// Intentionally apply rules to all hosts on the zone.
    AllHosts,
}

/// Full configuration for [`crate::CloudflareExporter::export`].
#[derive(Debug, Clone)]
pub struct CloudflareExportOptions {
    /// Hostname scoping (must be set before export).
    pub host_scope: HostScope,
    /// Regex support, max rules, and expression length for the target plan.
    pub capabilities: CloudflareCapabilities,
    /// Action on match for every generated Cloudflare rule.
    pub action: CloudflareAction,
    /// Prefix for generated rule `description` strings.
    pub rule_name_prefix: String,
    /// Ruleset `name` in the API payload.
    pub ruleset_name: String,
    /// Ruleset `description` in the API payload.
    pub ruleset_description: String,
}

impl Default for CloudflareExportOptions {
    fn default() -> Self {
        CloudflareExportOptions {
            host_scope: HostScope::Hostnames(vec![]),
            capabilities: CloudflareCapabilities::for_plan(CloudflarePlan::Free),
            action: CloudflareAction::default(),
            rule_name_prefix: "shield".into(),
            ruleset_name: "HTTP scanner shield".into(),
            ruleset_description: "Generated from portable shield rules".into(),
        }
    }
}

impl CloudflareExportOptions {
    /// Start a builder with the same defaults as [`CloudflareExportOptions::default`].
    pub fn builder() -> CloudflareExportOptionsBuilder {
        CloudflareExportOptionsBuilder::default()
    }
}

/// Fluent builder for [`CloudflareExportOptions`].
#[derive(Default)]
pub struct CloudflareExportOptionsBuilder {
    inner: CloudflareExportOptions,
}

impl CloudflareExportOptionsBuilder {
    /// Scope export to the given hostnames (replaces prior host scope).
    pub fn hostnames(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner.host_scope = HostScope::Hostnames(hosts.into_iter().map(|h| h.into()).collect());
        self
    }

    /// Explicitly export without an `http.host` constraint.
    pub fn all_hosts(mut self) -> Self {
        self.inner.host_scope = HostScope::AllHosts;
        self
    }

    /// Set raw capability limits (overrides a prior [`Self::plan`] call).
    pub fn capabilities(mut self, cap: CloudflareCapabilities) -> Self {
        self.inner.capabilities = cap;
        self
    }

    /// Use documented defaults for a named Cloudflare plan tier.
    pub fn plan(mut self, plan: CloudflarePlan) -> Self {
        self.inner.capabilities = CloudflareCapabilities::for_plan(plan);
        self
    }

    /// Set the match action for generated rules.
    pub fn action(mut self, action: CloudflareAction) -> Self {
        self.inner.action = action;
        self
    }

    /// Finish the builder and return owned options.
    pub fn build(self) -> CloudflareExportOptions {
        self.inner
    }
}
