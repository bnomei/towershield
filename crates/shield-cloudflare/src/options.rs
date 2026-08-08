//! Host scope, action, and plan knobs for a Cloudflare export run.
//!
//! Defaults intentionally leave hostnames empty so accidental zone-wide
//! exports fail with [`crate::exporter::ExportError::MissingHostScope`] unless
//! the caller sets hostnames or opts into [`HostScope::AllHosts`]. Plan
//! budgets come from [`crate::CloudflarePlan`] via
//! [`crate::CloudflareCapabilities`]; override fields when account
//! entitlements differ from published tier defaults.

use crate::plan::{CloudflareCapabilities, CloudflarePlan};

/// Cloudflare action applied when a generated expression matches.
///
/// Written into every packed rule's Rulesets API `action` field. Choose
/// [`Log`](Self::Log) for dry-run monitoring when the target account supports
/// it, before enabling [`Block`](Self::Block) in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloudflareAction {
    /// Hard block with Cloudflare's error page (default for production).
    #[default]
    Block,
    /// Log-only match (dry-run / monitoring; requires a supporting entitlement).
    Log,
    /// Issue a JavaScript challenge before allowing the request.
    JsChallenge,
    /// Issue Cloudflare's managed challenge.
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
///
/// Build with [`CloudflareExportOptions::builder`], or start from
/// [`Default`] and set public fields. Export **requires** hostnames or an
/// explicit [`HostScope::AllHosts`]; the default empty hostname list is a
/// deliberate fail-closed guard against zone-wide accidents.
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
///
/// Defaults match [`CloudflareExportOptions::default`]: Free-plan budgets,
/// block action, and empty hostnames. Call [`Self::hostnames`] or
/// [`Self::all_hosts`] before export or the exporter returns
/// [`crate::exporter::ExportError::MissingHostScope`].
///
/// Ruleset name/description and the rule-name prefix are public fields on
/// the finished options value if they need tuning after [`Self::build`].
#[derive(Default)]
pub struct CloudflareExportOptionsBuilder {
    inner: CloudflareExportOptions,
}

impl CloudflareExportOptionsBuilder {
    /// Scope export to these `http.host` values (replaces prior host scope).
    pub fn hostnames(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner.host_scope = HostScope::Hostnames(hosts.into_iter().map(|h| h.into()).collect());
        self
    }

    /// Explicitly export without an `http.host` constraint (zone-wide).
    ///
    /// Prefer named hostnames for multi-host zones; this is an intentional
    /// opt-in that skips the missing-scope guard.
    pub fn all_hosts(mut self) -> Self {
        self.inner.host_scope = HostScope::AllHosts;
        self
    }

    /// Set raw capability limits (overrides a prior [`Self::plan`] call).
    pub fn capabilities(mut self, cap: CloudflareCapabilities) -> Self {
        self.inner.capabilities = cap;
        self
    }

    /// Use documented custom-rules budgets for a named Cloudflare plan tier.
    pub fn plan(mut self, plan: CloudflarePlan) -> Self {
        self.inner.capabilities = CloudflareCapabilities::for_plan(plan);
        self
    }

    /// Set the match action written into every packed Cloudflare rule.
    pub fn action(mut self, action: CloudflareAction) -> Self {
        self.inner.action = action;
        self
    }

    /// Finish the builder and return owned options (does not validate host scope).
    pub fn build(self) -> CloudflareExportOptions {
        self.inner
    }
}
