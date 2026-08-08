//! Export options: host scoping, action, and plan.

use crate::plan::{CloudflareCapabilities, CloudflarePlan};

/// The Cloudflare action to apply for matched (blocked) traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloudflareAction {
    /// Block the request with a Cloudflare-generated error page.
    #[default]
    Block,
    /// Log without blocking (for monitoring).
    Log,
    /// Challenge with a JS challenge.
    JsChallenge,
    /// Challenge with a managed challenge.
    ManagedChallenge,
}

impl CloudflareAction {
    /// Cloudflare API string for this action.
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudflareAction::Block => "block",
            CloudflareAction::Log => "log",
            CloudflareAction::JsChallenge => "js_challenge",
            CloudflareAction::ManagedChallenge => "managed_challenge",
        }
    }
}

/// How to scope generated Cloudflare expressions to specific hostnames.
#[derive(Debug, Clone)]
pub enum HostScope {
    /// Scope rules to specific hostnames.
    Hostnames(Vec<String>),
    /// Explicitly acknowledge that rules should apply to all traffic.
    AllHosts,
}

/// Options controlling Cloudflare export.
#[derive(Debug, Clone)]
pub struct CloudflareExportOptions {
    /// Host scoping policy.
    pub host_scope: HostScope,
    /// Target plan capabilities.
    pub capabilities: CloudflareCapabilities,
    /// Action to take when a rule matches.
    pub action: CloudflareAction,
    /// Prefix applied to generated Cloudflare rule descriptions.
    pub rule_name_prefix: String,
    /// Ruleset name (appears in the Rulesets API payload).
    pub ruleset_name: String,
    /// Ruleset description.
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
    /// Create a builder for export options.
    pub fn builder() -> CloudflareExportOptionsBuilder {
        CloudflareExportOptionsBuilder::default()
    }
}

/// Builder for [`CloudflareExportOptions`].
#[derive(Default)]
pub struct CloudflareExportOptionsBuilder {
    inner: CloudflareExportOptions,
}

impl CloudflareExportOptionsBuilder {
    /// Set explicit hostnames.
    pub fn hostnames(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner.host_scope = HostScope::Hostnames(hosts.into_iter().map(|h| h.into()).collect());
        self
    }

    /// Acknowledge that rules should apply to all traffic.
    pub fn all_hosts(mut self) -> Self {
        self.inner.host_scope = HostScope::AllHosts;
        self
    }

    /// Set plan capabilities.
    pub fn capabilities(mut self, cap: CloudflareCapabilities) -> Self {
        self.inner.capabilities = cap;
        self
    }

    /// Set plan by enum variant.
    pub fn plan(mut self, plan: CloudflarePlan) -> Self {
        self.inner.capabilities = CloudflareCapabilities::for_plan(plan);
        self
    }

    /// Set the action.
    pub fn action(mut self, action: CloudflareAction) -> Self {
        self.inner.action = action;
        self
    }

    /// Build the options.
    pub fn build(self) -> CloudflareExportOptions {
        self.inner
    }
}
