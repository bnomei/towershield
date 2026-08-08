//! Cloudflare plan capabilities.

/// Target Cloudflare plan level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudflarePlan {
    /// Free plan.
    Free,
    /// Pro plan.
    Pro,
    /// Business plan.
    Business,
    /// Enterprise plan.
    Enterprise,
}

/// Capability profile for a Cloudflare target.
///
/// Defaults match conservative estimates for the **Free** plan as
/// documented at <https://developers.cloudflare.com/waf/custom-rules/>
/// (April 2026). Call [`CloudflareCapabilities::for_plan`] for other plans,
/// or override any field if Cloudflare's published limits change.
#[derive(Debug, Clone)]
pub struct CloudflareCapabilities {
    /// Whether the `matches` regex operator is available.
    pub regex: bool,
    /// Maximum number of custom rules in the phase.
    pub maximum_rules: usize,
    /// Maximum expression length in characters.
    pub maximum_expression_length: usize,
}

impl CloudflareCapabilities {
    /// Return capability defaults for the given plan.
    ///
    /// Rule counts and expression limits are sourced from Cloudflare
    /// documentation as of April 2026. Override fields as needed when
    /// Cloudflare changes limits.
    pub fn for_plan(plan: CloudflarePlan) -> Self {
        match plan {
            CloudflarePlan::Free => CloudflareCapabilities {
                regex: false,
                maximum_rules: 5,
                maximum_expression_length: 4096,
            },
            CloudflarePlan::Pro => CloudflareCapabilities {
                regex: false,
                maximum_rules: 20,
                maximum_expression_length: 8192,
            },
            CloudflarePlan::Business => CloudflareCapabilities {
                regex: true,
                maximum_rules: 100,
                maximum_expression_length: 16384,
            },
            CloudflarePlan::Enterprise => CloudflareCapabilities {
                regex: true,
                maximum_rules: 1000,
                maximum_expression_length: 32768,
            },
        }
    }
}

impl Default for CloudflareCapabilities {
    fn default() -> Self {
        Self::for_plan(CloudflarePlan::Free)
    }
}
