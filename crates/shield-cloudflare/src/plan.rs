//! Plan-tier limits that constrain expression packing and regex export.
//!
//! Limits are operator-facing budgets for offline generation, not live
//! account queries. Override fields when Cloudflare publishes new caps.

/// Named Cloudflare plan tier used to select default capability budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudflarePlan {
    /// Free plan (smallest expression and rule budgets; no regex).
    Free,
    /// Pro plan.
    Pro,
    /// Business plan (regex `matches` available).
    Business,
    /// Enterprise plan (largest documented budgets).
    Enterprise,
}

/// Regex support and packing budgets for a Cloudflare target environment.
///
/// Defaults for [`CloudflarePlan::Free`] follow public custom-rules docs
/// (April 2026). See <https://developers.cloudflare.com/waf/custom-rules/>.
#[derive(Debug, Clone)]
pub struct CloudflareCapabilities {
    /// Whether the `matches` regex operator may be emitted.
    pub regex: bool,
    /// Maximum number of custom rules the exporter may produce.
    pub maximum_rules: usize,
    /// Maximum characters per packed expression.
    pub maximum_expression_length: usize,
}

impl CloudflareCapabilities {
    /// Documented default budgets for `plan` (override fields if limits change).
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
