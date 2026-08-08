//! Plan-tier limits that constrain expression packing and regex export.
//!
//! Limits are operator-facing budgets for offline generation, not live
//! account queries. Override fields when Cloudflare publishes new caps.

/// Named Cloudflare plan tier used to select default capability budgets.
///
/// Maps to documented custom-rules limits via
/// [`CloudflareCapabilities::for_plan`]. Override individual fields when
/// Cloudflare publishes new caps for your account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudflarePlan {
    /// Free plan: 5 rules, 4096-character expressions, no regex `matches`.
    Free,
    /// Pro plan: 20 rules, 4096-character expressions, no regex `matches`.
    Pro,
    /// Business plan: 100 rules, 4096-character expressions, regex enabled.
    Business,
    /// Enterprise plan: 1000 rules, 4096-character expressions, regex enabled.
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
    /// Documented default budgets for `plan`.
    ///
    /// Values track public Cloudflare custom-rules limits (see module-adjacent
    /// docs on [`CloudflareCapabilities`]). Override individual fields when
    /// account entitlements differ from the published tier defaults.
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
                maximum_expression_length: 4096,
            },
            CloudflarePlan::Business => CloudflareCapabilities {
                regex: true,
                maximum_rules: 100,
                maximum_expression_length: 4096,
            },
            CloudflarePlan::Enterprise => CloudflareCapabilities {
                regex: true,
                maximum_rules: 1000,
                maximum_expression_length: 4096,
            },
        }
    }
}

impl Default for CloudflareCapabilities {
    fn default() -> Self {
        Self::for_plan(CloudflarePlan::Free)
    }
}

#[cfg(test)]
mod tests {
    use super::{CloudflareCapabilities, CloudflarePlan};

    #[test]
    fn every_plan_respects_the_rules_engine_expression_limit() {
        for plan in [
            CloudflarePlan::Free,
            CloudflarePlan::Pro,
            CloudflarePlan::Business,
            CloudflarePlan::Enterprise,
        ] {
            assert_eq!(
                CloudflareCapabilities::for_plan(plan).maximum_expression_length,
                4096
            );
        }
    }
}
