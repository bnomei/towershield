//! Artifacts produced by a successful offline Cloudflare export.
//!
//! [`CloudflareOutput`] bundles the combined expression text, the Rulesets
//! API payload, and an [`ExportReport`] for human or CI review. Soft parity
//! issues appear as [`ExportDiagnostic`] entries rather than hard errors.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// One rule entry in a Rulesets API-compatible payload.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CloudflareApiRule {
    /// Operator-facing description (includes the configured name prefix).
    pub description: String,
    /// Full Ruleset Engine expression for this packed rule.
    pub expression: String,
    /// Action wire value (`block`, `log`, …).
    pub action: String,
    /// Whether the rule should be enabled when applied.
    pub enabled: bool,
}

/// Ruleset wrapper matching the custom firewall phase payload shape.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CloudflareApiRuleset {
    /// Ruleset display name.
    pub name: String,
    /// Ruleset description.
    pub description: String,
    /// Kind wire value (export always uses `"custom"`).
    pub kind: String,
    /// Phase wire value (`"http_request_firewall_custom"`).
    pub phase: String,
    /// Packed rules after plan-aware combining.
    pub rules: Vec<CloudflareApiRule>,
}

/// Soft warning when a source rule is skipped or only approximately exported.
#[derive(Debug, Clone)]
pub struct ExportDiagnostic {
    /// Portable rule ID, or a packing sentinel such as `"packing"`.
    pub rule_id: String,
    /// What went wrong or what was approximated.
    pub message: String,
    /// Optional remediation hint for operators.
    pub suggestion: Option<String>,
}

/// Operator-facing summary of what the exporter included, skipped, and packed.
#[derive(Debug, Clone)]
pub struct ExportReport {
    /// Source rule IDs that produced Cloudflare fragments.
    pub included_rule_ids: Vec<String>,
    /// Source rule IDs with `enabled = false` (never candidates).
    pub disabled_rule_ids: Vec<String>,
    /// Count of packed Cloudflare rules (after `or` grouping).
    pub cloudflare_rule_count: usize,
    /// Character length of each packed expression (for plan budgeting).
    pub expression_lengths: Vec<usize>,
    /// Whether any regex `matches` fragment was emitted.
    pub used_regex: bool,
    /// Human description of host scope (`"all hosts"` or joined names).
    pub hostname_scope: String,
    /// Soft diagnostics (wildcard skip, segment approximation, …).
    pub diagnostics: Vec<ExportDiagnostic>,
}

impl ExportReport {
    /// Render a plain-text report suitable for CLI stdout or CI logs.
    pub fn to_string_report(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Cloudflare Export Report ===\n");
        out.push_str(&format!(
            "Included source rules : {}\n",
            self.included_rule_ids.len()
        ));
        out.push_str(&format!(
            "Disabled source rules : {}\n",
            self.disabled_rule_ids.len()
        ));
        out.push_str(&format!(
            "Generated CF rules    : {}\n",
            self.cloudflare_rule_count
        ));
        out.push_str(&format!(
            "Hostname scope        : {}\n",
            self.hostname_scope
        ));
        out.push_str(&format!("Regex used            : {}\n", self.used_regex));
        if !self.expression_lengths.is_empty() {
            out.push_str(&format!(
                "Expression lengths    : {:?}\n",
                self.expression_lengths
            ));
        }
        if !self.diagnostics.is_empty() {
            out.push_str("\nDiagnostics:\n");
            for d in &self.diagnostics {
                out.push_str(&format!("  [{}] {}\n", d.rule_id, d.message));
                if let Some(s) = &d.suggestion {
                    out.push_str(&format!("    Suggestion: {}\n", s));
                }
            }
        }
        out
    }
}

/// Complete offline export result: expression preview, API body, and report.
///
/// `expression` mirrors the first packed rule for quick inspection; full
/// multi-rule output lives in [`CloudflareOutput::api_ruleset`].
#[derive(Debug, Clone)]
pub struct CloudflareOutput {
    /// Preview expression (typically the first packed Cloudflare rule).
    pub expression: String,
    /// Payload shaped for the Rulesets API (or Terraform hand-off).
    pub api_ruleset: CloudflareApiRuleset,
    /// Inclusion list, sizes, and soft diagnostics.
    pub report: ExportReport,
}

impl CloudflareOutput {
    /// Pretty-print [`CloudflareOutput::api_ruleset`] as JSON (`serde` feature).
    #[cfg(feature = "serde")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.api_ruleset)
    }
}
