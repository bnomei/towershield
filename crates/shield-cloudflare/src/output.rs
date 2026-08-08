//! Output types for Cloudflare export.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A Cloudflare Rulesets API-compatible rule entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CloudflareApiRule {
    /// Human-readable description.
    pub description: String,
    /// Ruleset Engine expression.
    pub expression: String,
    /// Action string.
    pub action: String,
    /// Whether this rule is enabled.
    pub enabled: bool,
}

/// A Cloudflare Rulesets API-compatible ruleset payload.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CloudflareApiRuleset {
    /// Ruleset name.
    pub name: String,
    /// Ruleset description.
    pub description: String,
    /// Rule kind, e.g. `"custom"`.
    pub kind: String,
    /// Phase, e.g. `"http_request_firewall_custom"`.
    pub phase: String,
    /// The generated rules.
    pub rules: Vec<CloudflareApiRule>,
}

/// A single diagnostic emitted when a rule cannot be fully exported.
#[derive(Debug, Clone)]
pub struct ExportDiagnostic {
    /// The rule ID that triggered the diagnostic.
    pub rule_id: String,
    /// Human-readable explanation.
    pub message: String,
    /// Optional suggestion.
    pub suggestion: Option<String>,
}

/// Human-readable export report.
#[derive(Debug, Clone)]
pub struct ExportReport {
    /// IDs of rules included in the export.
    pub included_rule_ids: Vec<String>,
    /// IDs of rules that were disabled and skipped.
    pub disabled_rule_ids: Vec<String>,
    /// Number of generated Cloudflare rules.
    pub cloudflare_rule_count: usize,
    /// Expression lengths for each generated rule.
    pub expression_lengths: Vec<usize>,
    /// Whether regex capability was used.
    pub used_regex: bool,
    /// Hostname scope description.
    pub hostname_scope: String,
    /// Diagnostics for unsupported or partially-supported rules.
    pub diagnostics: Vec<ExportDiagnostic>,
}

impl ExportReport {
    /// Format the report as a human-readable string.
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

/// Combined output from a Cloudflare export operation.
#[derive(Debug, Clone)]
pub struct CloudflareOutput {
    /// Raw Ruleset Engine expression (deny rules only, combined).
    pub expression: String,
    /// Rulesets API-compatible JSON payload.
    pub api_ruleset: CloudflareApiRuleset,
    /// Human-readable report.
    pub report: ExportReport,
}

impl CloudflareOutput {
    /// Serialize the API ruleset to JSON.
    #[cfg(feature = "serde")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.api_ruleset)
    }
}
