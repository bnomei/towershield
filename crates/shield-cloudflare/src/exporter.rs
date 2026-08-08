//! Offline compile of a portable [`RuleSet`] into Cloudflare Ruleset output.
//!
//! [`CloudflareExporter::export`] is the only entry point: deterministic,
//! side-effect free, and suitable for CI or config-generation pipelines.

use shield_core::{
    matcher::PathMatcher,
    rule::{Rule, RuleDisposition},
    ruleset::RuleSet,
};
use thiserror::Error;

use crate::{
    expression::{combine_expressions, compile_rule_expression, host_scope_expr},
    options::{CloudflareExportOptions, HostScope},
    output::{
        CloudflareApiRule, CloudflareApiRuleset, CloudflareOutput, ExportDiagnostic, ExportReport,
    },
};

/// Hard failure that aborts export (missing scope, empty set, plan overflow).
///
/// Soft mismatches (segment approximation, skipped wildcards) become
/// [`ExportDiagnostic`] entries inside a successful [`CloudflareOutput`].
#[derive(Debug, Error)]
pub enum ExportError {
    /// Neither hostnames nor an explicit [`HostScope::AllHosts`] was set.
    #[error("host scope required: set hostnames or call all_hosts()")]
    MissingHostScope,
    /// No enabled deny rules could be translated into Cloudflare fragments.
    #[error("no exportable deny rules in rule set")]
    NoRules,
    /// A packed expression exceeded the plan character budget.
    #[error("expression size {size} exceeds plan maximum {max} for rule group {index}")]
    ExpressionTooLong {
        /// Character length of the generated expression.
        size: usize,
        /// Plan maximum expression length.
        max: usize,
        /// Zero-based index of the Cloudflare rule being built.
        index: usize,
    },
    /// Packing produced more Cloudflare rules than the plan allows.
    #[error("generated {count} Cloudflare rules but plan allows {max}")]
    TooManyRules {
        /// Number of Cloudflare rules after packing.
        count: usize,
        /// Plan maximum rule count.
        max: usize,
    },
}

/// Stateless offline exporter from portable rules to Cloudflare artifacts.
pub struct CloudflareExporter;

impl CloudflareExporter {
    /// Compile `ruleset` under `options` into expressions, API JSON, and a report.
    ///
    /// Only **enabled deny** rules are candidates. Allow rules stay on the
    /// Tower side as exclusions. Deny rules are sorted by ID for deterministic
    /// output. Fragments are packed into `or` groups up to the plan's
    /// expression-length and rule-count caps.
    ///
    /// # Errors
    ///
    /// Returns [`ExportError`] when host scope is unset, nothing is
    /// exportable, or packing exceeds plan limits.
    pub fn export(
        ruleset: &RuleSet,
        options: &CloudflareExportOptions,
    ) -> Result<CloudflareOutput, ExportError> {
        // 1. Validate host scope.
        match &options.host_scope {
            HostScope::Hostnames(h) if h.is_empty() => {
                return Err(ExportError::MissingHostScope);
            }
            _ => {}
        }

        let host_expr = host_scope_expr(&options.host_scope);
        let host_prefix = host_expr.as_deref();
        let caps = &options.capabilities;

        let mut included: Vec<String> = Vec::new();
        let mut disabled: Vec<String> = Vec::new();
        let mut diagnostics: Vec<ExportDiagnostic> = Vec::new();
        #[cfg(feature = "regex")]
        let mut used_regex = false;
        #[cfg(not(feature = "regex"))]
        let used_regex = false;

        // 2. Collect deny rules sorted by ID for determinism.
        let mut deny_rules: Vec<&Rule> = ruleset
            .rules
            .iter()
            .filter(|r| r.enabled && r.disposition == RuleDisposition::Deny)
            .collect();
        deny_rules.sort_by(|a, b| a.id.0.cmp(&b.id.0));

        for r in &ruleset.rules {
            if !r.enabled {
                disabled.push(r.id.0.clone());
            }
        }

        if deny_rules.is_empty() {
            return Err(ExportError::NoRules);
        }

        // 3. Compile each rule, emitting diagnostics for unsupported cases.
        let mut fragments: Vec<String> = Vec::new();
        for rule in &deny_rules {
            // Detect regex rules on plans without regex.
            #[cfg(feature = "regex")]
            if matches!(rule.matcher, PathMatcher::Regex(_)) && !caps.regex {
                diagnostics.push(ExportDiagnostic {
                    rule_id: rule.id.0.clone(),
                    message: format!(
                        "Rule `{}` requires Cloudflare regex support. Target plan does not support `matches`.",
                        rule.id
                    ),
                    suggestion: Some(
                        "Rewrite as exact/prefix/suffix/wildcard rules, or upgrade plan.".into(),
                    ),
                });
                continue;
            }

            // Detect segment matchers (approximated).
            if matches!(rule.matcher, PathMatcher::Segment(_)) {
                diagnostics.push(ExportDiagnostic {
                    rule_id: rule.id.0.clone(),
                    message: format!(
                        "Rule `{}` uses Segment matcher which is approximated as `contains` in Cloudflare. May produce false positives or negatives.",
                        rule.id
                    ),
                    suggestion: Some("Consider rewriting as Prefix or Exact matcher.".into()),
                });
            }

            if matches!(rule.matcher, PathMatcher::Wildcard(_)) {
                diagnostics.push(ExportDiagnostic {
                    rule_id: rule.id.0.clone(),
                    message: format!(
                        "Rule `{}` uses wildcard semantics that Cloudflare cannot represent exactly.",
                        rule.id
                    ),
                    suggestion: Some(
                        "Rewrite as exact, prefix, suffix, contains, or regex rules.".into(),
                    ),
                });
                continue;
            }

            if let Some(expr) = compile_rule_expression(rule) {
                #[cfg(feature = "regex")]
                if matches!(rule.matcher, PathMatcher::Regex(_)) {
                    used_regex = true;
                }
                included.push(rule.id.0.clone());
                fragments.push(expr);
            }
        }

        if fragments.is_empty() {
            return Err(ExportError::NoRules);
        }

        // 4. Pack fragments into Cloudflare rules respecting plan limits.
        let mut cf_rules: Vec<CloudflareApiRule> = Vec::new();
        let mut current_batch: Vec<String> = Vec::new();
        let max_len = caps.maximum_expression_length;

        let build_expression =
            |batch: &[String]| -> String { combine_expressions(batch, host_prefix) };

        for frag in &fragments {
            current_batch.push(frag.clone());
            let expr = build_expression(&current_batch);
            if expr.len() > max_len {
                // Remove the last fragment and inspect what remains.
                current_batch.pop();
                if current_batch.is_empty() {
                    // Single fragment already exceeds the limit – include it
                    // with a diagnostic, flush, and move on without re-adding.
                    diagnostics.push(ExportDiagnostic {
                        rule_id: "packing".into(),
                        message: format!(
                            "Single rule expression length {} exceeds plan maximum {}.",
                            expr.len(),
                            max_len
                        ),
                        suggestion: Some("Upgrade plan or simplify the rule.".into()),
                    });
                    let single_expr = build_expression(std::slice::from_ref(frag));
                    cf_rules.push(CloudflareApiRule {
                        description: format!(
                            "{}: block scanner paths (part {})",
                            options.rule_name_prefix,
                            cf_rules.len() + 1
                        ),
                        expression: single_expr,
                        action: options.action.as_str().to_owned(),
                        enabled: true,
                    });
                    // current_batch is already empty; continue to next fragment.
                } else {
                    // Flush the batch collected so far (without the current frag).
                    let flush_expr = build_expression(&current_batch);
                    cf_rules.push(CloudflareApiRule {
                        description: format!(
                            "{}: block scanner paths (part {})",
                            options.rule_name_prefix,
                            cf_rules.len() + 1
                        ),
                        expression: flush_expr,
                        action: options.action.as_str().to_owned(),
                        enabled: true,
                    });
                    // Start a fresh batch with the current fragment.
                    current_batch = vec![frag.clone()];
                }
            }
        }

        // Flush the remaining batch.
        if !current_batch.is_empty() {
            let expr = build_expression(&current_batch);
            cf_rules.push(CloudflareApiRule {
                description: format!(
                    "{}: block scanner paths (part {})",
                    options.rule_name_prefix,
                    cf_rules.len() + 1
                ),
                expression: expr,
                action: options.action.as_str().to_owned(),
                enabled: true,
            });
        }

        // 5. Check rule count limit.
        if cf_rules.len() > caps.maximum_rules {
            return Err(ExportError::TooManyRules {
                count: cf_rules.len(),
                max: caps.maximum_rules,
            });
        }

        let expression_lengths: Vec<usize> = cf_rules.iter().map(|r| r.expression.len()).collect();
        let combined_expression = cf_rules
            .first()
            .map(|r| r.expression.clone())
            .unwrap_or_default();

        let hostname_scope = match &options.host_scope {
            HostScope::Hostnames(h) => h.join(", "),
            HostScope::AllHosts => "all hosts".to_owned(),
        };

        let api_ruleset = CloudflareApiRuleset {
            name: options.ruleset_name.clone(),
            description: options.ruleset_description.clone(),
            kind: "custom".to_owned(),
            phase: "http_request_firewall_custom".to_owned(),
            rules: cf_rules.clone(),
        };

        let report = ExportReport {
            included_rule_ids: included,
            disabled_rule_ids: disabled,
            cloudflare_rule_count: cf_rules.len(),
            expression_lengths,
            used_regex,
            hostname_scope,
            diagnostics,
        };

        Ok(CloudflareOutput {
            expression: combined_expression,
            api_ruleset,
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::CloudflareExportOptions;
    use crate::plan::CloudflarePlan;
    use shield_core::{CaseSensitivity, DEFAULT_RULES, PathMatcher, Rule, RuleGroup, RuleSet};

    fn opts_with_host(host: &str) -> CloudflareExportOptions {
        CloudflareExportOptions::builder()
            .hostnames([host])
            .plan(CloudflarePlan::Enterprise)
            .build()
    }

    #[test]
    fn missing_host_scope_returns_error() {
        let rs = DEFAULT_RULES.get();
        let opts = CloudflareExportOptions::default();
        assert!(matches!(
            CloudflareExporter::export(&rs, &opts),
            Err(ExportError::MissingHostScope)
        ));
    }

    #[test]
    fn export_produces_output() {
        let rs = DEFAULT_RULES.get();
        let opts = opts_with_host("example.com");
        let out = CloudflareExporter::export(&rs, &opts).unwrap();
        assert!(!out.expression.is_empty());
        assert!(!out.api_ruleset.rules.is_empty());
        assert!(out.expression.contains("example.com"));
        assert_eq!(out.api_ruleset.phase, "http_request_firewall_custom");
    }

    #[test]
    fn export_report_includes_rule_ids() {
        let rs = DEFAULT_RULES.get();
        let opts = opts_with_host("example.com");
        let out = CloudflareExporter::export(&rs, &opts).unwrap();
        assert!(!out.report.included_rule_ids.is_empty());
        assert!(
            out.report
                .included_rule_ids
                .iter()
                .any(|id| id.contains("secrets"))
        );
    }

    #[test]
    fn all_hosts_produces_unscoped_expression() {
        let rs = DEFAULT_RULES.get();
        let opts = CloudflareExportOptions::builder()
            .all_hosts()
            .plan(CloudflarePlan::Enterprise)
            .build();
        let out = CloudflareExporter::export(&rs, &opts).unwrap();
        assert!(!out.expression.contains("http.host"));
    }

    #[test]
    fn output_is_deterministic() {
        let rs = DEFAULT_RULES.get();
        let opts = opts_with_host("example.com");
        let a = CloudflareExporter::export(&rs, &opts).unwrap();
        let b = CloudflareExporter::export(&rs, &opts).unwrap();
        assert_eq!(a.expression, b.expression);
        assert_eq!(a.report.included_rule_ids, b.report.included_rule_ids);
    }

    #[test]
    fn export_respects_case_sensitive_rules() {
        let rs = RuleSet::new().push(
            Rule::deny(
                "test.case_sensitive",
                RuleGroup::Custom("test".into()),
                "test",
                PathMatcher::Exact("/Admin".into()),
            )
            .with_case_sensitivity(CaseSensitivity::Sensitive),
        );
        let out = CloudflareExporter::export(&rs, &opts_with_host("example.com")).unwrap();

        assert!(
            out.expression
                .contains(r#"http.request.uri.path eq "/Admin""#)
        );
        assert!(!out.expression.contains("lower(http.request.uri.path)"));
    }

    #[test]
    fn wildcard_rules_are_skipped_with_a_diagnostic() {
        let rs = RuleSet::new()
            .push(Rule::deny(
                "test.exact",
                RuleGroup::Custom("test".into()),
                "exportable",
                PathMatcher::Exact("/blocked".into()),
            ))
            .push(Rule::deny(
                "test.wildcard",
                RuleGroup::Custom("test".into()),
                "not exactly exportable",
                PathMatcher::Wildcard("/admin/*".into()),
            ));
        let out = CloudflareExporter::export(&rs, &opts_with_host("example.com")).unwrap();

        assert!(!out.expression.contains("wildcard"));
        assert!(out.report.diagnostics.iter().any(|diagnostic| {
            diagnostic.rule_id == "test.wildcard"
                && diagnostic.message.contains("cannot represent exactly")
        }));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_output_is_valid() {
        let rs = DEFAULT_RULES.get();
        let opts = opts_with_host("example.com");
        let out = CloudflareExporter::export(&rs, &opts).unwrap();
        let json = out.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["phase"], "http_request_firewall_custom");
    }
}
