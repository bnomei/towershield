//! Lower portable [`PathMatcher`] values into Cloudflare expression fragments.
//!
//! Fragments are combined by [`combine_expressions`] and optionally prefixed
//! with a host-scope predicate from [`host_scope_expr`]. This module does not
//! enforce plan limits; packing lives in [`crate::exporter`].

use shield_core::{
    matcher::{CaseSensitivity, PathMatcher},
    rule::Rule,
};

use crate::options::HostScope;

/// Translate one rule's matcher into a Cloudflare expression fragment.
///
/// Returns `None` when there is no semantics-preserving translation
/// (today: [`PathMatcher::Wildcard`]). Segment matchers are approximated as
/// `contains "/seg/"` and still return `Some`. Case-insensitive rules wrap
/// the path field in `lower(...)`.
pub fn compile_rule_expression(rule: &Rule) -> Option<String> {
    let case = rule.case_sensitivity;
    match &rule.matcher {
        PathMatcher::Exact(v) => {
            let val = v.to_ascii_lowercase();
            if case == CaseSensitivity::Insensitive {
                Some(format!("lower(http.request.uri.path) eq {:?}", val))
            } else {
                Some(format!("http.request.uri.path eq {:?}", v))
            }
        }
        PathMatcher::Prefix(v) => {
            let val = if case == CaseSensitivity::Insensitive {
                v.to_ascii_lowercase()
            } else {
                v.clone()
            };
            let path_expr = if case == CaseSensitivity::Insensitive {
                "lower(http.request.uri.path)".to_owned()
            } else {
                "http.request.uri.path".to_owned()
            };
            Some(format!("starts_with({}, {:?})", path_expr, val))
        }
        PathMatcher::Suffix(v) => {
            let val = if case == CaseSensitivity::Insensitive {
                v.to_ascii_lowercase()
            } else {
                v.clone()
            };
            let path_expr = if case == CaseSensitivity::Insensitive {
                "lower(http.request.uri.path)".to_owned()
            } else {
                "http.request.uri.path".to_owned()
            };
            Some(format!("ends_with({}, {:?})", path_expr, val))
        }
        PathMatcher::Contains(v) => {
            let val = if case == CaseSensitivity::Insensitive {
                v.to_ascii_lowercase()
            } else {
                v.clone()
            };
            if case == CaseSensitivity::Insensitive {
                Some(format!("lower(http.request.uri.path) contains {:?}", val))
            } else {
                Some(format!("http.request.uri.path contains {:?}", val))
            }
        }
        // Core `*` stays in-segment; Cloudflare `*` crosses `/`. Core `**`
        // has no safe CF encoding (consecutive wildcards rejected). Skip.
        PathMatcher::Wildcard(_) => None,
        PathMatcher::Segment(v) => {
            // No native segment op: approximate as contains "/seg/" (see parity).
            let val = if case == CaseSensitivity::Insensitive {
                format!("/{}/", v.to_ascii_lowercase())
            } else {
                format!("/{}/", v)
            };
            if case == CaseSensitivity::Insensitive {
                Some(format!("lower(http.request.uri.path) contains {:?}", val))
            } else {
                Some(format!("http.request.uri.path contains {:?}", val))
            }
        }
        #[cfg(feature = "regex")]
        PathMatcher::Regex(v) => {
            // Caller must enforce plan regex capability; we only lower syntax.
            if case == CaseSensitivity::Insensitive {
                Some(format!(
                    "http.request.uri.path matches {:?}",
                    format!("(?i:{v})")
                ))
            } else {
                Some(format!("http.request.uri.path matches {:?}", v))
            }
        }
    }
}

/// Optional `http.host in {…}` predicate for hostname-scoped exports.
///
/// [`HostScope::AllHosts`] and empty hostname lists yield `None` (no prefix).
pub fn host_scope_expr(scope: &HostScope) -> Option<String> {
    match scope {
        HostScope::AllHosts => None,
        HostScope::Hostnames(hosts) if hosts.is_empty() => None,
        HostScope::Hostnames(hosts) => {
            let quoted: Vec<String> = hosts.iter().map(|h| format!("{:?}", h)).collect();
            Some(format!("(http.host in {{{}}})", quoted.join(" ")))
        }
    }
}

/// Join path fragments with `or`, optionally requiring a host-scope prefix.
///
/// # Panics
///
/// Panics if `fragments` is empty. Callers must only combine after at least
/// one rule compiled successfully.
pub fn combine_expressions(fragments: &[String], host_prefix: Option<&str>) -> String {
    assert!(
        !fragments.is_empty(),
        "cannot combine empty expression list"
    );
    let body = if fragments.len() == 1 {
        fragments[0].clone()
    } else {
        let joined = fragments
            .iter()
            .map(|f| format!("    {}", f))
            .collect::<Vec<_>>()
            .join(" or\n");
        format!("(\n{}\n)", joined)
    };

    match host_prefix {
        Some(hp) => format!("{} and\n{}", hp, body),
        None => body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_core::{
        matcher::{CaseSensitivity, PathMatcher},
        rule::{Rule, RuleGroup},
    };

    fn rule(m: PathMatcher) -> Rule {
        Rule::deny("test.r", RuleGroup::Secrets, "test", m)
    }

    #[test]
    fn exact_insensitive() {
        let expr = compile_rule_expression(&rule(PathMatcher::Exact("/.env".into())));
        assert_eq!(expr.unwrap(), r#"lower(http.request.uri.path) eq "/.env""#);
    }

    #[test]
    fn exact_sensitive() {
        let rule = rule(PathMatcher::Exact("/.env".into()))
            .with_case_sensitivity(CaseSensitivity::Sensitive);
        let expr = compile_rule_expression(&rule);
        assert_eq!(expr.unwrap(), r#"http.request.uri.path eq "/.env""#);
    }

    #[test]
    fn prefix_insensitive() {
        let expr = compile_rule_expression(&rule(PathMatcher::Prefix("/wp-admin/".into())));
        assert_eq!(
            expr.unwrap(),
            r#"starts_with(lower(http.request.uri.path), "/wp-admin/")"#
        );
    }

    #[test]
    fn suffix_sensitive() {
        let rule = rule(PathMatcher::Suffix(".php".into()))
            .with_case_sensitivity(CaseSensitivity::Sensitive);
        let expr = compile_rule_expression(&rule);
        assert_eq!(expr.unwrap(), r#"ends_with(http.request.uri.path, ".php")"#);
    }

    #[test]
    fn host_scope_two_hosts() {
        let scope = HostScope::Hostnames(vec!["example.com".into(), "www.example.com".into()]);
        let expr = host_scope_expr(&scope).unwrap();
        assert!(expr.contains("example.com"));
        assert!(expr.contains("www.example.com"));
    }

    #[test]
    fn host_scope_all_hosts_is_none() {
        assert!(host_scope_expr(&HostScope::AllHosts).is_none());
    }
}
