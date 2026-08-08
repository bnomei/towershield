//! Cloudflare Ruleset Engine expression generation.

use shield_core::{
    matcher::{CaseSensitivity, PathMatcher},
    rule::Rule,
};

use crate::options::HostScope;

/// Compile a single rule's path matcher into a Cloudflare expression fragment.
///
/// Returns `None` when the rule cannot be represented (e.g. regex on a plan
/// without regex support – caller should emit a diagnostic).
pub fn compile_rule_expression(rule: &Rule, case: CaseSensitivity) -> Option<String> {
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
        PathMatcher::Wildcard(v) => {
            let val = if case == CaseSensitivity::Insensitive {
                v.to_ascii_lowercase()
            } else {
                v.clone()
            };
            if case == CaseSensitivity::Insensitive {
                // Wrap path in lower() and use a lowercased pattern for
                // case-insensitive matching (CF wildcard is case-sensitive).
                Some(format!("lower(http.request.uri.path) wildcard {:?}", val))
            } else {
                Some(format!("http.request.uri.path strict wildcard {:?}", val))
            }
        }
        PathMatcher::Segment(v) => {
            // Cloudflare does not have a segment operator; approximate with
            // contains.  Document this in parity report.
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
            // Regex requires Business/Enterprise.
            Some(format!("http.request.uri.path matches {:?}", v))
        }
    }
}

/// Build a host-scope prefix expression.
pub fn host_scope_expr(scope: &HostScope) -> Option<String> {
    match scope {
        HostScope::AllHosts => None,
        HostScope::Hostnames(hosts) if hosts.is_empty() => None,
        HostScope::Hostnames(hosts) => {
            // (http.host in {"a.com" "b.com"})
            let quoted: Vec<String> = hosts.iter().map(|h| format!("{:?}", h)).collect();
            Some(format!("(http.host in {{{}}})", quoted.join(" ")))
        }
    }
}

/// Combine path expression fragments with `or` into a single expression,
/// optionally prefixed with a host scope predicate.
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
        let expr = compile_rule_expression(
            &rule(PathMatcher::Exact("/.env".into())),
            CaseSensitivity::Insensitive,
        );
        assert_eq!(expr.unwrap(), r#"lower(http.request.uri.path) eq "/.env""#);
    }

    #[test]
    fn exact_sensitive() {
        let expr = compile_rule_expression(
            &rule(PathMatcher::Exact("/.env".into())),
            CaseSensitivity::Sensitive,
        );
        assert_eq!(expr.unwrap(), r#"http.request.uri.path eq "/.env""#);
    }

    #[test]
    fn prefix_insensitive() {
        let expr = compile_rule_expression(
            &rule(PathMatcher::Prefix("/wp-admin/".into())),
            CaseSensitivity::Insensitive,
        );
        assert_eq!(
            expr.unwrap(),
            r#"starts_with(lower(http.request.uri.path), "/wp-admin/")"#
        );
    }

    #[test]
    fn suffix_sensitive() {
        let expr = compile_rule_expression(
            &rule(PathMatcher::Suffix(".php".into())),
            CaseSensitivity::Sensitive,
        );
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
