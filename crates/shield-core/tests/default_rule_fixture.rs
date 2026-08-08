use std::collections::HashSet;

use towershield_core::{DEFAULT_RULES, InspectionPath, ShieldDecision};

const CASES: &str = include_str!("fixtures/default_paths.tsv");

#[test]
fn default_rules_match_request_fixture() {
    let declarative = DEFAULT_RULES.get();
    let mut ids = HashSet::with_capacity(declarative.rules.len());
    for rule in &declarative.rules {
        assert!(rule.builtin, "{} is not marked built-in", rule.id);
        assert!(rule.enabled, "{} is unexpectedly disabled", rule.id);
        assert!(
            ids.insert(rule.id.clone()),
            "duplicate rule id: {}",
            rule.id
        );
    }

    let compiled = DEFAULT_RULES.compiled();
    for (line_number, line) in CASES.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (expected, path) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("invalid fixture line {}", line_number + 1));
        let decision = compiled.evaluate(&InspectionPath::new(path));
        match expected {
            "block" => assert!(
                matches!(decision, ShieldDecision::Block(_)),
                "fixture line {} expected {path} to be blocked",
                line_number + 1
            ),
            "allow" => assert_eq!(
                decision,
                ShieldDecision::Allow,
                "fixture line {} expected {path} to be allowed",
                line_number + 1
            ),
            other => panic!("invalid expectation {other:?} on line {}", line_number + 1),
        }
    }
}
