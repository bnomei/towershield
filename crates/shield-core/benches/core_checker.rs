use std::sync::LazyLock;

use divan::{AllocProfiler, Bencher, black_box};
#[cfg(feature = "regex")]
use towershield_core::CaseSensitivity;
use towershield_core::{
    CompiledRuleSet, DEFAULT_RULES, InspectionPath, PathMatcher, Rule, RuleGroup, RuleId, RuleSet,
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

static COMPILED: LazyLock<CompiledRuleSet> = LazyLock::new(|| DEFAULT_RULES.compiled());

const REPRESENTATIVE_PATHS: &[&str] = &[
    "/",
    "/api/v1/users/42",
    "/assets/application.css",
    "/health",
    "/.env",
    "/.git/config",
    "/%2eenv",
    "/.codex/auth.json",
];

fn main() {
    LazyLock::force(&COMPILED);
    divan::main();
}

#[divan::bench]
fn compile_default_rules() -> CompiledRuleSet {
    DEFAULT_RULES
        .get()
        .compile()
        .expect("built-in rules must compile")
}

#[divan::bench]
fn clone_precompiled_default_rules() -> CompiledRuleSet {
    DEFAULT_RULES.compiled()
}

#[divan::bench(args = [256, 1_024, 4_096])]
fn compile_synthetic_rules(bencher: Bencher<'_, '_>, count: usize) {
    let rules = (0..count).fold(RuleSet::new(), |rules, index| {
        rules.push(Rule::deny(
            RuleId::new(format!("bench.rule_{index}")),
            RuleGroup::Custom("benchmark".into()),
            "synthetic compile benchmark",
            PathMatcher::Exact(format!("/scanner/probe/{index}")),
        ))
    });
    bencher.bench_local(|| {
        black_box(rules.clone())
            .compile()
            .expect("synthetic rules must compile")
    });
}

#[cfg(feature = "regex")]
#[divan::bench(args = [64, 256, 1_024])]
fn compile_synthetic_regex_rules(bencher: Bencher<'_, '_>, count: usize) {
    let rules = (0..count).fold(RuleSet::new(), |rules, index| {
        rules.push(
            Rule::deny(
                RuleId::new(format!("bench.regex_{index}")),
                RuleGroup::Custom("benchmark".into()),
                "synthetic regex compile benchmark",
                PathMatcher::Regex(format!(
                    r"^/tenant/{index}/(?:admin|debug|internal)/(?:[a-z0-9_-]{{1,64}})$"
                )),
            )
            .with_case_sensitivity(CaseSensitivity::Sensitive),
        )
    });
    bencher.bench_local(|| {
        black_box(rules.clone())
            .compile()
            .expect("synthetic regex rules must compile")
    });
}

#[divan::bench(args = [
    "/api/v1/users/42",
    "/.env",
    "/%2eenv",
    "/.codex/auth.json",
])]
fn inspect_and_evaluate(bencher: Bencher<'_, '_>, path: &str) {
    bencher.bench_local(|| {
        let inspection = InspectionPath::new(black_box(path));
        black_box(COMPILED.evaluate(&inspection))
    });
}

#[divan::bench(args = [
    "/api/v1/users/42",
    "/.env",
    "/.codex/auth.json",
])]
fn evaluate_prepared_path(bencher: Bencher<'_, '_>, path: &str) {
    let inspection = InspectionPath::new(path);
    bencher.bench_local(|| black_box(COMPILED.evaluate(black_box(&inspection))));
}

#[divan::bench]
fn mixed_request_batch(bencher: Bencher<'_, '_>) {
    bencher.bench_local(|| {
        for path in black_box(REPRESENTATIVE_PATHS) {
            let inspection = InspectionPath::new(path);
            black_box(COMPILED.evaluate(&inspection));
        }
    });
}
