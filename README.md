# TowerShield

[![Crates.io Version](https://img.shields.io/crates/v/towershield)](https://crates.io/crates/towershield)
[![Docs.rs](https://img.shields.io/docsrs/towershield)](https://docs.rs/towershield)
[![CI](https://img.shields.io/github/actions/workflow/status/bnomei/towershield/ci.yml?branch=main)](https://github.com/bnomei/towershield/actions/workflows/ci.yml)
[![Crates.io Downloads](https://img.shields.io/crates/d/towershield)](https://crates.io/crates/towershield)
[![License](https://img.shields.io/crates/l/towershield)](https://crates.io/crates/towershield)
[![Discord](https://flat.badgen.net/badge/discord/bnomei?color=7289da&icon=discord&label)](https://discordapp.com/users/bnomei)
[![Buymecoffee](https://flat.badgen.net/badge/icon/donate?icon=buymeacoffee&color=FF813F&label)](https://www.buymeacoffee.com/bnomei)

`towershield` is a small, auditable Rust workspace for rejecting
high-confidence vulnerability-scanner paths before they reach Axum routes or
application handlers. It includes a framework-neutral rule engine, a Tower
middleware layer, and an offline Cloudflare Ruleset Engine exporter.

This project is a path denylist, not a general-purpose web application
firewall (WAF). Use it as one inexpensive layer in a defence-in-depth setup.

## Workspace crates

| Crate | Purpose | API documentation |
| --- | --- | --- |
| [`towershield`](crates/shield-tower) | Tower `Layer` and `Service` for rejecting matched requests. | [docs.rs](https://docs.rs/towershield) |
| [`towershield-core`](crates/shield-core) | Portable rules, matchers, serialization, and built-in rules. | [docs.rs](https://docs.rs/towershield-core) |
| [`towershield-cloudflare`](crates/shield-cloudflare) | Offline Cloudflare expression and Rulesets API JSON generation. | [docs.rs](https://docs.rs/towershield-cloudflare) |

## Requirements

- Rust 1.97 or newer (the project's current stable toolchain).
- A Tower-compatible HTTP service. Axum is supported through its Tower
  integration.

The library performs no network calls and needs no runtime credentials.

## Installation

Add the Tower middleware to your application:

```toml
[dependencies]
towershield = "0.1"
```

Add `towershield-core` when you want to construct or serialize rules directly,
and add `towershield-cloudflare` when you want offline Cloudflare output. The
package and Rust library names follow the same `towershield*` family:

```toml
[dependencies]
towershield-core = "0.1"
towershield-cloudflare = "0.1"
```

## Quick start with Axum

Build the complete router, then wrap it with `Layer::layer`:

```rust
use axum::{routing::get, Router};
use towershield::ShieldLayer;
use tower::Layer;

fn main() {
    let router: Router = Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/api/users", get(|| async { "[]" }));

    let _app = ShieldLayer::default().layer(router);
}
```

The resulting service returns `404 Not Found` for a built-in probe such as
`/.env` and forwards `/api/users` unchanged.

Do not use `router.layer(ShieldLayer::default())` when you need to inspect
unmatched routes. Axum applies router middleware after route matching, so a
scanner probe with no matching route can bypass that layer. The complete
working example demonstrates the preferred wrapping and verifies both blocked
and allowed requests:

```bash
cargo run --example axum --package towershield
```

Expected output ends with:

```text
All assertions passed.
```

## Configure rules

`ShieldLayer::default()` uses the built-in rule set. Add a high-confidence
application-specific deny rule with the builder:

```rust
use towershield::{PathMatcher, Rule, RuleGroup, ShieldLayer};

let layer = ShieldLayer::builder()
    .add_rule(Rule::deny(
        "custom.internal_debug",
        RuleGroup::Custom("myapp".into()),
        "Block the internal debug probe",
        PathMatcher::Exact("/internal/debug".into()),
    ))
    .build();
```

Rules are ASCII case-insensitive by default. Opt into case-sensitive matching
for a custom rule when your router distinguishes path case:

```rust
use towershield::{CaseSensitivity, PathMatcher, Rule, RuleGroup};

let rule = Rule::deny(
    "custom.admin",
    RuleGroup::Custom("myapp".into()),
    "Block the case-sensitive admin path",
    PathMatcher::Exact("/Admin".into()),
)
.with_case_sensitivity(CaseSensitivity::Sensitive);
```

### Add an exclusion

Allow rules take precedence over all deny rules. Use a narrow matcher for a
legitimate path that would otherwise be blocked:

```rust
use towershield::{PathMatcher, Rule, RuleGroup, ShieldLayer, DEFAULT_RULES};

let rules = DEFAULT_RULES.get().push(Rule::allow(
    "app.legitimate_path",
    RuleGroup::Custom("application".into()),
    "Allow the application's legitimate endpoint",
    PathMatcher::Exact("/internal/debug".into()),
));

let layer = ShieldLayer::builder().with_ruleset(rules).build();
```

### Change the blocked response

Blocked responses contain an empty body and `content-length: 0`. The default
status is `404 Not Found`; change it when your application requires another
status:

```rust
use http::StatusCode;
use towershield::{BlockedResponse, ShieldLayer};

let layer = ShieldLayer::builder()
    .with_blocked_response(BlockedResponse::with_status(StatusCode::FORBIDDEN))
    .build();
```

### Observe blocked requests

Register a callback, or use the default `tracing` feature for structured debug
events:

```rust
use towershield::ShieldLayer;

let layer = ShieldLayer::builder()
    .on_block(|matched, method, path| {
        println!("blocked {method} {path} by {}", matched.rule_id);
    })
    .build();
```

The callback receives the decoded URI path, without its query string. Do not
log secrets discovered in paths or add sensitive headers, cookies, or request
bodies to this event.

## Export rules for Cloudflare

`towershield-cloudflare` converts the same deny rules into expressions and a
Rulesets API-compatible JSON payload. It does not deploy the payload or access
Cloudflare credentials.

```rust
use towershield_cloudflare::{
    CloudflareExportOptions, CloudflareExporter, CloudflarePlan,
};
use towershield_core::DEFAULT_RULES;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = CloudflareExportOptions::builder()
        .hostnames(["example.com", "www.example.com"])
        .plan(CloudflarePlan::Pro)
        .build();

    let output = CloudflareExporter::export(&DEFAULT_RULES.get(), &options)?;
    println!("{}", output.report.to_string_report());
    println!("{}", output.to_json()?);
    Ok(())
}
```

Review `output.report.diagnostics` before deployment. Cloudflare and Tower do
not normalize every path in exactly the same way; see the
[`towershield_cloudflare::parity`](https://docs.rs/towershield-cloudflare/latest/towershield_cloudflare/parity/)
module for the compatibility boundaries.

## Built-in rule groups

The default rules cover 14 categories of high-confidence scanner probes:

| Group | Example paths |
| --- | --- |
| Secrets and environment files | `/.env`, `/.npmrc`, `/.netrc` |
| Source-control metadata | `/.git/`, `/.svn/`, `/.hg/` |
| Cloud credentials | `/.aws/credentials`, `/gcp-credentials.json` |
| SSH keys and certificates | `/.ssh/`, `/id_rsa`, `*.pem`, `*.key` |
| Build and deployment manifests | `/Dockerfile`, `/terraform.tfstate` |
| Framework configuration | `/config/master.key`, `/settings.py`, `/appsettings.json` |
| JavaScript, React, and Next.js tooling | `/package.json`, `/bun.lock`, `/.next/`, `/__nextjs_original-stack-frame`, `/@vite/client` |
| WordPress | `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php` |
| Joomla | `/administrator/`, `/installation/` |
| Drupal | `/sites/default/`, `/update.php` |
| Magento | `/downloader/`, `/shell/` |
| PHP web shells | `/c99.php`, `/r57.php`, `/shell.php` |
| Debug and actuator endpoints | `/debug/pprof/`, `/actuator`, `/server-status` |
| AI and developer-tool credentials | `/.codex/`, `/.cursor/`, `/.claude.json` |

Applications serving WordPress, Joomla, Drupal, Magento, PHP, build manifests,
developer-tool files, or deliberately exposed Next.js/Vite development
endpoints should review the built-ins and add precise allow rules before
enabling the middleware. Normal production assets such as `/_next/static`,
`/_next/image`, JavaScript bundles, and `/manifest.json` remain allowed.

## Path inspection policy

For every request, the Tower service derives an inspection path:

1. Read `http::Uri::path()`; query strings are excluded.
2. Percent-decode the path exactly once.
3. Preserve invalid percent sequences verbatim.
4. Lazily produce an ASCII-lowercase form only when a rule needs it.
5. Evaluate allow rules, then deny rules.

The middleware does not collapse `.` or `..`, normalize duplicate slashes,
convert backslashes, or mutate the original request. See
[`inspection.rs`](crates/shield-core/src/inspection.rs) for the exact policy.

## Threat model and boundaries

The built-in rules target automated probes for well-known sensitive paths and
cover trivial one-pass percent-encoding variants such as `%2eenv`.

This project does not provide:

- SQL injection, XSS, RCE, or OWASP Core Rule Set detection.
- Header, query-string, request-body, or response-body inspection.
- IP reputation, rate limiting, DDoS mitigation, or CAPTCHA.
- Authentication, authorization, TLS termination, or redirect management.
- Runtime rule downloads, background workers, or network calls.
- Protection from novel obfuscation, targeted reconnaissance, or
  vulnerabilities in allowed application routes.

The JavaScript rules reduce exposed-file and development-endpoint probing;
they are not substitutes for framework updates. In particular, path-only
filtering cannot mitigate Next.js middleware-header bypasses such as
[CVE-2025-29927](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
or attacker-controlled React Server Components protocol payloads such as
[CVE-2025-66478](https://nextjs.org/blog/CVE-2025-66478).

## Cargo features

Features are defined per crate:

| Crate | Feature | Default | Purpose |
| --- | --- | --- | --- |
| `towershield-core` | `serde` | Yes | Serialize and deserialize rules with Serde, JSON, and TOML. |
| `towershield-core` | `regex` | Yes | Enable regex matchers and 16 broader built-in rules. |
| `towershield-core` | `rayon` | No | Enable regex support and parallelize compilation of large regex-heavy custom rule sets. |
| `towershield` | `tracing` | Yes | Emit structured debug events for blocked requests. |
| `towershield` | `regex` | Yes | Enable regex matchers and the broader built-in rule tier. |
| `towershield` | `rayon` | No | Forward the core crate's opt-in parallel compilation. |
| `towershield-cloudflare` | `serde` | Yes | Serialize Rulesets API output as JSON. |
| `towershield-cloudflare` | `regex` | Yes | Export regex matchers and include the broader built-in rule tier. |
| `towershield-cloudflare` | `rayon` | No | Forward the core crate's opt-in parallel compilation. |

### Disabling regex

Regex support is on by default because it materially improves the built-in
coverage. To remove the regex dependency from the Tower middleware:

```toml
towershield = { version = "0.1", default-features = false, features = ["tracing"] }
```

For `towershield-core` or `towershield-cloudflare`, re-enable `serde` explicitly
if you still need serialization:

```toml
towershield-core = { version = "0.1", default-features = false, features = ["serde"] }
towershield-cloudflare = { version = "0.1", default-features = false, features = ["serde"] }
```

This does **not** disable TowerShield. The conservative exact, prefix, suffix,
segment, contains, and wildcard baseline remains. It does remove 16 expansion
rules, so nested environment and credential files, nested package manifests and
framework configs, nested CMS installations, PHP shell filenames, debug paths,
and AI-tool metadata receive substantially less coverage. For example,
`/package-lock.json` remains blocked while `/frontend/package-lock.json` is no
longer caught by the built-in set.

Cargo features are additive, so another dependency can re-enable regex. Check
the resolved graph with:

```console
cargo tree -e features -i towershield-core
```

The Cloudflare exporter emits diagnostics and skips regex rules when the
selected Cloudflare plan does not support the `matches` operator.

## Performance model

The built-in rules compile once per process and are shared by default layers.
Custom rule sets compile when their layer is built. Ordinary lowercase,
unencoded paths borrow the URI path and allocate nothing during inspection;
percent-decoding and ASCII case folding allocate lazily only when required.
Allow and deny rules live in separate compiled tables, so the common built-in
deny-only set is scanned once. A blocked decision owns its match metadata and
returns before invoking the inner service.

The optional `rayon` feature is intentionally narrow: it activates only when
an enabled custom set contains at least 256 regex rules. Exact, prefix, suffix,
and ordinary-sized sets remain sequential, and request evaluation is never
parallelized. This keeps Rayon scheduling and memory overhead away from the
latency-sensitive request path.

Run `cargo bench -p towershield-core --bench core_checker` for the core matcher,
including allocation counts and peak live bytes. Benchmark your own custom
rule set and traffic shape before relying on a latency or throughput target.

## Project maintenance

- [Changelog](CHANGELOG.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Axum example](crates/shield-tower/examples/axum.rs)

## License

Licensed under the [MIT License](LICENSE).
