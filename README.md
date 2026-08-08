# tower-http-shield

A small, auditable Rust library that rejects obvious automated
vulnerability-scanner paths before they reach Axum routing or application
handlers.

It provides a deterministic Tower `Layer` and `Service` that works naturally
with Axum. It is **not** a general-purpose WAF.

---

## What it does

- Inspects the URI path of every incoming HTTP request.
- Rejects requests whose paths match a configured deny rule.
- Returns an empty HTTP 404 response for blocked paths.
- Forwards all other requests to the inner service, unchanged.
- Ships with conservative built-in rule groups covering 13 scanner-probe
  categories.

## What it explicitly does NOT do

This crate is **not** a full WAF and does not implement:

- SQL injection, XSS, RCE, or OWASP CRS detection
- Request body or response body inspection
- IP reputation, rate limiting, DDoS mitigation, CAPTCHA
- User-agent classification
- Authentication or authorization
- Redirect management or TLS termination
- Background workers, network calls, or rule downloads at runtime

Do not rely on this crate as complete security protection. It is an
inexpensive early-rejection layer for obvious scanner probes and one
component of defence in depth.

---

## Threat model

### What is defended

- Automated vulnerability scanners probing for well-known paths such as
  `/.env`, `/.git/config`, `/wp-login.php`, and `/actuator/env`.
- Trivial percent-encoding bypasses (`%2eenv` → `/.env`).

### What is NOT defended

- Targeted, slow-rate manual reconnaissance.
- Novel or obfuscated paths not covered by the rule set.
- Application-layer vulnerabilities in allowed paths.
- Anything beyond the URI path (query strings, headers, body).

---

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
shield-tower = "0.1"
```

Wrap your complete Axum router:

```rust,no_run
use tower::Layer;
use shield_tower::ShieldLayer;

// Build your router first.
// let router = axum::Router::new()...;

// Wrap the COMPLETE router so the shield runs before Axum route matching.
// let app = ShieldLayer::default().layer(router);
```

---

## Correct Axum integration

**Always wrap the complete router with `Layer::layer`.**

```rust,no_run
use tower::Layer;
use shield_tower::ShieldLayer;
// let app = ShieldLayer::default().layer(router);
```

Do **not** use `router.layer(ShieldLayer::default())`. Axum's `Router::layer`
applies middleware after route matching, so requests that do not match any
route (precisely the scanner probes this library targets) bypass the shield.

---

## Builder example

```rust
use shield_tower::ShieldLayer;
use shield_core::{Rule, RuleGroup, PathMatcher, DEFAULT_RULES};
use http::StatusCode;
use shield_tower::BlockedResponse;

let layer = ShieldLayer::builder()
    .with_ruleset(
        DEFAULT_RULES.get()
            .push(Rule::deny(
                "custom.probe",
                RuleGroup::Custom("myapp".into()),
                "Block internal probe",
                PathMatcher::Exact("/internal/debug".into()),
            ))
    )
    .with_blocked_response(BlockedResponse::with_status(StatusCode::FORBIDDEN))
    .build();
```

---

## Custom rules

```rust
use shield_core::{Rule, RuleGroup, PathMatcher, RuleSet};

let rules = RuleSet::new()
    .push(Rule::deny(
        "custom.admin_probe",
        RuleGroup::Custom("myapp".into()),
        "Block suspicious admin probe",
        PathMatcher::Exact("/admin/setup.php".into()),
    ));
```

---

## Exclusions

Allow rules take precedence over deny rules:

```rust
use shield_core::{Rule, RuleGroup, PathMatcher, DEFAULT_RULES};

let rules = DEFAULT_RULES.get()
    .push(Rule::allow(
        "app.legit_metrics",
        RuleGroup::Custom("application".into()),
        "Allow the real metrics endpoint",
        PathMatcher::Exact("/metrics".into()),
    ));
```

---

## Built-in rule groups

| # | Group | Examples |
|---|-------|---------|
| 1 | Secrets & env files | `/.env`, `/.npmrc`, `/.netrc` |
| 2 | Source-control metadata | `/.git/`, `/.svn/`, `/.hg/` |
| 3 | Cloud credentials | `/.aws/credentials`, `/gcp-credentials.json` |
| 4 | SSH keys | `/.ssh/`, `/id_rsa`, `*.pem`, `*.key` |
| 5 | Build & deployment manifests | `/Dockerfile`, `/terraform.tfstate` |
| 6 | Framework configuration | `/config/master.key`, `/settings.py`, `/appsettings.json` |
| 7 | WordPress probes | `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php` |
| 8 | Joomla probes | `/administrator/`, `/installation/` |
| 9 | Drupal probes | `/sites/default/`, `/update.php` |
| 10 | Magento probes | `/downloader/`, `/shell/` |
| 11 | PHP web-shell probes | `/c99.php`, `/r57.php`, `/shell.php` |
| 12 | Debug / actuator / server-status | `/debug/pprof/`, `/actuator`, `/server-status` |
| 13 | AI & developer-tool credentials | `/.codex/`, `/.cursor/`, `/.claude.json` |

### False-positive considerations

- **WordPress / Joomla / Drupal / Magento / PHP apps**: disable the
  corresponding rule group or add explicit allow rules.
- **`/metrics`, `/health`, `/admin`**: these generic paths are **not**
  blocked by default. More specific descendants may be blocked.
- **Dockerfile or package.json served via HTTP**: add allow rules for those
  exact paths.
- **Developer tools intentionally exposed**: add allow rules.
- **APIs with user-controlled path segments**: add allow rules for legitimate
  paths that coincidentally match a rule.
- **Case-sensitive routers**: the shield's built-in matchers are all
  case-insensitive. Custom rules can specify `CaseSensitivity::Sensitive`.
- **Percent-encoded path parameters**: the shield decodes paths once before
  matching; legitimate encoded params that match a rule must be allowed
  explicitly.

---

## Percent-encoding and normalisation policy

The shield computes a *derived inspection path* from the raw URI path:

1. The raw URI path is percent-decoded **once**.
2. Invalid sequences are left verbatim.
3. The result is ASCII-lowercased for case-insensitive matchers.
4. The query string is **never** included.
5. The original request is **never mutated**.

This covers trivial bypasses such as `%2eenv` → `/.env` without iterative
decoding. See `shield-core/src/inspection.rs` for the exact algorithm.

---

## Response behaviour

Blocked paths receive:

- **HTTP 404 Not Found** (default, configurable).
- Empty body.
- `content-length: 0`.
- No information about which rule matched.
- No reflected request data.

Use `ShieldBuilder::with_blocked_response` to change the status code.

---

## Observability

Register a callback with `ShieldBuilder::on_block`:

```rust,no_run
use shield_tower::ShieldLayer;

let layer = ShieldLayer::builder()
    .on_block(|m, method, path| {
        // m.rule_id, m.group, m.match_kind, m.is_builtin
        // method: &http::Method
        // path: decoded URI path (no query string)
        println!("blocked {} {} by rule {}", method, path, m.rule_id);
    })
    .build();
```

The callback must never log query strings, authorization headers, cookies,
request bodies, or secrets discovered in the path.

Enable the `tracing` Cargo feature for structured `tracing::debug!` events.

---

## Middleware ordering

Place the shield as the **outermost** middleware (applied last, runs first):

```
ShieldLayer               ← runs first, rejects scanner probes
  TracingLayer
    RequestBodyLimitLayer
      AuthLayer
        CompressionLayer
          Router          ← your application
```

---

## Performance expectations

- **Allowed paths**: near-zero cost. One `InspectionPath` allocation (two
  `String` values) per request; no regex evaluation for non-regex rules.
- **Blocked paths**: slightly more work (rule iteration + response
  allocation), but the request never reaches application code.
- **Rule compilation**: performed once at startup; per-request evaluation
  is allocation-free on the hot path.

---

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `serde` | ✓ | Serialise/deserialise rules as TOML/JSON |
| `tracing` | ✓ | `tracing::debug!` events for blocked requests |
| `regex` | ✗ | Enable `PathMatcher::Regex` |
| `axum` | ✗ | Axum convenience re-exports |

---

## MSRV

Rust **1.75** (stable). The MSRV may be updated in minor versions.

---

## Security reporting

Please report security vulnerabilities privately. See [SECURITY.md](SECURITY.md).

---

## Comparison with a full WAF

This crate is a *path denylist*, not a WAF. It does not perform anomaly
scoring, OWASP CRS analysis, SQLi/XSS/RCE detection, or body inspection.
If you need those capabilities, look at dedicated WAF solutions.

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
