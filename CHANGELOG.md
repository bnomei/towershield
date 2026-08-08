# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Built-in rule versioning policy

Adding a new built-in rule may cause a previously-allowed path to be blocked.
This is a **behavioural change** and is treated as follows:

- **Adding a built-in rule**: minor version bump (`0.x.0` → `0.x+1.0`).
- **Removing or weakening a built-in rule**: major version bump.
- **Correcting a rule that was incorrectly blocking a non-scanner path**:
  treated as a bug fix (patch version).

Applications that are concerned about unexpected blocking from new rules
should pin the minor version.

---

## [0.1.0] – 2026-08-08

### Added

- `shield-core`: portable rule model (`Rule`, `RuleSet`, `PathMatcher`,
  `CaseSensitivity`, `RuleGroup`, `RuleDisposition`, `CompiledRuleSet`).
- `shield-tower`: Tower `Layer` and `Service` (`ShieldLayer`, `ShieldService`,
  `ShieldBuilder`, `BlockedResponse`).
- `shield-cloudflare`: offline Cloudflare Ruleset Engine expression exporter
  (`CloudflareExporter`, `CloudflareExportOptions`, `CloudflarePlan`,
  `CloudflareCapabilities`).
- 13 built-in rule groups covering secrets, source control, cloud credentials,
  SSH keys, build manifests, framework configuration, WordPress, Joomla,
  Drupal, Magento, PHP web-shells, debug endpoints, and AI tool credentials.
- Optional `serde` feature for TOML/JSON rule serialisation.
- Optional `tracing` feature for structured blocked-request events.
- Optional `regex` feature for `PathMatcher::Regex`.
- CI workflow: fmt, check, test, clippy, doc, MSRV.
