# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `towershield-core`: portable rule model (`Rule`, `RuleSet`, `PathMatcher`,
  `CaseSensitivity`, `RuleGroup`, `RuleDisposition`, and `CompiledRuleSet`).
- `towershield`: Tower `Layer` and `Service` (`ShieldLayer`, `ShieldService`,
  `ShieldBuilder`, and `BlockedResponse`).
- `towershield-cloudflare`: offline Cloudflare Ruleset Engine expression exporter
  (`CloudflareExporter`, `CloudflareExportOptions`, `CloudflarePlan`, and
  `CloudflareCapabilities`).
- 13 built-in rule groups covering secrets, source control, cloud credentials,
  SSH keys, build manifests, framework configuration, WordPress, Joomla,
  Drupal, Magento, PHP web shells, debug endpoints, and AI tool credentials.
- Per-rule case-sensitivity configuration for Tower evaluation and Cloudflare
  export.
- Cloudflare diagnostics that skip wildcard rules whose semantics cannot be
  represented safely by the Rules language.
- Optional Serde, tracing, and regex integrations.
- Rust 2024 edition support with Rust 1.97 as the minimum supported version.
- A uniform TowerShield package and library family: `towershield`,
  `towershield-core`, and `towershield-cloudflare`.
- CI checks for formatting, default/no-default/all-feature builds, tests,
  Clippy, rustdoc, stable-toolchain compatibility, and package metadata.
- Current stable releases for all direct dependencies.
- Data-driven default-rule request fixtures and allocation-aware Divan
  benchmarks for compilation, prepared paths, and mixed request batches.
- An opt-in `towershield-core/rayon` feature for compiling custom sets containing
  at least 256 regex rules in parallel; request evaluation stays sequential.
- Conservative rules for common Composer/RubyGems/gcloud credential stores,
  IDE metadata, framework configs and backup variants, debug consoles, and
  Codex/Claude configuration directories.

### Changed

- Simplified project licensing from `MIT OR Apache-2.0` to MIT-only.
- Built-in compiled rules are cached per process and cloned through shared
  rule tables; custom rule compilation reuses owned matcher strings.
- Request inspection now borrows ordinary paths and lazily allocates only for
  percent-decoding or uppercase case folding. Allow and deny rules are stored
  separately to avoid a redundant pass through deny-only rule sets.

### Documentation

- Added an Axum quickstart, crate and feature reference, custom-rule examples,
  Cloudflare export guide, threat model, path-inspection policy, and release
  maintenance guidance.

## Built-in rule versioning policy

Adding a new built-in rule may cause a previously-allowed path to be blocked.
This is a **behavioural change** and is treated as follows:

- **Adding a built-in rule**: minor version bump (`0.x.0` → `0.x+1.0`).
- **Removing or weakening a built-in rule**: major version bump.
- **Correcting a rule that was incorrectly blocking a non-scanner path**:
  treated as a bug fix (patch version).

Applications that are concerned about unexpected blocking from new rules
should pin the minor version.
