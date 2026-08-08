//! Offline Cloudflare Ruleset Engine exporter for portable shield rules.
//!
//! Turns a [`towershield_core::RuleSet`] into Cloudflare expression text, a
//! Rulesets API-shaped JSON payload, and a human-readable
//! [`ExportReport`]. Export is pure CPU: no network, credentials, zone IDs,
//! Terraform, or live deploy side effects.
//!
//! ## Pipeline
//!
//! 1. Filter enabled **deny** rules (allow rules are Tower-only exclusions).
//! 2. Lower each matcher to a Cloudflare fragment ([`expression`]).
//! 3. Emit soft diagnostics for unsupported or approximated operators.
//! 4. Pack fragments into plan-sized `or` groups with optional host scope.
//! 5. Return [`CloudflareOutput`] for review or hand-off to your deploy tooling.
//!
//! Hard failures ([`exporter::ExportError`]) abort export: missing host
//! scope, nothing exportable, or plan budget overflow. Soft gaps appear as
//! [`output::ExportDiagnostic`] entries inside a successful output.
//!
//! ## Parity
//!
//! Edge matching and the Tower path denylist are not byte-identical. See
//! [`parity`] for field normalisation, segment/wildcard gaps, and how the
//! exporter reports them.
//!
//! # Features
//!
//! | Feature | Effect |
//! |---|---|
//! | `serde` (default) | JSON pretty-print of Rulesets API payloads |
//! | `regex` | Export `PathMatcher::Regex` as Cloudflare `matches` |
//! | `rayon` | Forwarded to `towershield-core` (compile-side only) |
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod exporter;
pub mod expression;
pub mod options;
pub mod output;
pub mod parity;
pub mod plan;

pub use exporter::CloudflareExporter;
pub use options::{CloudflareExportOptions, HostScope};
pub use output::{CloudflareOutput, ExportReport};
pub use plan::{CloudflareCapabilities, CloudflarePlan};
