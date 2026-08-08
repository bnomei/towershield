//! # shield-cloudflare
//!
//! Offline Cloudflare Ruleset Engine expression exporter for
//! [`shield-core`][shield_core] rule sets.
//!
//! ## What this crate does
//!
//! - Compiles portable [`shield_core::RuleSet`] rules into Cloudflare
//!   Ruleset Engine expressions.
//! - Produces Rulesets API-compatible JSON.
//! - Produces a human-readable export report.
//! - Performs host-scoping and plan-capability checks.
//! - Packs multiple rules into grouped `or` expressions within plan limits.
//!
//! ## What this crate does NOT do
//!
//! - Make any network calls.
//! - Read or write Cloudflare API tokens, zone IDs, or ruleset IDs.
//! - Deploy rules to Cloudflare.
//! - Modify Terraform state.
//!
//! ## Semantic parity
//!
//! Cloudflare and the Tower middleware inspect differently-normalised path
//! representations. See [`parity`] for documented differences.
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
