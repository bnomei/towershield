//! Tower HTTP adapter for the portable path denylist in [`towershield_core`].
//!
//! [`ShieldLayer`] compiles a [`RuleSet`] once and wraps any Tower
//! [`Service`][tower_service::Service]. On each request it builds an
//! [`towershield_core::InspectionPath`] from `uri.path()`, evaluates the compiled
//! rules, and either forwards the request **unchanged** or returns a generic
//! blocked response without calling the inner service.
//!
//! ## Placement (critical for Axum)
//!
//! Wrap the **complete** `axum::Router` with `Layer::layer` so the shield runs
//! *before* route matching. `router.layer(ShieldLayer::…)` runs *after*
//! matching, so unmatched scanner probes never hit the denylist.
//!
//! ```rust,no_run
//! use tower::Layer;
//! use towershield::ShieldLayer;
//! // let app = ShieldLayer::default().layer(router);
//! ```
//!
//! ## Middleware ordering
//!
//! Keep the shield outermost (applied last → runs first):
//!
//! ```text
//! ShieldLayer               ← reject probes before the rest of the stack
//!   TracingLayer
//!     RequestBodyLimitLayer
//!       AuthLayer
//!         Router
//! ```
//!
//! ```rust,no_run
//! # use tower::ServiceBuilder;
//! # use towershield::ShieldLayer;
//! # let router = tower::service_fn(|_: http::Request<()>| async { Ok::<_, std::convert::Infallible>(http::Response::new(())) });
//! let app = ServiceBuilder::new()
//!     .layer(ShieldLayer::default())
//!     .service(router);
//! ```
//!
//! Core rule types are re-exported so application crates can depend only on
//! `towershield` for common configuration.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]

mod layer;
mod service;

pub use layer::{BlockedResponse, OnBlock, ShieldBuilder, ShieldLayer};
pub use service::ShieldService;

pub use towershield_core::{
    CaseSensitivity, CompiledRuleSet, DEFAULT_RULES, MatchKind, PathMatcher, Rule, RuleDisposition,
    RuleGroup, RuleId, RuleSchemaVersion, RuleSet, ShieldDecision, ShieldMatch,
};
