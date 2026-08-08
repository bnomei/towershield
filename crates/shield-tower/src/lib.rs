//! # shield-tower
//!
//! Tower [`Layer`][tower_layer::Layer] and [`Service`][tower_service::Service] for
//! [`shield-core`][shield_core] path-denylist middleware.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use tower::Layer;
//! use shield_tower::ShieldLayer;
//!
//! // Build your Axum router (or any Tower service) first.
//! // fn build_router() -> axum::Router { axum::Router::new() }
//! // let router = build_router();
//!
//! // Wrap the **complete** Router so the shield runs before Axum route
//! // matching. Do NOT use `router.layer(ShieldLayer::default())` – that
//! // runs the middleware *after* route matching, which means un-matched
//! // requests never reach the shield.
//! //
//! // let app = ShieldLayer::default().layer(router);
//! ```
//!
//! ## Middleware ordering
//!
//! Place the shield as the **outermost** middleware (applied last, runs first):
//!
//! ```text
//! ShieldLayer               ← runs first, rejects scanner probes
//!   TracingLayer
//!     RequestBodyLimitLayer
//!       AuthLayer
//!         CompressionLayer
//!           Router          ← your application
//! ```
//!
//! To build this stack, wrap from inside out:
//!
//! ```rust,no_run
//! # use tower::ServiceBuilder;
//! # use shield_tower::ShieldLayer;
//! # let router = tower::service_fn(|_: http::Request<()>| async { Ok::<_, std::convert::Infallible>(http::Response::new(())) });
//! let app = ServiceBuilder::new()
//!     .layer(ShieldLayer::default())
//!     // .layer(TraceLayer::new_for_http())
//!     // .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
//!     .service(router);
//! ```
//!
//! Or equivalently:
//!
//! ```rust,no_run
//! use tower::Layer;
//! use shield_tower::ShieldLayer;
//! # let router = tower::service_fn(|_: http::Request<()>| async { Ok::<_, std::convert::Infallible>(http::Response::new(())) });
//! let app = ShieldLayer::default().layer(router);
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]

mod layer;
mod service;

pub use layer::{BlockedResponse, OnBlock, ShieldBuilder, ShieldLayer};
pub use service::ShieldService;

// Re-export the builder types from shield-core for convenience.
pub use shield_core::{
    CaseSensitivity, CompiledRuleSet, MatchKind, PathMatcher, Rule, RuleDisposition, RuleGroup,
    RuleId, RuleSchemaVersion, RuleSet, ShieldDecision, ShieldMatch, DEFAULT_RULES,
};
