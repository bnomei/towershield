//! Configuration and Tower [`Layer`][tower_layer::Layer] for path denylist middleware.
//!
//! [`ShieldBuilder`] owns the authoring-time knobs (rules, blocked status,
//! observability callback). [`ShieldLayer`] holds the compiled, shareable
//! state applied to each wrapped service.

use crate::service::ShieldService;
use http::{Response, StatusCode};
use shield_core::{CompiledRuleSet, Rule, RuleSet};
use std::sync::Arc;
use tower_layer::Layer;

/// Client-facing response shape for blocked scanner probes.
///
/// Always empty-bodied with `content-length: 0`. Defaults to **404** so
/// probes learn nothing about which path was denylisted. Never embeds
/// [`shield_core::ShieldMatch`] details in the response.
#[derive(Debug, Clone)]
pub struct BlockedResponse {
    status: StatusCode,
}

impl Default for BlockedResponse {
    fn default() -> Self {
        BlockedResponse {
            status: StatusCode::NOT_FOUND,
        }
    }
}

impl BlockedResponse {
    /// Use a non-default status (e.g. 403) while keeping an empty body.
    pub fn with_status(status: StatusCode) -> Self {
        BlockedResponse { status }
    }

    /// HTTP status that will be returned on block.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Materialise the empty blocked response for the service's body type.
    pub fn build<B: Default>(&self) -> Response<B> {
        let mut resp = Response::new(B::default());
        *resp.status_mut() = self.status;
        resp.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("0"),
        );
        resp
    }
}

/// Observability hook invoked after a path is blocked, before the response is returned.
///
/// Arguments: match metadata, HTTP method, and the **decoded path only**.
/// Implementations must not log query strings, cookies, authorization
/// headers, bodies, or secrets discovered in the path.
pub type OnBlock =
    Arc<dyn Fn(&shield_core::ShieldMatch, &http::Method, &str) + Send + Sync + 'static>;

/// Fluent configuration for a [`ShieldLayer`] before rule compilation.
///
/// Defaults: built-in [`DEFAULT_RULES`][shield_core::DEFAULT_RULES], 404
/// blocked responses, no `on_block` callback.
///
/// # Example
///
/// ```rust
/// use shield_tower::ShieldLayer;
/// use shield_core::{Rule, RuleGroup, PathMatcher, DEFAULT_RULES};
///
/// let layer = ShieldLayer::builder()
///     .with_ruleset(
///         DEFAULT_RULES.get()
///             .push(Rule::deny(
///                 "custom.myapp_probe",
///                 RuleGroup::Custom("myapp".into()),
///                 "Block internal probe",
///                 PathMatcher::Exact("/internal/debug".into()),
///             ))
///     )
///     .build();
/// ```
pub struct ShieldBuilder {
    rules: BuilderRules,
    blocked_response: BlockedResponse,
    on_block: Option<OnBlock>,
}

enum BuilderRules {
    Builtin,
    Custom(RuleSet),
}

impl Default for ShieldBuilder {
    fn default() -> Self {
        ShieldBuilder {
            rules: BuilderRules::Builtin,
            blocked_response: BlockedResponse::default(),
            on_block: None,
        }
    }
}

impl ShieldBuilder {
    /// Replace the entire rule set (drops the previous builder rules).
    pub fn with_ruleset(mut self, rs: RuleSet) -> Self {
        self.rules = BuilderRules::Custom(rs);
        self
    }

    /// Append one rule onto the builder's current set.
    pub fn add_rule(mut self, rule: Rule) -> Self {
        self.rules = BuilderRules::Custom(match self.rules {
            BuilderRules::Builtin => shield_core::DEFAULT_RULES.get().push(rule),
            BuilderRules::Custom(ruleset) => ruleset.push(rule),
        });
        self
    }

    /// Override the empty blocked response (status code only today).
    pub fn with_blocked_response(mut self, r: BlockedResponse) -> Self {
        self.blocked_response = r;
        self
    }

    /// Register metrics/logging for blocked requests (server-side only).
    ///
    /// # Observability policy
    ///
    /// Receive only match metadata, method, and decoded path. Never log
    /// query strings, authorization headers, cookies, bodies, or secrets.
    pub fn on_block(
        mut self,
        f: impl Fn(&shield_core::ShieldMatch, &http::Method, &str) + Send + Sync + 'static,
    ) -> Self {
        self.on_block = Some(Arc::new(f));
        self
    }

    /// Compile rules and produce a shareable [`ShieldLayer`].
    ///
    /// # Panics
    ///
    /// Panics if compilation fails (typically an invalid regex). Prefer
    /// [`ShieldBuilder::try_build`] at process startup when rules come from
    /// external config.
    pub fn build(self) -> ShieldLayer {
        self.try_build().expect("failed to compile shield rule set")
    }

    /// Compile rules without panicking; returns [`CompileError`][shield_core::ruleset::CompileError].
    pub fn try_build(self) -> Result<ShieldLayer, shield_core::ruleset::CompileError> {
        let compiled = match self.rules {
            BuilderRules::Builtin => shield_core::DEFAULT_RULES.compiled(),
            BuilderRules::Custom(ruleset) => ruleset.compile()?,
        };
        Ok(ShieldLayer {
            inner: Arc::new(LayerInner {
                compiled,
                blocked_response: self.blocked_response,
                on_block: self.on_block,
            }),
        })
    }
}

/// Shared compiled state cloned cheaply into each [`ShieldService`].
pub(crate) struct LayerInner {
    pub(crate) compiled: CompiledRuleSet,
    pub(crate) blocked_response: BlockedResponse,
    pub(crate) on_block: Option<OnBlock>,
}

impl std::fmt::Debug for LayerInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayerInner")
            .field("compiled", &self.compiled)
            .field("blocked_response", &self.blocked_response)
            .field("on_block", &self.on_block.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

/// Tower [`Layer`] that evaluates the path denylist before the inner service.
///
/// # Defaults
///
/// [`ShieldLayer::default`] compiles the built-in rule set and returns empty
/// HTTP 404 responses for blocks.
///
/// # Placement
///
/// **Wrap the complete `axum::Router` with `layer(router)`.** Axum's
/// `Router::layer` runs middleware *after* route matching, so unrouted
/// probes would bypass the shield.
///
/// ```rust,no_run
/// use tower::Layer;
/// use shield_tower::ShieldLayer;
/// // let app = ShieldLayer::default().layer(router);
/// ```
///
/// The layer is `Clone` + `Send` + `Sync`; the compiled rules live behind
/// an `Arc` shared by every produced [`crate::ShieldService`].
#[derive(Debug, Clone)]
pub struct ShieldLayer {
    pub(crate) inner: Arc<LayerInner>,
}

impl Default for ShieldLayer {
    /// Built-in rules, 404 blocked responses, no observability callback.
    fn default() -> Self {
        ShieldBuilder::default().build()
    }
}

impl ShieldLayer {
    /// Start a [`ShieldBuilder`] (same defaults as [`ShieldLayer::default`]).
    pub fn builder() -> ShieldBuilder {
        ShieldBuilder::default()
    }
}

impl<S> Layer<S> for ShieldLayer {
    type Service = ShieldService<S>;

    fn layer(&self, inner_service: S) -> Self::Service {
        ShieldService::new(inner_service, Arc::clone(&self.inner))
    }
}
