//! [`ShieldLayer`] – a Tower [`Layer`][tower_layer::Layer] that applies the
//! path-denylist middleware.

use crate::service::ShieldService;
use http::{Response, StatusCode};
use shield_core::{CompiledRuleSet, Rule, RuleSet};
use std::sync::Arc;
use tower_layer::Layer;

/// Configures the response returned for blocked paths.
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
    /// Create with the given HTTP status code.
    pub fn with_status(status: StatusCode) -> Self {
        BlockedResponse { status }
    }

    /// The configured HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Build the HTTP response for a blocked request.
    ///
    /// The body is always empty and the response contains no information
    /// about which rule matched.
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

/// Optional callback invoked when a request is blocked.
///
/// The callback receives the [`ShieldMatch`][shield_core::ShieldMatch] describing
/// why the request was blocked along with the HTTP method and a safe path
/// representation (never the raw query string, authorization headers, cookies,
/// or body).
pub type OnBlock =
    Arc<dyn Fn(&shield_core::ShieldMatch, &http::Method, &str) + Send + Sync + 'static>;

/// Builder for [`ShieldLayer`].
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
    ruleset: RuleSet,
    blocked_response: BlockedResponse,
    on_block: Option<OnBlock>,
}

impl Default for ShieldBuilder {
    fn default() -> Self {
        ShieldBuilder {
            ruleset: shield_core::DEFAULT_RULES.get(),
            blocked_response: BlockedResponse::default(),
            on_block: None,
        }
    }
}

impl ShieldBuilder {
    /// Replace the entire rule set.
    pub fn with_ruleset(mut self, rs: RuleSet) -> Self {
        self.ruleset = rs;
        self
    }

    /// Append a single rule to the current rule set.
    pub fn add_rule(mut self, rule: Rule) -> Self {
        self.ruleset = self.ruleset.push(rule);
        self
    }

    /// Set the HTTP response returned for blocked paths.
    pub fn with_blocked_response(mut self, r: BlockedResponse) -> Self {
        self.blocked_response = r;
        self
    }

    /// Register a callback invoked when a request is blocked.
    ///
    /// The callback receives:
    /// - The [`ShieldMatch`][shield_core::ShieldMatch] (rule ID, group, kind).
    /// - The HTTP method.
    /// - A safe path representation (decoded URI path, no query string).
    ///
    /// # Observability policy
    ///
    /// The callback must never log query strings, authorization headers,
    /// cookies, request bodies, or secrets discovered in the path.
    pub fn on_block(
        mut self,
        f: impl Fn(&shield_core::ShieldMatch, &http::Method, &str) + Send + Sync + 'static,
    ) -> Self {
        self.on_block = Some(Arc::new(f));
        self
    }

    /// Compile the rule set and produce the final [`ShieldLayer`].
    ///
    /// # Panics
    ///
    /// Panics if any regex pattern is invalid. Use
    /// [`ShieldBuilder::try_build`] to handle errors.
    pub fn build(self) -> ShieldLayer {
        self.try_build().expect("failed to compile shield rule set")
    }

    /// Compile the rule set and produce the final [`ShieldLayer`].
    pub fn try_build(self) -> Result<ShieldLayer, shield_core::ruleset::CompileError> {
        let compiled = self.ruleset.compile()?;
        Ok(ShieldLayer {
            inner: Arc::new(LayerInner {
                compiled,
                blocked_response: self.blocked_response,
                on_block: self.on_block,
            }),
        })
    }
}

/// Inner shared state for [`ShieldLayer`] and [`ShieldService`].
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

/// Tower [`Layer`] that rejects HTTP requests matching the configured deny
/// rules.
///
/// # Default configuration
///
/// `ShieldLayer::default()` uses the conservative built-in rule set with
/// HTTP 404 responses for blocked paths.
///
/// # Placement
///
/// **Wrap the complete `axum::Router` using `Layer::layer(router)`.**
///
/// Axum's `Router::layer` runs middleware *after* route matching, so
/// un-routed requests (404s, fallback handlers) would bypass the shield.
/// Wrapping the whole router ensures the shield evaluates every incoming
/// request.
///
/// ```rust,no_run
/// use tower::Layer;
/// use shield_tower::ShieldLayer;
/// // let router: axum::Router = build_router();
/// // let app = ShieldLayer::default().layer(router);
/// ```
#[derive(Debug, Clone)]
pub struct ShieldLayer {
    pub(crate) inner: Arc<LayerInner>,
}

impl Default for ShieldLayer {
    /// Create a [`ShieldLayer`] using the conservative built-in rule set.
    fn default() -> Self {
        ShieldBuilder::default().build()
    }
}

impl ShieldLayer {
    /// Return a [`ShieldBuilder`] for configuring the layer.
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
