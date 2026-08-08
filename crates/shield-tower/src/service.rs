//! Per-request Tower [`Service`] that enforces the compiled path denylist.
//!
//! Produced by [`crate::ShieldLayer`]; holds the inner service plus shared
//! compiled rules and block-response configuration.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response};
use tower_service::Service;
use towershield_core::InspectionPath;

use crate::layer::LayerInner;

/// Tower [`Service`] that evaluates path rules, then either blocks or forwards.
///
/// # Contracts
///
/// - **Allow**: the original request is passed to the inner service with no
///   mutation of method, URI, headers, or body.
/// - **Block**: the inner service is never polled; a configured empty
///   response is returned. Optional [`crate::OnBlock`] and `tracing` run first.
/// - Only `uri.path()` is inspected (query string ignored).
#[derive(Clone, Debug)]
pub struct ShieldService<S> {
    inner: S,
    state: Arc<LayerInner>,
}

impl<S> ShieldService<S> {
    pub(crate) fn new(inner: S, state: Arc<LayerInner>) -> Self {
        ShieldService { inner, state }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ShieldService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Default + Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = ShieldFuture<S::Future, ResBody, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let ip = InspectionPath::new(req.uri().path());
        let decision = self.state.compiled.evaluate(&ip);

        match decision {
            towershield_core::ShieldDecision::Allow => {
                // End the URI borrow before forwarding the request. No path
                // copy is needed for the common allow case.
                drop(ip);
                let fut = self.inner.call(req);
                ShieldFuture::Inner(fut)
            }
            towershield_core::ShieldDecision::Block(ref m) => {
                // Server-side only: match metadata + decoded path, never the raw request.
                if let Some(cb) = &self.state.on_block {
                    cb(m, req.method(), ip.decoded.as_ref());
                }

                #[cfg(feature = "tracing")]
                {
                    tracing::debug!(
                        rule_id = %m.rule_id,
                        group = %m.group,
                        match_kind = ?m.match_kind,
                        method = %req.method(),
                        path = %ip.decoded,
                        builtin = m.is_builtin,
                        "shield blocked request"
                    );
                }

                let response = self.state.blocked_response.build::<ResBody>();
                ShieldFuture::Blocked(Some(response))
            }
        }
    }
}

/// Future returned by [`ShieldService::call`].
///
/// Either drives the inner service (`Inner`) or yields a ready blocked
/// response once (`Blocked`). Polling `Blocked` after the response is taken
/// panics — the same single-use contract as other ready futures.
#[pin_project::pin_project(project = ShieldFutureProj)]
pub enum ShieldFuture<F, B, E> {
    /// Request allowed; poll the inner service future.
    Inner(#[pin] F),
    /// Request blocked; ready response stored until first poll.
    Blocked(Option<Response<B>>),
    /// Holds `E` in the type system without storing a value.
    #[allow(dead_code)]
    _Phantom(std::marker::PhantomData<E>),
}

impl<F, B, E> Future for ShieldFuture<F, B, E>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ShieldFutureProj::Inner(f) => f.poll(cx),
            ShieldFutureProj::Blocked(opt) => {
                Poll::Ready(Ok(opt.take().expect("ShieldFuture::Blocked polled twice")))
            }
            ShieldFutureProj::_Phantom(_) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{Request, Response, StatusCode};
    use tower::ServiceExt;
    use tower_service::Service;

    use crate::ShieldLayer;
    use tower::Layer;
    use towershield_core::DEFAULT_RULES;

    fn ok_service() -> impl Service<
        Request<http_body_util::Empty<bytes::Bytes>>,
        Response = Response<http_body_util::Empty<bytes::Bytes>>,
        Error = std::convert::Infallible,
        Future: Send + 'static,
    > {
        tower::service_fn(|_req: Request<http_body_util::Empty<bytes::Bytes>>| async {
            Ok::<_, std::convert::Infallible>(Response::new(
                http_body_util::Empty::<bytes::Bytes>::new(),
            ))
        })
    }

    #[tokio::test]
    async fn blocked_path_returns_404() {
        let layer = ShieldLayer::default();
        let svc = layer.layer(ok_service());
        let req = Request::get("/.env")
            .body(http_body_util::Empty::new())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn allowed_path_reaches_inner() {
        let layer = ShieldLayer::default();
        let svc = layer.layer(ok_service());
        let req = Request::get("/api/v1/users")
            .body(http_body_util::Empty::new())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn original_request_forwarded_unchanged() {
        use std::sync::{Arc, Mutex};

        let captured_path: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let cap = Arc::clone(&captured_path);

        let svc = tower::service_fn(move |req: Request<http_body_util::Empty<bytes::Bytes>>| {
            let cap = Arc::clone(&cap);
            async move {
                *cap.lock().unwrap() = Some(req.uri().path().to_owned());
                Ok::<_, std::convert::Infallible>(Response::new(http_body_util::Empty::<
                    bytes::Bytes,
                >::new()))
            }
        });

        let layer = ShieldLayer::default();
        let wrapped = layer.layer(svc);

        let req = Request::get("/safe/path?foo=bar")
            .body(http_body_util::Empty::new())
            .unwrap();
        wrapped.oneshot(req).await.unwrap();
        assert_eq!(captured_path.lock().unwrap().as_deref(), Some("/safe/path"));
    }

    #[tokio::test]
    async fn inner_not_called_when_blocked() {
        use std::sync::{Arc, Mutex};

        let called = Arc::new(Mutex::new(false));
        let c = Arc::clone(&called);

        let svc = tower::service_fn(move |_: Request<http_body_util::Empty<bytes::Bytes>>| {
            let c = Arc::clone(&c);
            async move {
                *c.lock().unwrap() = true;
                Ok::<_, std::convert::Infallible>(Response::new(http_body_util::Empty::<
                    bytes::Bytes,
                >::new()))
            }
        });

        let layer = ShieldLayer::default();
        let wrapped = layer.layer(svc);

        let req = Request::get("/.env")
            .body(http_body_util::Empty::new())
            .unwrap();
        let resp = wrapped.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            !*called.lock().unwrap(),
            "inner service should not be called"
        );
    }

    #[tokio::test]
    async fn on_block_callback_invoked() {
        use std::sync::{Arc, Mutex};
        use towershield_core::{PathMatcher, Rule, RuleGroup};

        let saw_block = Arc::new(Mutex::new(false));
        let s = Arc::clone(&saw_block);

        let layer = ShieldLayer::builder()
            .with_ruleset(DEFAULT_RULES.get().push(Rule::deny(
                "test.block",
                RuleGroup::Secrets,
                "test",
                PathMatcher::Exact("/secret".into()),
            )))
            .on_block(move |_m, _method, _path| {
                *s.lock().unwrap() = true;
            })
            .build();

        let svc = layer.layer(ok_service());
        let req = Request::get("/secret")
            .body(http_body_util::Empty::new())
            .unwrap();
        svc.oneshot(req).await.unwrap();
        assert!(*saw_block.lock().unwrap());
    }

    #[tokio::test]
    async fn custom_status_code() {
        use crate::layer::BlockedResponse;
        use http::StatusCode;

        let layer = ShieldLayer::builder()
            .with_blocked_response(BlockedResponse::with_status(StatusCode::FORBIDDEN))
            .build();
        let svc = layer.layer(ok_service());
        let req = Request::get("/.env")
            .body(http_body_util::Empty::new())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // Compile-time Send + Sync bounds check.
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn shield_layer_is_send_sync() {
        assert_send_sync::<ShieldLayer>();
    }
}
