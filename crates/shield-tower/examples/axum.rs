//! Axum integration example.
//!
//! This example demonstrates two usage patterns:
//!
//! 1. **Pre-router wrapping** (preferred): wraps the entire `axum::Router`
//!    so the shield evaluates requests *before* Axum routing. Blocked
//!    paths never reach route matching or application handlers.
//!
//! 2. **`Router::layer` wrapping** (limited): applies the shield as an
//!    axum router layer. Because Axum applies `Router::layer` middleware
//!    after route matching, requests that do *not* match a route (including
//!    scanner probes) are **not** intercepted by the shield. Only use this
//!    if you exclusively want to protect matched routes.
//!
//! Run with:
//! ```not_rust
//! cargo run --example axum --package shield-tower
//! ```

use axum::{routing::get, Router};
use http::StatusCode;
use shield_tower::ShieldLayer;
use tower::Layer;
use tower::ServiceExt;

#[tokio::main]
async fn main() {
    // 1. Build your application router.
    let router: Router = Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/api/v1/users", get(|| async { "[]" }));

    // 2. ── Preferred: wrap the COMPLETE Router ───────────────────────────
    //
    //    ShieldLayer::default().layer(router) produces a Tower service
    //    that evaluates every incoming request before Axum routing starts.
    //
    //    `/.env`, `/.git/config`, `/wp-login.php`, etc. are rejected here
    //    and NEVER reach the Axum router or application handlers.
    let app = ShieldLayer::default().layer(router.clone());

    // Demonstrate that scanner probes are blocked:
    let blocked = app
        .clone()
        .oneshot(
            http::Request::get("/.env")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    println!("/.env status: {} (expected 404)", blocked.status());
    assert_eq!(blocked.status(), StatusCode::NOT_FOUND);

    // Normal paths are forwarded unchanged:
    let allowed = app
        .oneshot(
            http::Request::get("/api/v1/users")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    println!("/api/v1/users status: {} (expected 200)", allowed.status());
    assert_eq!(allowed.status(), StatusCode::OK);

    // 3. ── To serve with axum::serve ─────────────────────────────────────
    //
    //    axum::serve expects a type implementing Service<IncomingStream>.
    //    Because IncomingStream is Axum-internal, the most practical pattern
    //    for wrapping at the HTTP/1.1 + HTTP/2 level is to apply the shield
    //    via axum's Router::layer (which runs after routing for matched
    //    routes) combined with a fallback that also runs the shield.
    //
    //    Example that serves all traffic including fallbacks:
    //
    //    let protected = router
    //        .fallback(|| async { StatusCode::NOT_FOUND })
    //        .layer(ShieldLayer::default());
    //    axum::serve(listener, protected).await.unwrap();
    //
    //    For full pre-routing interception at the TCP/HTTP level, use
    //    hyper_util directly (not shown here to avoid the extra dependency).

    println!("All assertions passed.");
}
