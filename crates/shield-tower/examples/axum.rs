//! Axum placement example for the path-denylist middleware.
//!
//! Preferred pattern: wrap the **entire** `Router` with
//! `ShieldLayer::default().layer(router)` so every request is evaluated
//! before Axum route matching. `Router::layer(ShieldLayer…)` is weaker:
//! unmatched probes never enter the layer.
//!
//! Run: `cargo run --example axum --package tower-http-shield`

use axum::{Router, routing::get};
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
