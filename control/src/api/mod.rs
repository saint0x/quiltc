pub mod containers;
pub mod nodes;

use axum::{
    body::Body,
    http::StatusCode,
    routing::{delete, get, patch, post},
    Json, Router,
};
use std::sync::Arc;

use crate::types::HealthResponse;
use nodes::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        // Health check
        .route("/health", get(health))
        // Node management
        .route("/api/nodes/register", post(nodes::register_node))
        .route("/api/nodes/:id/heartbeat", post(nodes::heartbeat))
        .route("/api/nodes/:id/deregister", post(nodes::deregister_node))
        .route("/api/nodes", get(nodes::list_nodes));

    // Container + runtime API surface:
    // If a Quilt backend is configured, these are proxied to Quilt's HTTP API using the configured auth.
    // Otherwise they are handled locally (legacy DB-backed behavior used by tests/dev).
    if state.quilt.is_some() {
        use axum::routing::any;

        router = router
            // Containers
            .route("/api/containers", any(quilt_proxy))
            .route("/api/containers/*path", any(quilt_proxy))
            // Snapshots
            .route("/api/snapshots", any(quilt_proxy))
            .route("/api/snapshots/*path", any(quilt_proxy))
            // Operations
            .route("/api/operations", any(quilt_proxy))
            .route("/api/operations/*path", any(quilt_proxy))
            // Auth
            .route("/api/auth/*path", any(quilt_proxy))
            // Volumes
            .route("/api/volumes", any(quilt_proxy))
            .route("/api/volumes/*path", any(quilt_proxy))
            // API keys
            .route("/api/api-keys", any(quilt_proxy))
            .route("/api/api-keys/*path", any(quilt_proxy))
            // Events (SSE)
            .route("/api/events", any(quilt_proxy));
    } else {
        router = router
            .route("/api/containers", post(containers::create_container))
            .route("/api/containers", get(containers::list_containers))
            .route("/api/containers/:id", get(containers::get_container))
            .route("/api/containers/:id", delete(containers::delete_container))
            .route(
                "/api/containers/:id/ip",
                patch(containers::update_container_ip),
            );
    }

    router.with_state(state)
}

/// GET /health - Health check endpoint
async fn health() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok".to_string(),
        }),
    )
}

async fn quilt_proxy(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: axum::http::Request<Body>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let quilt = state.quilt.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Quilt backend not configured".to_string(),
    ))?;

    quilt
        .proxy(req)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))
}
