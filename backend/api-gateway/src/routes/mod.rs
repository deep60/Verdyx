pub mod v1;

use axum::{extract::State, http::header, routing::get, Json, Router};

use crate::AppState;

/// Create the main router with API v1, the root-level /ws proxy, and the
/// platform-uniform `/health`, `/ready`, `/metrics` endpoints used by
/// `docker-compose` healthchecks and the Prometheus scrape config in
/// `infrastructure/docker/production/prometheus.yml`.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // WebSocket proxy — lives at the root so the frontend can connect to /ws
        .route("/ws", get(crate::handlers::websocket::ws_proxy))
        // Root observability endpoints — kept consistent with every other
        // service so a single Prometheus job (metrics_path: /metrics) and a
        // single compose healthcheck pattern (`curl /health`) work fleet-wide.
        .route("/health", get(root_health))
        .route("/ready", get(root_ready))
        .route("/metrics", get(root_metrics))
        .with_state(state.clone())
        .merge(taxii_routes(state.clone()))
        .nest("/scim/v2", scim_routes(state.clone()))
        .nest("/api/v1", v1::create_routes(state.clone()))
        .nest("/api", v1::create_routes(state))
}

/// TAXII 2.1 at the root, where TAXII clients look for it. Discovery and the
/// API root say nothing about anyone's data; collections need an API key.
fn taxii_routes(state: AppState) -> Router {
    use crate::handlers::threat_feed as t;
    let collections = Router::new()
        .route("/taxii2/api/collections/", get(t::collections))
        .route("/taxii2/api/collections/{id}/", get(t::collection))
        .route("/taxii2/api/collections/{id}/objects/", get(t::objects))
        .route("/taxii2/api/collections/{id}/manifest/", get(t::manifest))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::auth::auth_middleware,
        ));
    Router::new()
        .route("/taxii2/", get(t::discovery))
        .route("/taxii2", get(t::discovery))
        .route("/taxii2/api/", get(t::api_root))
        .merge(collections)
        .with_state(state)
}

/// SCIM 2.0 provisioning. Each request carries the team's provisioning
/// token, checked by the handlers, not a session.
fn scim_routes(state: AppState) -> Router {
    use crate::handlers::scim as s;
    Router::new()
        .route("/Users", get(s::list_users).post(s::create_user))
        .route(
            "/Users/{id}",
            get(s::get_user)
                .put(s::replace_user)
                .patch(s::patch_user)
                .delete(s::delete_user),
        )
        .route("/Groups", get(s::list_groups))
        .route("/ServiceProviderConfig", get(s::service_provider_config))
        .route("/ResourceTypes", get(s::resource_types))
        .route("/Schemas", get(s::schemas))
        .fallback(s::not_supported)
        .with_state(state)
}

/// Liveness — always 200 when the process can answer HTTP.
async fn root_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "api-gateway",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Readiness — returns 503 if a critical dependency is down so an
/// orchestrator stops routing traffic without killing the pod.
async fn root_ready(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let db_ok = state.db.health_check().await.is_ok();
    let redis_ok = state.redis.health_check().await.unwrap_or(false);
    if db_ok && redis_ok {
        Ok(Json(serde_json::json!({
            "ready": true,
            "database": "up",
            "redis": "up",
        })))
    } else {
        tracing::warn!(db_ok, redis_ok, "api-gateway readiness check failed");
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Prometheus text exposition format, sharing the `verdyx_*` schema with
/// every other service.
async fn root_metrics(
    State(state): State<AppState>,
) -> (
    axum::http::StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    String,
) {
    (
        axum::http::StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.prom_metrics.render_prometheus(),
    )
}
