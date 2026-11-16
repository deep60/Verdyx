// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

mod analytics;
mod config;
mod handlers;
mod models;
mod scoring;
mod services;
mod workers;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};

use crate::config::Config;
use crate::services::reputation_service::ReputationService;

/// Waits for SIGINT or SIGTERM so the server can drain in-flight requests
/// before the process exits (Docker/Kubernetes send SIGTERM on stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => warn!("failed to install SIGTERM handler: {e}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    info!("Shutdown signal received, draining connections...");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize tracing
    let _error_reporting = shared::observability::error_reporting::init(
        "reputation-service",
        env!("CARGO_PKG_VERSION"),
    );
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        tracing_subscriber::fmt()
            .with_target(false)
            .with_thread_ids(true)
            .with_line_number(true)
            .json()
            .finish()
            .with(shared::observability::error_reporting::layer())
            .init();
    }

    info!("Starting Reputation Service...");

    // Load configuration
    let config = Config::from_env()?;
    info!("Configuration loaded successfully");

    // Initialize database connection pool
    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;
    info!("Database connection pool established");

    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await?;
    info!("Database migrations completed");

    // Initialize Redis client
    let redis_client = redis::Client::open(config.redis.url.clone())?;
    let redis_conn = redis_client.get_connection_manager().await?;
    info!("Redis connection established");

    // Initialize reputation service
    let reputation_service = Arc::new(
        ReputationService::new(config.clone(), db_pool.clone(), redis_conn.clone()).await?,
    );
    info!("Reputation service initialized");

    // Start background workers
    let service_clone = reputation_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::reputation_calculator::start(service_clone).await {
            warn!("Reputation calculator error: {}", e);
        }
    });

    let service_clone = reputation_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::decay_processor::start(service_clone).await {
            warn!("Decay processor error: {}", e);
        }
    });

    let service_clone = reputation_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::leaderboard_updater::start(service_clone).await {
            warn!("Leaderboard updater error: {}", e);
        }
    });

    info!("Background workers started");

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        db_pool,
        redis_conn,
        reputation_service,
        metrics: shared::MetricsRegistry::new("reputation-service", env!("CARGO_PKG_VERSION")),
    });

    // Configure CORS - allow specific origins from environment
    let allowed_origins: Vec<_> = std::env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000,http://localhost:5173".to_string())
        .split(',')
        .filter_map(|origin| origin.trim().parse::<axum::http::HeaderValue>().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::PATCH,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .allow_credentials(true);

    // Build router
    let app = Router::new()
        .route("/health", get(handlers::health::health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
        // Reputation endpoints
        .route(
            "/api/v1/reputation/user/{user_id}",
            get(handlers::reputation::get_user_reputation),
        )
        .route(
            "/api/v1/reputation/user/{user_id}/history",
            get(handlers::reputation::get_reputation_history),
        )
        .route(
            "/api/v1/reputation/user/{user_id}/update",
            post(handlers::reputation::update_reputation),
        )
        .route(
            "/api/v1/reputation/engine/{engine_id}",
            get(handlers::reputation::get_engine_reputation),
        )
        .route(
            "/api/v1/reputation/leaderboard",
            get(handlers::reputation::get_leaderboard),
        )
        .route(
            "/api/v1/reputation/badges/{user_id}",
            get(handlers::reputation::get_user_badges),
        )
        // Analytics endpoints
        .route(
            "/api/v1/analytics/reputation/trends",
            get(handlers::analytics::get_reputation_trends),
        )
        .route(
            "/api/v1/analytics/reputation/distribution",
            get(handlers::analytics::get_score_distribution),
        )
        .route(
            "/api/v1/analytics/accuracy/stats",
            get(handlers::analytics::get_accuracy_stats),
        )
        // Admin endpoints
        .route(
            "/api/v1/admin/reputation/recalculate/{user_id}",
            post(handlers::admin::recalculate_reputation),
        )
        .route(
            "/api/v1/admin/reputation/reset/{user_id}",
            post(handlers::admin::reset_reputation),
        )
        .route(
            "/api/v1/admin/badges/award",
            post(handlers::admin::award_badge),
        )
        .layer(axum::middleware::from_fn({
            let r = app_state.metrics.clone();
            move |req, next| {
                let r = r.clone();
                async move { shared::metrics_mw::track_with(r, req, next).await }
            }
        }))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .with_state(app_state);

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Reputation Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Reputation Service shut down gracefully");
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_conn: redis::aio::ConnectionManager,
    pub reputation_service: Arc<ReputationService>,
    pub metrics: shared::MetricsRegistry,
}

/// Liveness: process is up. Always 200 unless the process is dead.
async fn liveness_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "alive": true }))
}

/// Readiness: checks DB connectivity. 503 when not ready.
async fn readiness_check(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let db_ok = sqlx::query("SELECT 1")
        .execute(&state.db_pool)
        .await
        .is_ok();
    if db_ok {
        Ok(axum::Json(
            serde_json::json!({ "ready": true, "database": "up" }),
        ))
    } else {
        warn!("readiness check failed: database unreachable");
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Prometheus text-format metrics.
async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> (
    axum::http::StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    String,
) {
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.render_prometheus(),
    )
}
