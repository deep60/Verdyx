// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

mod aggregation;
mod commitment;
mod config;
mod handlers;
mod models;
mod services;
mod validators;
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
use crate::services::consensus_service::ConsensusService;

/// Waits for either SIGINT (Ctrl+C) or SIGTERM (sent by Docker/Kubernetes on
/// stop/rollout) and resolves so the server can drain in-flight requests.
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
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .json()
        .init();

    info!("Starting Consensus Service...");

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

    // Initialize consensus service
    let consensus_service =
        Arc::new(ConsensusService::new(config.clone(), db_pool.clone(), redis_conn.clone()).await?);
    info!("Consensus service initialized");

    // Start background workers
    let service_clone = consensus_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::consensus_processor::start(service_clone).await {
            warn!("Consensus processor error: {}", e);
        }
    });

    let service_clone = consensus_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::dispute_resolver::start(service_clone).await {
            warn!("Dispute resolver error: {}", e);
        }
    });

    let service_clone = consensus_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::regrader::start(service_clone).await {
            warn!("Regrader error: {}", e);
        }
    });

    info!("Background workers started");

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        db_pool,
        redis_conn,
        consensus_service,
        metrics: shared::MetricsRegistry::new("consensus-service", env!("CARGO_PKG_VERSION")),
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
        // Consensus endpoints
        .route(
            "/api/v1/consensus/bounty/{bounty_id}",
            get(handlers::consensus::get_bounty_consensus),
        )
        .route(
            "/api/v1/consensus/bounty/{bounty_id}/calculate",
            post(handlers::consensus::calculate_consensus),
        )
        .route(
            "/api/v1/consensus/bounty/{bounty_id}/vote",
            post(handlers::consensus::record_vote),
        )
        .route(
            "/api/v1/consensus/submission/{submission_id}",
            get(handlers::consensus::get_submission_consensus),
        )
        .route(
            "/api/v1/consensus/stats/{bounty_id}",
            get(handlers::consensus::get_consensus_stats),
        )
        // Commit-reveal voting: hide votes until the window shuts, so a late
        // voter cannot read the tally and copy whoever is ahead.
        .route(
            "/api/v1/voting/bounty/{bounty_id}/phase",
            get(handlers::voting::get_phase),
        )
        .route(
            "/api/v1/voting/bounty/{bounty_id}/commit",
            post(handlers::voting::commit_vote),
        )
        .route(
            "/api/v1/voting/bounty/{bounty_id}/reveal",
            post(handlers::voting::reveal_vote),
        )
        // Grading endpoints -- what the crowd got wrong, once we know better
        .route(
            "/api/v1/grades/{bounty_id}",
            get(handlers::grading::get_grade).post(handlers::grading::submit_grade),
        )
        .route("/api/v1/grading/stats", get(handlers::grading::get_stats))
        // Dispute endpoints
        .route(
            "/api/v1/disputes/create",
            post(handlers::dispute::create_dispute),
        )
        .route(
            "/api/v1/disputes/{dispute_id}",
            get(handlers::dispute::get_dispute),
        )
        .route(
            "/api/v1/disputes/{dispute_id}/resolve",
            post(handlers::dispute::resolve_dispute),
        )
        .route(
            "/api/v1/disputes/bounty/{bounty_id}",
            get(handlers::dispute::get_bounty_disputes),
        )
        // Validation endpoints
        .route(
            "/api/v1/validation/submission/{submission_id}",
            post(handlers::validation::validate_submission),
        )
        .route(
            "/api/v1/validation/batch",
            post(handlers::validation::batch_validate),
        )
        // Admin endpoints
        .route(
            "/api/v1/admin/consensus/recalculate/{bounty_id}",
            post(handlers::admin::recalculate_consensus),
        )
        .route(
            "/api/v1/admin/consensus/override/{bounty_id}",
            post(handlers::admin::override_consensus),
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
    info!("Consensus Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Consensus Service shut down gracefully");
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_conn: redis::aio::ConnectionManager,
    pub consensus_service: Arc<ConsensusService>,
    pub metrics: shared::MetricsRegistry,
}

/// Liveness: process is up. Always 200 unless the process is dead.
async fn liveness_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "alive": true }))
}

/// Readiness: checks DB connectivity. 503 when not ready so orchestrators
/// stop routing traffic without killing the pod.
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
