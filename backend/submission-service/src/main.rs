// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::CorsLayer;

mod db;
mod handlers;
mod models;
mod queue;
mod storage;

use storage::s3_client::S3Client;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub s3_client: Arc<S3Client>,
    pub db_pool: PgPool,
    pub redis_client: redis::Client,
    pub metrics: shared::MetricsRegistry,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables before tracing so RUST_LOG/log level from
    // .env are honored.
    dotenvy::dotenv().ok();

    // Initialize tracing — JSON format with thread ids + line numbers so logs
    // aggregate cleanly across the fleet (matches user/consensus/payment/etc).
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .json()
        .init();

    tracing::info!("Starting Submission Service...");

    // Initialize database connection with proper error handling
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;

    tracing::info!("Connecting to database...");
    let db_pool = match PgPool::connect(&database_url).await {
        Ok(pool) => {
            tracing::info!("Database connection established");
            pool
        }
        Err(e) => {
            tracing::error!("Failed to connect to database: {}", e);
            return Err(anyhow::anyhow!("Database connection failed: {e}").into());
        }
    };

    // Run service-local migrations on startup. The `submissions` table lives
    // in ./migrations and is owned by this service. `sqlx::migrate!` embeds the
    // migration SQL into the binary at compile time, so we run it
    // unconditionally — the migrations directory is not shipped in the runtime
    // image, and gating on its runtime presence would silently skip schema
    // creation, leaving every real request to fail with `relation "submissions"
    // does not exist`. A migration failure is therefore fatal.
    tracing::info!("Running database migrations...");
    if let Err(e) = sqlx::migrate!("./migrations").run(&db_pool).await {
        tracing::error!("Database migration failed: {}", e);
        return Err(anyhow::anyhow!("Database migration failed: {e}").into());
    }
    tracing::info!("Database migrations completed");

    // Initialize Redis client with error handling
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    tracing::info!("Connecting to Redis...");
    let redis_client = match redis::Client::open(redis_url) {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to create Redis client: {}", e);
            return Err(anyhow::anyhow!("Redis client creation failed: {e}").into());
        }
    };

    // Test Redis connection
    match redis_client.get_multiplexed_async_connection().await {
        Ok(_) => tracing::info!("Redis connection established"),
        Err(e) => {
            tracing::error!("Failed to connect to Redis: {}", e);
            return Err(anyhow::anyhow!("Redis connection failed: {e}").into());
        }
    }

    // Initialize S3 client
    let s3_client = S3Client::new().await?;
    tracing::info!("S3 client initialized successfully");

    // Create app state
    let state = AppState {
        s3_client: Arc::new(s3_client),
        db_pool,
        redis_client,
        metrics: shared::MetricsRegistry::new("submission-service", env!("CARGO_PKG_VERSION")),
    };

    // Build CORS layer - allow specific origins from environment
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

    // Build our application with routes. Metrics middleware updates
    // request/error counters exposed by `/metrics`.
    let prom_registry = state.metrics.clone();
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
        .route("/submit/file", post(handlers::file_upload::submit_file))
        .route("/submit/url", post(handlers::url_submission::submit_url))
        .layer(axum::middleware::from_fn(move |req, next| {
            let r = prom_registry.clone();
            async move { shared::metrics_mw::track_with(r, req, next).await }
        }))
        .layer(cors)
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .with_state(state);

    // Get port from environment or use default
    let port = std::env::var("SUBMISSION_SERVICE_PORT")
        .unwrap_or_else(|_| "8085".to_string())
        .parse::<u16>()?;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Submission Service listening on {}", addr);

    // Run the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Submission Service shut down gracefully");
    Ok(())
}

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
            Err(e) => tracing::warn!("failed to install SIGTERM handler: {e}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    tracing::info!("Shutdown signal received, draining connections...");
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "submission-service",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now(),
    }))
}

/// Liveness: process is up. Always 200 unless the process is dead.
async fn liveness_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "alive": true }))
}

/// Readiness: can we serve traffic? Checks DB + Redis connectivity.
/// Returns 503 if a dependency is unreachable so orchestrators stop routing
/// traffic to this pod without killing it.
async fn readiness_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let db_ok = sqlx::query("SELECT 1")
        .execute(&state.db_pool)
        .await
        .is_ok();

    let redis_ok = state
        .redis_client
        .get_multiplexed_async_connection()
        .await
        .is_ok();

    if db_ok && redis_ok {
        Ok(Json(serde_json::json!({
            "ready": true,
            "database": "up",
            "redis": "up",
        })))
    } else {
        tracing::warn!(db_ok, redis_ok, "readiness check failed");
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Prometheus text-format metrics. Mirrors the other services so the single
/// `prometheus.yml` scrape config works without per-service path overrides.
async fn metrics_handler(
    State(state): State<AppState>,
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
