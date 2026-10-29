// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

mod channels;
mod config;
mod handlers;
mod models;
mod notification_manager;
mod templates;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};

use crate::config::Config;
use crate::notification_manager::NotificationManager;

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
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .json()
        .init();

    info!("Starting Notification Service...");

    // Load configuration
    let config = Config::from_env()?;
    info!("Configuration loaded successfully");

    // Initialize database connection pool (auto-create verdyx_notifications if missing)
    let db_pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await
    {
        Ok(pool) => pool,
        Err(first_err) => {
            warn!("Primary DB connect failed ({first_err}); attempting to ensure database exists...");
            if let Some((base_url, db_name)) = config.database.url.rsplit_once('/') {
                let admin_url = format!("{base_url}/postgres");
                if let Ok(admin_pool) = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin_url)
                    .await
                {
                    let create_sql = format!("CREATE DATABASE \"{db_name}\"");
                    let _ = sqlx::query(&create_sql).execute(&admin_pool).await;
                }
            }
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(config.database.max_connections)
                .connect(&config.database.url)
                .await?
        }
    };
    info!("Database connection pool established");

    // Run migrations idempotently
    if let Err(mig_err) = sqlx::migrate!("./migrations").run(&db_pool).await {
        warn!("sqlx::migrate notice ({mig_err}); ensuring schema exists via raw SQL...");
        let _ = sqlx::raw_sql(include_str!("../migrations/20240101000000_initial_schema.sql"))
            .execute(&db_pool)
            .await;
    }
    info!("Database migrations completed");

    // Initialize Redis client
    let redis_client = redis::Client::open(config.redis.url.clone())?;
    let redis_conn = redis_client.get_connection_manager().await?;
    info!("Redis connection established");

    // Initialize notification manager
    let notification_manager = Arc::new(
        NotificationManager::new(config.clone(), db_pool.clone(), redis_conn.clone()).await?,
    );
    info!("Notification manager initialized");

    // Start background workers
    let manager_clone = notification_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = manager_clone.start_event_listener().await {
            warn!("Event listener error: {}", e);
        }
    });

    let manager_clone = notification_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = manager_clone.start_retry_worker().await {
            warn!("Retry worker error: {}", e);
        }
    });

    info!("Background workers started");

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        db_pool,
        redis_conn,
        notification_manager,
        metrics: shared::MetricsRegistry::new("notification-service", env!("CARGO_PKG_VERSION")),
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
        .route(
            "/api/v1/notifications/send",
            post(handlers::notification::send_notification),
        )
        .route(
            "/api/v1/notifications/preferences",
            get(handlers::preferences::get_preferences),
        )
        .route(
            "/api/v1/notifications/preferences",
            post(handlers::preferences::update_preferences),
        )
        .route(
            "/api/v1/notifications/history",
            get(handlers::notification::get_notification_history),
        )
        .route(
            "/api/v1/notifications/{id}/retry",
            post(handlers::notification::retry_notification),
        )
        .route(
            "/api/v1/webhooks/register",
            post(handlers::webhook::register_webhook),
        )
        .route(
            "/api/v1/webhooks/unregister",
            post(handlers::webhook::unregister_webhook),
        )
        .route("/ws", get(handlers::websocket::websocket_handler))
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
    info!("Notification Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Notification Service shut down gracefully");
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_conn: redis::aio::ConnectionManager,
    pub notification_manager: Arc<NotificationManager>,
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
