// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

mod blockchain;
mod config;
mod handlers;
mod models;
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
use crate::services::payment_service::PaymentService;

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
    let _error_reporting =
        shared::observability::error_reporting::init("payment-service", env!("CARGO_PKG_VERSION"));
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

    info!("Starting Payment Service...");

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

    // Initialize blockchain provider. Don't hard-fail startup if the RPC is
    // unreachable (blockchain disabled in CI/dev, or a momentary outage): run
    // with no provider so DB-backed payment routes still serve. On-chain
    // operations return an error until the RPC is reachable.
    let provider = match blockchain::provider::create_provider(&config.blockchain).await {
        Ok(p) => {
            info!("Blockchain provider initialized");
            Some(p)
        }
        Err(e) => {
            warn!(
                "Blockchain provider unavailable ({e}); on-chain payment features disabled \
                 until the RPC is reachable."
            );
            None
        }
    };

    // Initialize payment service
    let payment_service = Arc::new(
        PaymentService::new(
            config.clone(),
            db_pool.clone(),
            redis_conn.clone(),
            provider.clone(),
        )
        .await?,
    );
    info!("Payment service initialized");

    // Start background workers
    let service_clone = payment_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::transaction_monitor::start(service_clone).await {
            warn!("Transaction monitor error: {}", e);
        }
    });

    let service_clone = payment_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::pending_payment_processor::start(service_clone).await {
            warn!("Pending payment processor error: {}", e);
        }
    });

    let service_clone = payment_service.clone();
    tokio::spawn(async move {
        if let Err(e) = workers::balance_reconciliation::start(service_clone).await {
            warn!("Balance reconciliation worker error: {}", e);
        }
    });

    info!("Background workers started");

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        db_pool,
        redis_conn,
        payment_service,
        metrics: shared::MetricsRegistry::new("payment-service", env!("CARGO_PKG_VERSION")),
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
        // Payment endpoints
        .route(
            "/api/v1/payments/bounty/deposit",
            post(handlers::payment::deposit_bounty_reward),
        )
        .route(
            "/api/v1/payments/bounty/distribute",
            post(handlers::payment::distribute_bounty_reward),
        )
        .route(
            "/api/v1/payments/stake/lock",
            post(handlers::payment::lock_stake),
        )
        .route(
            "/api/v1/payments/stake/unlock",
            post(handlers::payment::unlock_stake),
        )
        .route(
            "/api/v1/payments/stake/slash",
            post(handlers::payment::slash_stake),
        )
        .route(
            "/api/v1/payments/withdraw",
            post(handlers::payment::withdraw_funds),
        )
        .route(
            "/api/v1/payments/balance/{address}",
            get(handlers::payment::get_balance),
        )
        .route(
            "/api/v1/payments/transactions/{address}",
            get(handlers::payment::get_transactions),
        )
        .route(
            "/api/v1/payments/transaction/{tx_hash}",
            get(handlers::payment::get_transaction_status),
        )
        // Gas estimation
        .route(
            "/api/v1/payments/gas/estimate",
            post(handlers::payment::estimate_gas),
        )
        // Admin endpoints
        .route(
            "/api/v1/admin/payments/pending",
            get(handlers::admin::get_pending_payments),
        )
        .route(
            "/api/v1/admin/payments/failed",
            get(handlers::admin::get_failed_payments),
        )
        .route(
            "/api/v1/admin/payments/{id}/retry",
            post(handlers::admin::retry_payment),
        )
        .route(
            "/api/v1/admin/treasury/balance",
            get(handlers::admin::get_treasury_balance),
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
    info!("Payment Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Payment Service shut down gracefully");
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_conn: redis::aio::ConnectionManager,
    pub payment_service: Arc<PaymentService>,
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
