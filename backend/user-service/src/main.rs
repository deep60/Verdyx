// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

mod auth;
mod config;
mod handlers;
mod middleware;
mod models;
mod services;
mod storage;

use anyhow::Result;
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use crate::config::Config;
use crate::middleware::{admin_middleware, auth_middleware};
use crate::services::user_service::UserService;

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

    info!("Starting User Service...");

    // Load configuration
    let config = Config::from_env()?;
    info!("Configuration loaded successfully");

    // Initialize database connection pool
    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;
    info!("Database connection pool established");

    // Run service-local migrations. The schema (users, user_profiles,
    // user_settings, kyc_verifications) lives in ./migrations and is owned by
    // this service. `sqlx::migrate!` embeds the migration SQL into the binary
    // at compile time, so we run it unconditionally — the migrations directory
    // is not shipped in the runtime image, and gating on its runtime presence
    // would skip schema creation entirely. A failure must be fatal: booting
    // without the schema would let liveness pass while every real request 500s
    // on a missing relation.
    info!("Running database migrations...");
    if let Err(e) = sqlx::migrate!("./migrations").run(&db_pool).await {
        tracing::error!("Database migration failed: {}", e);
        return Err(anyhow::anyhow!("Database migration failed: {e}"));
    }
    info!("Database migrations completed");

    // Initialize Redis client for sessions
    let redis_client = redis::Client::open(config.redis.url.clone())?;
    let redis_conn = redis_client.get_connection_manager().await?;
    info!("Redis connection established");

    // Initialize user service
    let user_service =
        Arc::new(UserService::new(config.clone(), db_pool.clone(), redis_conn.clone()).await?);
    info!("User service initialized");

    // Initialize avatar storage (optional - only if S3/MinIO is reachable).
    let avatar_storage = match storage::AvatarStorage::from_env().await {
        Ok(s) => {
            info!("Avatar storage initialized");
            Some(Arc::new(s))
        }
        Err(e) => {
            info!(
                "Avatar storage unavailable ({}); avatar uploads disabled",
                e
            );
            None
        }
    };

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        db_pool,
        redis_conn,
        user_service,
        avatar_storage,
        metrics: shared::MetricsRegistry::new("user-service", env!("CARGO_PKG_VERSION")),
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

    // Public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health::health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/refresh", post(handlers::auth::refresh_token))
        .route(
            "/api/v1/auth/forgot-password",
            post(handlers::auth::forgot_password),
        )
        .route(
            "/api/v1/auth/reset-password",
            post(handlers::auth::reset_password),
        );

    // Protected routes (authentication required)
    let protected_routes = Router::new()
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route(
            "/api/v1/auth/verify-email",
            post(handlers::auth::verify_email),
        )
        .route(
            "/api/v1/auth/wallet/verify",
            post(handlers::auth::verify_wallet),
        )
        // Current-user identity (gateway proxies /auth/verify here)
        .route("/api/v1/auth/me", get(handlers::auth::get_me))
        // Profile endpoints
        .route("/api/v1/profile", get(handlers::profile::get_profile))
        .route("/api/v1/profile", put(handlers::profile::update_profile))
        .route("/api/v1/account", put(handlers::profile::update_account))
        .route("/api/v1/account", delete(handlers::profile::delete_account))
        .route(
            "/api/v1/profile/avatar",
            post(handlers::profile::upload_avatar),
        )
        .route(
            "/api/v1/profile/{user_id}",
            get(handlers::profile::get_user_profile),
        )
        // Settings endpoints
        .route("/api/v1/settings", get(handlers::settings::get_settings))
        .route("/api/v1/settings", put(handlers::settings::update_settings))
        .route(
            "/api/v1/settings/password",
            put(handlers::settings::change_password),
        )
        .route(
            "/api/v1/settings/2fa/enable",
            post(handlers::settings::enable_2fa),
        )
        .route(
            "/api/v1/settings/2fa/disable",
            post(handlers::settings::disable_2fa),
        )
        .route(
            "/api/v1/settings/2fa/verify",
            post(handlers::settings::verify_2fa),
        )
        // KYC endpoints
        .route("/api/v1/kyc/submit", post(handlers::kyc::submit_kyc))
        .route("/api/v1/kyc/status", get(handlers::kyc::get_kyc_status))
        .route(
            "/api/v1/kyc/documents",
            post(handlers::kyc::upload_documents),
        )
        // Wallet endpoints
        .route("/api/v1/wallet/link", post(handlers::wallet::link_wallet))
        .route(
            "/api/v1/wallet/unlink",
            delete(handlers::wallet::unlink_wallet),
        )
        .route("/api/v1/wallet/list", get(handlers::wallet::list_wallets))
        .layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    // Admin routes (admin role required)
    let admin_routes = Router::new()
        .route("/api/v1/admin/users", get(handlers::admin::list_users))
        .route(
            "/api/v1/admin/users/{user_id}",
            get(handlers::admin::get_user),
        )
        .route(
            "/api/v1/admin/users/{user_id}/suspend",
            post(handlers::admin::suspend_user),
        )
        .route(
            "/api/v1/admin/users/{user_id}/activate",
            post(handlers::admin::activate_user),
        )
        .route(
            "/api/v1/admin/kyc/{user_id}/approve",
            post(handlers::admin::approve_kyc),
        )
        .route(
            "/api/v1/admin/kyc/{user_id}/reject",
            post(handlers::admin::reject_kyc),
        )
        .layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            admin_middleware,
        ));

    // Combine all routes. The metrics middleware sees every request before
    // routing and ticks `verdyx_http_requests_total` / `verdyx_http_errors_total`
    // — the same counters served at `/metrics`.
    let prom_registry = app_state.metrics.clone();
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(admin_routes)
        .layer(axum_middleware::from_fn(move |req, next| {
            let r = prom_registry.clone();
            async move { shared::metrics_mw::track_with(r, req, next).await }
        }))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .with_state(app_state);

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("User Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("User Service shut down gracefully");
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_conn: redis::aio::ConnectionManager,
    pub user_service: Arc<UserService>,
    pub avatar_storage: Option<Arc<storage::AvatarStorage>>,
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
        tracing::warn!("readiness check failed: database unreachable");
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
