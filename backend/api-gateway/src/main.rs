// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::SystemTime};
use tokio::{net::TcpListener, sync::RwLock};
use tower::{ServiceBuilder, layer::Layer};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{config::AppConfig, handlers, middleware, models, routes, services, utils};
use crate::models::response::ApiResponse;
use crate::services::{
    blockchain::BlockchainService, database::DatabaseService, proxy_service::ProxyService,
    redis::RedisService,
};

// Shared middleware
use shared::{
    circuit_breaker::{CircuitBreakerConfig, CircuitBreakerRegistry},
    idempotency::{IdempotencyStore, idempotency_middleware},
    otel::{init_combined_subscriber, OtelConfig},
    validation::validation_middleware,
};

mod config;
mod handlers;
mod middleware;
use middleware::metrics::MetricsCollector;
mod models;
mod routes;
mod services;
mod utils;

use config::AppConfig;
use services::{
    blockchain::BlockchainService, database::DatabaseService, proxy_service::ProxyService,
    redis::RedisService,
};

// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DatabaseService>,
    pub redis: Arc<RedisService>,
    pub blockchain: Arc<BlockchainService>,
    pub config: Arc<AppConfig>,
    pub active_sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    pub metrics: Arc<MetricsCollector>,
    /// HTTP proxy to downstream microservices (auth/users → user-service,
    /// submissions → submission-service, etc.) with circuit breaking + retries.
    pub proxy: Arc<ProxyService>,
    /// Prometheus-text-format registry. Kept alongside the existing per-endpoint
    /// `MetricsCollector` so the gateway emits the same `verdyx_*` schema as
    /// every other service for the root `/metrics` scrape.
    pub prom_metrics: shared::MetricsRegistry,
    /// Circuit breaker registry for downstream service calls
    pub circuit_breaker_registry: Arc<CircuitBreakerRegistry>,
    /// Idempotency store for safe retries
    pub idempotency_store: Arc<IdempotencyStore>,
}

// Session information for active users
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_id: Uuid,
    pub wallet_address: Option<String>,
    pub reputation_score: i32,
    pub last_activity: u64,
    pub permissions: Vec<String>,
}

// ApiResponse moved to models::response

// Middleware for authentication
async fn auth_middleware(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // Check if token is blacklisted
            let blacklist_key = format!("jwt_blacklist:{token}");
            {
                let mut conn = state.redis.connection_pool.clone();
                let is_blacklisted: Option<String> = redis::cmd("GET")
                    .arg(&blacklist_key)
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();

                if is_blacklisted.is_some() {
                    warn!("Attempted use of blacklisted token");
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }

            // Validate JWT token
            match utils::crypto::validate_jwt(token, &state.config.security.jwt_secret) {
                Ok(claims) => {
                    // Check if session is still active
                    let sessions = state.active_sessions.read().await;
                    if let Some(session_info) = sessions.get(&claims.sub) {
                        // Add user info to request extensions
                        request.extensions_mut().insert(claims);
                        request.extensions_mut().insert(session_info.clone());
                        return Ok(next.run(request).await);
                    }
                }
                Err(e) => {
                    warn!("JWT validation failed: {}", e);
                }
            }
        }
    }

    // For public endpoints, continue without authentication
    let path = request.uri().path();
    if path.starts_with("/api/v1/health")
        || path.starts_with("/api/v1/auth/login")
        || path.starts_with("/api/v1/auth/register")
        || path.starts_with("/api/v1/auth/refresh")
        || path.starts_with("/api/v1/auth/forgot-password")
        || path.starts_with("/api/v1/auth/reset-password")
    {
        return Ok(next.run(request).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}

// Middleware for request logging
async fn logging_middleware(request: axum::extract::Request, next: Next) -> Response {
    let start_time = SystemTime::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    debug!("Incoming request: {} {}", method, uri);

    let response = next.run(request).await;

    let elapsed = start_time.elapsed().unwrap_or_default();
    info!(
        "Request completed: {} {} - Status: {} - Duration: {:?}",
        method,
        uri,
        response.status(),
        elapsed
    );
    response
}

// Initialize services
async fn initialize_services(
    config: &AppConfig,
) -> Result<(DatabaseService, RedisService, BlockchainService)> {
    info!("Initializing services...");

    // Initialize database with connection pool
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await
        .context("Failed to connect to database")?;

    let db = DatabaseService::new(pool);

    // Run database migrations
    sqlx::migrate!("./migrations")
        .run(db.pool())
        .await
        .context("Failed to run database migrations")?;

    // Initialize Redis
    let redis = RedisService::new(&config.redis.url)
        .await
        .context("Failed to initialize Redis service")?;

    // Initialize blockchain service
    let blockchain = BlockchainService::new(config.blockchain.clone())
        .await
        .context("Failed to initialize blockchain service")?;

    info!("All services initialized successfully");
    Ok((db, redis, blockchain))
}

// Load configuration from environment or config files
fn load_config() -> Result<AppConfig> {
    AppConfig::load().context("Failed to load configuration")
}

// // Utility function to get current timestamp
// fn current_timestamp() -> u64 {
//     SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap_or_default()
//         .as_secs()
// }

// Graceful shutdown handler — waits for SIGINT (Ctrl+C) or SIGTERM (sent by
// Docker/Kubernetes on stop/rollout) so in-flight requests can drain.
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

    info!("Shutdown signal received, starting graceful shutdown...");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize OpenTelemetry + logging (combined subscriber)
    let otel_config = OtelConfig {
        service_name: "api-gateway".to_string(),
        otlp_endpoint: std::env::var("OTEL_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4317".to_string()),
        sample_rate: std::env::var("OTEL_SAMPLE_RATE")
            .unwrap_or_else(|_| "0.1".to_string())
            .parse()
            .unwrap_or(0.1),
        tls: false,
        attributes: vec![
            ("deployment.environment".to_string(), 
             std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string())),
            ("service.version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
        ],
    };

    let log_config = shared::logging::LogConfig {
        service_name: "api-gateway".to_string(),
        format: shared::logging::LogFormat::Json,
        level: shared::logging::LogLevel::Info,
        include_line_numbers: false,
        include_thread_ids: true,
    };

    init_combined_subscriber(log_config, otel_config)
        .context("Failed to initialize OpenTelemetry + logging")?;

    info!("Starting Verdyx API Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = load_config()?;
    info!(config.server.host, config.server.port);

    // Initialize metrics collector
    let metrics_collector = Arc::new(MetricsCollector::new());

    // Initialize services
    let (db, redis, blockchain) = initialize_services(&config).await?;

    // Initialize the downstream-service proxy (auth/users → user-service, etc.)
    let proxy = Arc::new(
        ProxyService::new(services::proxy_service::ProxyConfig::default())
            .context("Failed to initialize proxy service")?,
    );

    // Create circuit breaker registry for downstream services
    let circuit_breaker_registry = Arc::new(CircuitBreakerRegistry::new());
    
    // Create idempotency store
    let idempotency_store = Arc::new(IdempotencyStore::new(
        std::time::Duration::from_secs(24 * 60 * 60) // 24 hours
    ));

    // Create application state
    let state = AppState {
        db: Arc::new(db),
        redis: Arc::new(redis),
        blockchain: Arc::new(blockchain),
        config: Arc::new(config.clone()),
        active_sessions: Arc::new(RwLock::new(HashMap::new())),
        metrics: metrics_collector.clone(),
        proxy,
        prom_metrics: shared::MetricsRegistry::new("api-gateway", env!("CARGO_PKG_VERSION")),
        circuit_breaker_registry: circuit_breaker_registry.clone(),
        idempotency_store: idempotency_store.clone(),
    };

    // Create CORS layer from config
    let allowed_origins: Vec<_> = state
        .config
        .security
        .cors
        .allowed_origins
        .iter()
        .filter_map(|origin| origin.parse::<axum::http::HeaderValue>().ok())
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
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            "X-API-Key".parse().unwrap(),
        ])
        .allow_credentials(true);

    // Tower middleware that increments the `verdyx_http_requests_total` /
    // `verdyx_http_errors_total` counters exposed by `/metrics`. Kept as a
    // tiny closure so we can hand each request a cheap clone of the registry.
    let prom_registry = state.prom_metrics.clone();
    let app = routes::create_router(state)
        .layer(axum::middleware::from_fn(move |req, next| {
            let r = prom_registry.clone();
            async move { shared::metrics_mw::track_with(r, req, next).await }
        }))
        // Validation middleware (runs first to reject invalid requests early)
        .layer(axum::middleware::from_fn(validation_middleware::<shared::types::EmptyBody>))
        // Idempotency middleware (for mutating endpoints)
        .layer(axum::middleware::from_fn_with_state(
            idempotency_store.clone(),
            idempotency_middleware
        ))
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(cors)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)); // 10MB

    // Create server address
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));

    // Create TCP listener
    let listener = TcpListener::bind(addr)
        .await
        .context("Failed to bind to address")?;

    info!("🚀 Verdyx API Gateway running on http://{}", addr);
    info!(
        "📚 API Documentation available at http://{}/api/v1/docs",
        addr
    );
    info!("🔍 Health check available at http://{}/api/v1/health", addr);

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    // Shutdown OpenTelemetry gracefully
    shared::shutdown_otel();
    
    info!("Verdyx API Gateway shut down gracefully");
    Ok(())
}
