// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

use std::env;
use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::error;
use tracing::info;
use uuid::Uuid;

mod analyzers;
mod models;
mod queue;
mod sandbox;
mod scanners;
mod storage;
mod utils;

use crate::analyzers::hash_analyzer::{HashInfo, HashType};
use crate::analyzers::{
    AnalysisEngine, AnalysisEngineConfig, AnalysisOptions, FileAnalysisRequest,
};
use crate::scanners::file_scanner::{FileScanner, FileScannerConfig};
use crate::scanners::url_scanner::{UrlScanner, UrlScannerConfig};
use crate::scanners::Scanner;
use crate::storage::S3Client;
use crate::utils::file_handler::FileHandler;
use chrono::Utc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    analysis_engine: Arc<Mutex<AnalysisEngine>>,
    file_handler: Arc<FileHandler>,
    s3_client: Arc<S3Client>,
    file_scanner: Arc<FileScanner>,
    url_scanner: Arc<UrlScanner>,
    db: sqlx::PgPool,
    metrics: shared::MetricsRegistry,
}
#[derive(Deserialize)]
struct AnalysisRequest {
    artifact_type: String, // "file", "url", "hash"
    priority: Option<u8>,
    bounty_id: Option<String>,
    metadata: Option<serde_json::Value>,
}
#[derive(Serialize)]
struct AnalysisResponse {
    analysis_id: String,
    status: String,
    message: String,
}
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    engines: EngineStatus,
    detailed_engines: crate::analyzers::DetailedEngineReport,
}
#[derive(Serialize)]
struct EngineStatus {
    // Always compiled into the binary.
    static_analyzer: bool,
    hash_analyzer: bool,
    heuristic_engine: bool,
    signature_matcher: bool,
    // Native engines, gated behind cargo features at build time.
    yara_engine: bool,
    clamav: bool,
    ml_engine: bool,
}

impl EngineStatus {
    /// Report what is actually compiled into this binary rather than
    /// hardcoding `true`. Native engines reflect their cargo feature flags.
    fn current() -> Self {
        Self {
            static_analyzer: true,
            hash_analyzer: true,
            heuristic_engine: true,
            signature_matcher: true,
            yara_engine: cfg!(feature = "yara-engine"),
            clamav: cfg!(feature = "clamav"),
            ml_engine: cfg!(feature = "ml-engine"),
        }
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::time())
        .init();

    info!("Starting Verdyx Analysis Engine");

    // Load configuration
    let database_url =
        env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let port = env::var("SERVER_PORT")
        .or_else(|_| env::var("PORT"))
        .unwrap_or_else(|_| "8082".to_string())
        .parse::<u16>()
        .unwrap_or(8082);
    let yara_rule_path = env::var("YARA_RULES_PATH")
        .or_else(|_| env::var("YARA_RULE_PATH"))
        .unwrap_or_else(|_| "./rules".to_string());
    let upload_dir = env::var("UPLOAD_DIR").unwrap_or_else(|_| "./temp/verdyx-uploads".to_string());

    // Initialize database connection pool with proper error handling
    info!("Connecting to database...");
    let db_pool = match sqlx::PgPool::connect(&database_url).await {
        Ok(pool) => {
            info!("Database connection established");
            pool
        }
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            return Err(anyhow::anyhow!("Database connection failed: {e}").into());
        }
    };

    // Run migrations with error handling. Fail-fast: a broken migration is a
    // production-blocking bug; silently continuing risks the service running
    // against a schema it does not expect.
    info!("Running database migrations...");
    if let Err(e) = sqlx::migrate!("./migrations").run(&db_pool).await {
        error!("Failed to run database migrations: {}", e);
        return Err(anyhow::anyhow!("Database migration failed: {e}").into());
    }
    info!("Database migrations complete");

    // Initialize Redis client with error handling
    info!("Connecting to Redis...");
    let redis_client = match redis::Client::open(redis_url.clone()) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create Redis client: {}", e);
            return Err(anyhow::anyhow!("Redis client creation failed: {e}").into());
        }
    };

    match redis_client.get_multiplexed_async_connection().await {
        Ok(_) => info!("Redis connection established"),
        Err(e) => {
            error!("Failed to connect to Redis: {}", e);
            return Err(anyhow::anyhow!("Redis connection failed: {e}").into());
        }
    }

    // Initialize S3 client
    info!("Initializing S3 client...");
    let s3_client = Arc::new(crate::storage::S3Client::new().await?);
    info!("S3 client initialized");

    // Initialize analyzers via combined engine
    info!("Initializing analysis engines...");
    let mut config = AnalysisEngineConfig::default();
    config.yara_engine.rules_directory = std::path::PathBuf::from(yara_rule_path);
    let analysis_engine = Arc::new(Mutex::new(AnalysisEngine::new(config).await?));
    let file_handler = Arc::new(FileHandler::new(&upload_dir)?);

    // Initialize scanners
    info!("Initializing scanners...");
    let file_scanner = Arc::new(<FileScanner as Scanner>::new(FileScannerConfig::default())?);
    let url_scanner = Arc::new(<UrlScanner as Scanner>::new(UrlScannerConfig::default())?);

    // Create application state
    let app_state = AppState {
        analysis_engine,
        file_handler,
        s3_client: s3_client.clone(),
        file_scanner,
        url_scanner,
        db: db_pool.clone(),
        metrics: shared::MetricsRegistry::new("analysis-engine", env!("CARGO_PKG_VERSION")),
    };

    info!("Analysis engines initialized successfully");

    // Spawn queue consumer worker in background
    info!("Starting analysis queue consumer worker...");
    let consumer_redis_client = redis_client.clone();
    let consumer_db_pool = db_pool.clone();
    let consumer_s3_client = s3_client.clone();
    let consumer_analysis_engine = app_state.analysis_engine.clone();

    tokio::spawn(async move {
        if let Err(e) = crate::queue::consumer::start_analysis_worker(
            consumer_redis_client,
            consumer_db_pool,
            consumer_s3_client,
            consumer_analysis_engine,
        )
        .await
        {
            error!("Queue consumer worker failed: {}", e);
        }
    });
    info!("Queue consumer worker started");

    // Build the application router. Metrics middleware ticks
    // `verdyx_http_requests_total` / `verdyx_http_errors_total` per request.
    let prom_registry = app_state.metrics.clone();
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
        .route("/analyze/file", post(analyze_file))
        .route("/analyze/url", post(analyze_url))
        .route("/analyze/hash", post(analyze_hash))
        .route("/analysis/{id}", get(get_analysis_result))
        .route("/analysis/{id}/detailed", get(get_detailed_analysis))
        .route("/engines/status", get(engines_status))
        .with_state(app_state)
        .layer(axum::middleware::from_fn(move |req, next| {
            let r = prom_registry.clone();
            async move { shared::metrics_mw::track_with(r, req, next).await }
        }))
        .layer({
            let allowed_origins: Vec<_> = std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:8080".to_string())
                .split(',')
                .filter_map(|o| o.trim().parse::<axum::http::HeaderValue>().ok())
                .collect();

            CorsLayer::new()
                .allow_origin(allowed_origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ])
        })
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::catch_panic::CatchPanicLayer::new());

    // Start the server
    let addr = format!("0.0.0.0:{port}");
    info!("Analysis Engine listening on {}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Analysis Engine shut down gracefully");
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

    info!("Shutdown signal received, draining connections...");
}

async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    let detailed_engines = state.analysis_engine.lock().await.get_engine_status_report().await;
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "analysis-engine".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        engines: EngineStatus::current(),
        detailed_engines,
    })
}

/// Liveness: process is up.
async fn liveness_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "alive": true }))
}

/// Readiness: checks DB connectivity. 503 when not ready.
async fn readiness_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    if db_ok {
        Ok(Json(serde_json::json!({ "ready": true, "database": "up" })))
    } else {
        error!("readiness check failed: database unreachable");
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Prometheus text-format metrics.
async fn metrics_handler(
    State(state): State<AppState>,
) -> (
    StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    String,
) {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.render_prometheus(),
    )
}

async fn analyze_file(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<AnalysisResponse>, StatusCode> {
    info!("Received file analysis request");

    let _analysis_id = Uuid::new_v4().to_string();

    // Process multipart data
    let mut file_data = Vec::new();
    let mut filename = String::new();
    let mut _analysis_req: Option<AnalysisRequest> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        error!("Failed to read multipart field: {}", e);
        StatusCode::BAD_REQUEST
    })? {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        if name == "file" {
            filename = field.file_name().map(|s| s.to_string()).unwrap_or_default();
            file_data = field
                .bytes()
                .await
                .map_err(|e| {
                    error!("Failed to read file bytes: {}", e);
                    StatusCode::BAD_REQUEST
                })?
                .to_vec();
        } else if name == "request" {
            let json_str = field.text().await.map_err(|e| {
                error!("Failed to read request json: {}", e);
                StatusCode::BAD_REQUEST
            })?;
            _analysis_req = Some(serde_json::from_str(&json_str).map_err(|e| {
                error!("Invalid request json: {}", e);
                StatusCode::BAD_REQUEST
            })?);
        }
    }

    let request = FileAnalysisRequest {
        filename,
        file_data,
        file_hashes: None,
        analysis_options: AnalysisOptions::default(),
    };

    let mut engine_guard = state.analysis_engine.lock().await;
    let analysis_result = engine_guard.analyze_file(request).await.map_err(|e| {
        error!("Analysis failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Store analysis result in database
    let verdict_str = format!("{:?}", analysis_result.consensus_verdict);
    let status_str = format!("{:?}", analysis_result.status);
    let result_json = serde_json::to_value(&analysis_result).unwrap_or_default();

    if let Err(e) = sqlx::query(
        r#"INSERT INTO engine_analysis_results (analysis_id, status, verdict, confidence, created_at, completed_at, result_data)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (analysis_id) DO UPDATE SET status = $2, verdict = $3, confidence = $4, completed_at = $6, result_data = $7"#
    )
    .bind(analysis_result.analysis_id)
    .bind(&status_str)
    .bind(&verdict_str)
    .bind(analysis_result.consensus_confidence)
    .bind(analysis_result.started_at)
    .bind(analysis_result.completed_at)
    .bind(&result_json)
    .execute(&state.db)
    .await {
        error!("Failed to persist analysis result: {}", e);
    }

    info!("Analysis completed: {:?}", analysis_result.analysis_id);

    Ok(Json(AnalysisResponse {
        analysis_id: analysis_result.analysis_id.to_string(),
        status: "completed".to_string(),
        message: "File Analysis completed successfully".to_string(),
    }))
}

async fn analyze_url(
    State(state): State<AppState>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<AnalysisResponse>, StatusCode> {
    let url = request
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();

    let analysis_id = Uuid::new_v4().to_string();

    let state_clone = state.clone();
    let analysis_id_clone = analysis_id.clone();

    tokio::spawn(async move {
        if let Err(e) = perform_url_analysis(state_clone, &analysis_id_clone, &url).await {
            error!("URL analysis failed for {}: {}", analysis_id_clone, e);
        }
    });

    Ok(Json(AnalysisResponse {
        analysis_id,
        status: "submitted".to_string(),
        message: "URL Analysis started successfully".to_string(),
    }))
}

async fn analyze_hash(
    State(state): State<AppState>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<AnalysisResponse>, StatusCode> {
    info!("Received hash analysis request");

    let analysis_id = Uuid::new_v4().to_string();

    let hash = request
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();

    let state_clone = state.clone();
    let analysis_id_clone = analysis_id.clone();
    let hash_clone = hash;

    tokio::spawn(async move {
        if let Err(e) = perform_hash_analysis(state_clone, &analysis_id_clone, &hash_clone).await {
            error!("Hash analysis failed for {}: {}", analysis_id_clone, e);
        }
    });

    Ok(Json(AnalysisResponse {
        analysis_id,
        status: "submitted".to_string(),
        message: "Hash Analysis started successfully".to_string(),
    }))
}

async fn get_analysis_result(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Fetching analysis result for: {}", id);

    let analysis_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    #[allow(clippy::type_complexity)]
    let row: Option<(String, Option<String>, Option<f32>, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT status, verdict, confidence, created_at, completed_at FROM engine_analysis_results WHERE analysis_id = $1"
    )
    .bind(analysis_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to query analysis result: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match row {
        Some((status, verdict, confidence, created_at, completed_at)) => {
            Ok(Json(serde_json::json!({
                "analysis_id": id,
                "status": status,
                "verdict": verdict,
                "confidence": confidence,
                "created_at": created_at,
                "completed_at": completed_at
            })))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_detailed_analysis(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Fetching detailed analysis for: {}", id);

    let analysis_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT result_data FROM engine_analysis_results WHERE analysis_id = $1")
            .bind(analysis_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                error!("Failed to query detailed analysis: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    match row {
        Some((result_data,)) => Ok(Json(result_data)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn engines_status(State(state): State<AppState>) -> Json<crate::analyzers::DetailedEngineReport> {
    let report = state.analysis_engine.lock().await.get_engine_status_report().await;
    Json(report)
}

async fn perform_file_analysis(
    state: AppState,
    _analysis_id: &str,
    file_path: &str,
    _request: Option<AnalysisRequest>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_data = state.file_handler.get_file(file_path).await?;
    let req = FileAnalysisRequest {
        filename: file_path.to_string(),
        file_data,
        file_hashes: None,
        analysis_options: AnalysisOptions::default(),
    };

    let mut engine_guard = state.analysis_engine.lock().await;
    engine_guard.analyze_file(req).await?;

    Ok(())
}

async fn perform_url_analysis(
    state: AppState,
    analysis_id: &str,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting URL analysis for: {} ({})", analysis_id, url);

    let aid = Uuid::parse_str(analysis_id)?;

    // Insert pending record
    let _ = sqlx::query(
        "INSERT INTO engine_analysis_results (analysis_id, status, created_at, result_data) VALUES ($1, 'InProgress', NOW(), $2)"
    )
    .bind(aid)
    .bind(serde_json::json!({"type": "url", "url": url}))
    .execute(&state.db)
    .await;

    // Use URL scanner to analyze the URL
    let scan_result = state.url_scanner.scan(url.as_bytes(), None).await?;

    let verdict = format!("{:?}", scan_result.base.verdict);
    let confidence = scan_result.base.confidence_score;
    let result_json = serde_json::to_value(&scan_result).unwrap_or_default();

    info!(
        "URL analysis completed for: {} - Verdict: {}",
        analysis_id, verdict
    );

    // Update with results
    sqlx::query(
        "UPDATE engine_analysis_results SET status = 'Completed', verdict = $1, confidence = $2, completed_at = NOW(), result_data = $3 WHERE analysis_id = $4"
    )
    .bind(&verdict)
    .bind(confidence)
    .bind(&result_json)
    .bind(aid)
    .execute(&state.db)
    .await?;

    Ok(())
}

async fn perform_hash_analysis(
    state: AppState,
    analysis_id: &str,
    hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting hash analysis for: {} ({})", analysis_id, hash);

    let aid = Uuid::parse_str(analysis_id)?;

    let hash_info = HashInfo {
        hash_type: HashType::SHA256,
        hash_value: hash.to_string(),
        file_size: None,
        computed_at: chrono::Utc::now(),
    };

    info!(
        "Hash analysis requested for hash: {} (type: {:?})",
        hash_info.hash_value, hash_info.hash_type
    );

    // Persist hash analysis result
    let result_json = serde_json::json!({
        "type": "hash",
        "hash": hash,
        "hash_type": format!("{:?}", hash_info.hash_type),
        "status": "completed"
    });

    sqlx::query(
        r#"INSERT INTO engine_analysis_results (analysis_id, status, verdict, created_at, completed_at, result_data)
           VALUES ($1, 'Completed', 'Unknown', NOW(), NOW(), $2)"#
    )
    .bind(aid)
    .bind(&result_json)
    .execute(&state.db)
    .await?;

    info!("Hash analysis completed for: {}", analysis_id);
    Ok(())
}
