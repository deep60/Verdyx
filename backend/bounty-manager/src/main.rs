// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]

use axum::{
    response::Json,
    routing::{get, post, put},
    Router,
};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info, warn};
use uuid::Uuid;

mod config;
mod handlers;
mod models;
mod services;
mod workers;

use handlers::bounty_crud;
use services::reputation;

// Application State
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub reputation_service: Arc<reputation::ReputationService>,
}

// Bounty Models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bounty {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub reward_amount: Decimal,
    pub token_address: Option<String>,
    pub creator_address: String,
    pub artifact_hash: String,
    pub artifact_type: ArtifactType,
    pub status: BountyStatus,
    pub min_reputation: i32,
    pub max_participants: i32,
    pub current_participants: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactType {
    File,
    Url,
    Hash,
    Domain,
    IpAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BountyStatus {
    Open,
    Active,
    Pending,
    Completed,
    Cancelled,
    Expired,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBountyRequest {
    pub title: String,
    pub description: String,
    pub reward_amount: Decimal,
    pub token_address: Option<String>,
    pub creator_address: String,
    pub artifact_hash: String,
    pub artifact_type: ArtifactType,
    pub min_reputation: Option<i32>,
    pub max_participants: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BountyFilters {
    pub status: Option<BountyStatus>,
    pub artifact_type: Option<ArtifactType>,
    pub min_reward: Option<Decimal>,
    pub max_reward: Option<Decimal>,
    pub creator_address: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BountyParticipation {
    pub bounty_id: Uuid,
    pub participant_address: String,
    pub stake_amount: Decimal,
    pub verdict: Option<ThreatVerdict>,
    pub confidence_score: Option<f64>,
    pub analysis_data: Option<serde_json::Value>,
    pub submitted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ThreatVerdict {
    Malicious,
    Benign,
    Suspicious,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
            timestamp: Utc::now(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env first so RUST_LOG/log-level/secret env are honored everywhere.
    dotenvy::dotenv().ok();

    // Initialize tracing — JSON format with thread ids + line numbers so logs
    // aggregate cleanly across the fleet (matches user/consensus/payment/etc).
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .json()
        .init();

    info!("Starting Bounty Manager...");

    // Load configuration. In production we refuse to fall back to a localhost
    // dev DSN — a misconfigured deploy that boots against an empty local DB
    // is worse than a hard failure at startup.
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) if environment != "production" => {
            warn!("DATABASE_URL not set; using local dev default (NEVER use in prod)");
            "postgresql://verdyx:password@localhost/verdyx".to_string()
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "DATABASE_URL must be set in production (ENVIRONMENT=production)"
            )
            .into());
        }
    };

    let _redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let port = std::env::var("SERVER_PORT")
        .or_else(|_| std::env::var("PORT"))
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()?;

    // Initialize database connection. Avoid logging the full DSN — it
    // contains credentials.
    info!("Connecting to database...");
    let db = PgPool::connect(&database_url).await?;
    info!("Database connection established");

    // Run database migrations — fail-fast on error.
    info!("Running database migrations...");
    sqlx::migrate!("./migrations").run(&db).await?;
    info!("Database migrations complete");

    // Initialize reputation service with database pool
    let reputation_service = Arc::new(reputation::ReputationService::new(db.clone()));

    // Initialize the on-chain client up front so it can be shared by the router
    // (claimable-balance queries), the sync service, and the resolution keeper.
    let blockchain = init_blockchain_service().await;

    // Create application state using BountyManagerState
    let state = bounty_crud::BountyManagerState {
        db: db.clone(),
        reputation_service: reputation_service.clone(),
        blockchain: blockchain.clone(),
    };

    // Build router
    let app = create_router(state);

    if let Some(blockchain) = blockchain.clone() {
        // Blockchain sync: mirror on-chain events (ConsensusReached, RewardsDistributed,
        // ...) into the database. `start()` spawns its own loop and returns quickly.
        let sync_service =
            services::blockchain_sync::BlockchainSyncService::new(db.clone(), blockchain.clone());
        info!("Blockchain sync service starting...");
        if let Err(e) = sync_service.start().await {
            error!("Blockchain sync service failed to start: {}", e);
        }

        // Resolution keeper: the contract decouples resolution from submission, so
        // this worker calls resolveBounty() on-chain once a bounty is eligible.
        let resolution_worker =
            workers::resolution_worker::ResolutionWorker::new(db.clone(), blockchain);
        info!("Bounty resolution keeper starting...");
        tokio::spawn(async move {
            resolution_worker.run().await;
        });
    } else {
        warn!(
            "Blockchain features disabled: set BLOCKCHAIN_PRIVATE_KEY and BOUNTY_MANAGER_ADDRESS \
             (and optionally BOUNTY_MANAGER_ABI_PATH / THREAT_TOKEN_ABI_PATH) to enable the \
             resolution keeper, chain sync, and withdrawal queries"
        );
    }

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Bounty Manager service starting on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Bounty Manager shut down gracefully");
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

/// Inline metrics middleware for bounty-manager. The rest of the fleet uses
/// `shared::metrics_mw::track_with`, but bounty-manager is on axum 0.8 (the
/// rest are on 0.7) so its `Request`/`Next` types are incompatible. The
/// behavior is identical: tick `inc_request` for every request, `inc_error`
/// for any 5xx.
async fn bounty_metrics_track(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let reg = metrics_registry();
    reg.inc_request();
    let resp = next.run(req).await;
    if resp.status().is_server_error() {
        reg.inc_error();
    }
    resp
}

/// Build the shared blockchain client from environment configuration.
/// Returns None (with a warning) when required settings are missing so the
/// service can still serve its HTTP API without chain connectivity.
async fn init_blockchain_service() -> Option<Arc<services::blockchain::BlockchainService>> {
    let rpc_url = std::env::var("BLOCKCHAIN_RPC_URL")
        .or_else(|_| std::env::var("ETHEREUM_RPC_URL"))
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let private_key = std::env::var("BLOCKCHAIN_PRIVATE_KEY")
        .or_else(|_| std::env::var("PRIVATE_KEY"))
        .unwrap_or_default();
    let chain_id: u64 = std::env::var("CHAIN_ID")
        .unwrap_or_else(|_| "31337".to_string())
        .parse()
        .unwrap_or(31337);
    let bounty_manager_addr = std::env::var("BOUNTY_MANAGER_ADDRESS")
        .or_else(|_| std::env::var("CONTRACT_ADDRESS_BOUNTY"))
        .unwrap_or_default();
    let threat_token_addr = std::env::var("THREAT_TOKEN_ADDRESS")
        .or_else(|_| std::env::var("CONTRACT_ADDRESS_TOKEN"))
        .unwrap_or_default();

    if private_key.is_empty() || bounty_manager_addr.is_empty() {
        return None;
    }

    // Load real ABIs so methods can be called by name (resolveBounty,
    // pendingWithdrawals, approve, transfer). Without a configured path we fall
    // back to empty ABIs and chain calls will fail loudly at call time.
    let bounty_abi = std::env::var("BOUNTY_MANAGER_ABI_PATH")
        .ok()
        .and_then(|p| load_abi(&p))
        .unwrap_or_default();
    let token_abi = std::env::var("THREAT_TOKEN_ABI_PATH")
        .ok()
        .and_then(|p| load_abi(&p))
        .unwrap_or_default();

    match services::blockchain::BlockchainService::new(
        &rpc_url,
        &private_key,
        chain_id,
        &bounty_manager_addr,
        &threat_token_addr,
        bounty_abi,
        token_abi,
    )
    .await
    {
        Ok(svc) => Some(Arc::new(svc)),
        Err(e) => {
            warn!("Could not initialize blockchain service: {}", e);
            None
        }
    }
}

/// Load a contract ABI from a JSON file. Accepts either a bare ABI array or a
/// Hardhat/Truffle artifact object containing an `"abi"` field.
fn load_abi(path: &str) -> Option<alloy::json_abi::JsonAbi> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read ABI file {}: {}", path, e);
            return None;
        }
    };

    // Try a bare ABI array first.
    if let Ok(abi) = serde_json::from_str::<alloy::json_abi::JsonAbi>(&contents) {
        return Some(abi);
    }

    // Fall back to an artifact object with an `abi` field.
    match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(v) => match v.get("abi") {
            Some(abi_val) => serde_json::from_value::<alloy::json_abi::JsonAbi>(abi_val.clone())
                .map_err(|e| warn!("ABI field in {} is invalid: {}", path, e))
                .ok(),
            None => {
                warn!("ABI file {} has no top-level `abi` field", path);
                None
            }
        },
        Err(e) => {
            warn!("ABI file {} is not valid JSON: {}", path, e);
            None
        }
    }
}

fn create_router(state: bounty_crud::BountyManagerState) -> Router {
    let metrics_layer = axum::middleware::from_fn(bounty_metrics_track);

    Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
        // Bounty management routes
        .route("/bounties", post(bounty_crud::create_bounty))
        .route("/bounties", get(bounty_crud::list_bounties))
        .route("/bounties/{id}", get(bounty_crud::get_bounty))
        .route("/bounties/{id}", put(bounty_crud::update_bounty))
        .route("/bounties/{id}/cancel", post(bounty_crud::cancel_bounty))
        // Stats route
        .route("/bounties/stats", get(bounty_crud::get_bounty_stats))
        // Submission routes
        .route("/bounties/{id}/submit", post(handlers::submit_analysis))
        .route(
            "/bounties/{id}/submissions",
            get(handlers::list_submissions_for_bounty),
        )
        .route("/submissions/{id}", get(handlers::get_submission))
        .route(
            "/submissions/{id}/status",
            put(handlers::update_submission_status),
        )
        // Payout routes
        .route(
            "/bounties/{id}/payout",
            post(handlers::process_bounty_completion),
        )
        .route(
            "/payouts/{id}/distribute",
            post(handlers::distribute_rewards),
        )
        .route("/payouts/{id}/slash", post(handlers::handle_stake_slashing))
        .route("/payouts/history", get(handlers::get_payout_history))
        // Withdrawal (pull-payment) surfacing
        .route("/withdrawals/{address}", get(handlers::get_claimable))
        // Dispute routes
        .route("/disputes", post(handlers::create_dispute))
        .route("/disputes", get(handlers::list_disputes))
        .route("/disputes/{id}", get(handlers::get_dispute))
        .route("/disputes/{id}", put(handlers::update_dispute))
        .route("/disputes/{id}/resolve", post(handlers::resolve_dispute))
        .route("/disputes/{id}/vote", post(handlers::vote_on_dispute))
        .route("/disputes/{id}/withdraw", post(handlers::withdraw_dispute))
        .route("/disputes/stats", get(handlers::get_dispute_stats))
        // Validation routes
        .route(
            "/submissions/{id}/validate",
            post(handlers::validate_submission),
        )
        .route(
            "/submissions/{id}/validation",
            get(handlers::get_validation_result),
        )
        .route("/validations", get(handlers::list_validations))
        .route(
            "/validations/bulk",
            post(handlers::bulk_validate_submissions),
        )
        .route("/validations/stats", get(handlers::get_validation_stats))
        .route(
            "/submissions/{id}/revalidate",
            post(handlers::revalidate_submission),
        )
        // Reputation routes
        .route("/reputation/{id}", get(handlers::get_engine_reputation))
        .route("/reputation/{id}", put(handlers::update_reputation))
        .route("/reputation/leaderboard", get(handlers::get_leaderboard))
        .route(
            "/reputation/{id}/history",
            get(handlers::get_reputation_history),
        )
        .route("/reputation/decay", post(handlers::apply_reputation_decay))
        .route("/engines/register", post(handlers::register_engine))
        // State management
        .with_state(state)
        // Middleware
        .layer(metrics_layer)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(tower_http::catch_panic::CatchPanicLayer::new())
                .layer(CorsLayer::permissive()),
        )
}

async fn health_check() -> Json<ApiResponse<HashMap<String, String>>> {
    let mut status = HashMap::new();
    status.insert("service".to_string(), "bounty-manager".to_string());
    status.insert("status".to_string(), "healthy".to_string());
    status.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());

    Json(ApiResponse::success(status))
}

/// Process-global metrics registry (bounty-manager shares its router state with
/// handlers, so a global keeps the metrics endpoint decoupled from that state).
fn metrics_registry() -> &'static shared::MetricsRegistry {
    static REGISTRY: std::sync::OnceLock<shared::MetricsRegistry> = std::sync::OnceLock::new();
    REGISTRY
        .get_or_init(|| shared::MetricsRegistry::new("bounty-manager", env!("CARGO_PKG_VERSION")))
}

/// Liveness: process is up.
async fn liveness_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "alive": true }))
}

/// Readiness: checks DB connectivity. 503 when not ready.
async fn readiness_check(
    axum::extract::State(state): axum::extract::State<bounty_crud::BountyManagerState>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    if db_ok {
        Ok(Json(serde_json::json!({ "ready": true, "database": "up" })))
    } else {
        warn!("readiness check failed: database unreachable");
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Prometheus text-format metrics.
async fn metrics_handler() -> (
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
        metrics_registry().render_prometheus(),
    )
}

// Database helper functions
// NOTE: These functions use sqlx::query! macro which requires DATABASE_URL to be set
// They are commented out for now. Use the models in src/models/ instead.
//
// pub async fn get_bounty_by_id(db: &PgPool, bounty_id: Uuid) -> Result<Option<Bounty>, sqlx::Error> {
//     models::bounty::BountyModel::find_by_id(db, bounty_id).await
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert!(response.0.success);
    }

    #[test]
    fn test_bounty_serialization() {
        let bounty = Bounty {
            id: Uuid::new_v4(),
            title: "Test Bounty".to_string(),
            description: "Test Description".to_string(),
            reward_amount: Decimal::new(100, 0),
            token_address: None,
            creator_address: "0x123".to_string(),
            artifact_hash: "hash123".to_string(),
            artifact_type: ArtifactType::File,
            status: BountyStatus::Open,
            min_reputation: 0,
            max_participants: 10,
            current_participants: 0,
            created_at: Utc::now(),
            expires_at: None,
            metadata: None,
        };

        let json = serde_json::to_string(&bounty).unwrap();
        assert!(json.contains("Test Bounty"));
    }
}
