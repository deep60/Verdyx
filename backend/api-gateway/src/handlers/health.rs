use axum::{extract::State, http::StatusCode, response::Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::services::blockchain::ChainHealth;
use crate::AppState;

static STARTED_AT: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Record the process start for `uptime`. Called once from `main`.
pub fn mark_started() {
    STARTED_AT.get_or_init(std::time::Instant::now);
}

fn uptime_secs() -> u64 {
    STARTED_AT
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs()
}

/// Service status enum
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Healthy,
    Degraded,
    Unhealthy,
    /// Not set up: no Verdyx contract exists on the configured chain.
    #[serde(rename = "not_deployed")]
    NotDeployed,
}

/// Health check response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: ServiceStatus,
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub uptime: u64,
    pub services: ServiceHealth,
}

/// Individual service health status
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub database: ServiceStatus,
    pub redis: ServiceStatus,
    pub blockchain: ServiceStatus,
}

/// Database and Redis are required for the public API. A chain with no
/// Verdyx contracts is a feature that isn't set up, not an outage; a deployed
/// chain whose RPC fails degrades the API without taking it down.
fn overall(db_ready: bool, redis_ready: bool, chain: ChainHealth) -> ServiceStatus {
    if !(db_ready && redis_ready) {
        ServiceStatus::Unhealthy
    } else if chain == ChainHealth::Unreachable {
        ServiceStatus::Degraded
    } else {
        ServiceStatus::Healthy
    }
}

/// Main health check endpoint
///
/// GET /api/v1/health
pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    // Check services
    let db_ready = state.db.health_check().await.is_ok();
    let redis_ready = state.redis.health_check().await.unwrap_or(false);
    let chain = state.blockchain.health_check().await;

    let overall_status = overall(db_ready, redis_ready, chain);
    let uptime = uptime_secs();

    let response = HealthResponse {
        status: overall_status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now(),
        uptime,
        services: ServiceHealth {
            database: if db_ready {
                ServiceStatus::Healthy
            } else {
                ServiceStatus::Unhealthy
            },
            redis: if redis_ready {
                ServiceStatus::Healthy
            } else {
                ServiceStatus::Unhealthy
            },
            blockchain: match chain {
                ChainHealth::Ready => ServiceStatus::Healthy,
                ChainHealth::NotDeployed => ServiceStatus::NotDeployed,
                ChainHealth::Unreachable => ServiceStatus::Unhealthy,
            },
        },
    };

    // Reflect health in the HTTP status so external monitors see a non-2xx
    // when the gateway is degraded, while still returning the diagnostic body.
    let status_code = if db_ready && redis_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

/// Readiness check endpoint
///
/// GET /api/v1/ready
pub async fn readiness_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Check if all critical services are ready
    let db_ready = state.db.health_check().await.is_ok();
    let redis_ready = state.redis.health_check().await.unwrap_or(false);

    if db_ready && redis_ready {
        Ok(Json(serde_json::json!({
            "ready": true,
            "timestamp": Utc::now()
        })))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Liveness check endpoint
///
/// GET /api/v1/alive
pub async fn liveness_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "alive": true,
        "timestamp": Utc::now()
    }))
}

/// Detailed metrics endpoint (for monitoring systems)
///
/// GET /api/v1/metrics
pub async fn metrics(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let snapshot = state.metrics.get_snapshot().await;
    let endpoint_metrics = state.metrics.get_endpoint_metrics().await;
    let status_codes = state.metrics.get_status_code_distribution().await;

    Ok(Json(serde_json::json!({
        "timestamp": Utc::now(),
        "version": env!("CARGO_PKG_VERSION"),
        "global": snapshot,
        "endpoints": endpoint_metrics,
        "status_codes": status_codes,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undeployed_chain_is_not_an_outage() {
        assert_eq!(
            overall(true, true, ChainHealth::Ready),
            ServiceStatus::Healthy
        );
        assert_eq!(
            overall(true, true, ChainHealth::NotDeployed),
            ServiceStatus::Healthy
        );
        assert_eq!(
            overall(true, true, ChainHealth::Unreachable),
            ServiceStatus::Degraded
        );
        assert_eq!(
            overall(false, true, ChainHealth::Ready),
            ServiceStatus::Unhealthy
        );
        assert_eq!(
            serde_json::to_string(&ServiceStatus::NotDeployed).unwrap(),
            "\"not_deployed\""
        );
    }

    #[test]
    fn uptime_counts_from_process_start() {
        mark_started();
        let first = uptime_secs();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(uptime_secs() > first);
    }
}
