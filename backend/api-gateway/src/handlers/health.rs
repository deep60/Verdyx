use axum::{extract::State, http::StatusCode, response::Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Service status enum
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Healthy,
    Degraded,
    Unhealthy,
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

/// Main health check endpoint
///
/// GET /api/v1/health
pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let start_time = std::time::Instant::now();

    // Check services
    let db_ready = state.db.health_check().await.is_ok();
    let redis_ready = state.redis.health_check().await.unwrap_or(false);
    let blockchain_ready = state.blockchain.health_check().await;

    // Database and Redis are required for the public API. Blockchain is
    // reported, but a dead RPC must not take the whole site down.
    let overall_status = if db_ready && redis_ready {
        if blockchain_ready {
            ServiceStatus::Healthy
        } else {
            ServiceStatus::Degraded
        }
    } else {
        ServiceStatus::Unhealthy
    };

    let uptime = start_time.elapsed().as_secs();

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
            blockchain: if blockchain_ready {
                ServiceStatus::Healthy
            } else {
                ServiceStatus::Unhealthy
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
