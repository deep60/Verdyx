//! The old off-chain bounty records, read-only.
//!
//! Bounties now live on the BountyManager contract and are posted, staked on
//! and resolved from the person's own wallet (see `handlers::chain` for the
//! indexed list). The routes that wrote here signed on-chain transactions
//! with a server key, so they are gone; these reads remain for old records.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::bounty::Bounty;
use crate::AppState;

#[derive(Deserialize)]
pub struct BountyFilters {
    pub status: Option<String>,
    pub min_reward: Option<u64>,
    pub max_reward: Option<u64>,
    pub category: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}
#[derive(Serialize)]
pub struct BountyResponse {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub creator_id: Uuid,
    pub reward_amount: String,
    pub bounty_status: String,
    pub created_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
    pub participant_count: i32,
    pub consensus_reached: bool,
    pub final_verdict: Option<String>,
    pub confidence_score: Option<f32>,
}
#[derive(Serialize)]
pub struct BountListResponse {
    pub bounties: Vec<BountyResponse>,
    pub total_count: u32,
    pub page: u32,
    pub limit: u32,
}

#[derive(Serialize)]
pub struct SubmissionResponse {
    pub id: Uuid,
    pub bounty_id: Uuid,
    pub engine_id: String,
    pub verdict: String,
    pub confidence: f32,
    pub stake_amount: u64,
    pub submitted_at: DateTime<Utc>,
    pub is_winner: Option<bool>,
}

#[derive(Serialize)]
pub struct BountyDetailsResponse {
    pub bounty: BountyResponse,
    pub submissions: Vec<SubmissionResponse>,
    pub file_info: Option<FileInfo>,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub hash: String,
    pub size: u64,
    pub file_type: String,
    pub upload_timestamp: DateTime<Utc>,
}

pub async fn list_bounties(
    State(state): State<AppState>,
    Query(filters): Query<BountyFilters>,
) -> Result<Json<Vec<Bounty>>, StatusCode> {
    let page = filters.page.unwrap_or(1).max(1) as i64;
    let limit = filters.limit.unwrap_or(20).clamp(1, 100) as i64;
    let offset = (page - 1) * limit;

    let bounties = state
        .db
        .get_active_bounties(limit, offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch bounties: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(bounties))
}

pub async fn get_bounty(
    State(state): State<AppState>,
    Path(bounty_id): Path<Uuid>,
) -> Result<Json<Bounty>, StatusCode> {
    let bounty = state
        .db
        .get_bounty_by_id(bounty_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch bounty: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(bounty))
}
/// Get bounty statistics
pub async fn get_bounty_stats(
    State(state): State<crate::AppState>,
    Path(bounty_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let _bounty = state
        .db
        .get_bounty_by_id(bounty_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let submissions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM analysis_results WHERE bounty_id = $1")
            .bind(bounty_id)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    let participants: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT COALESCE(engine_id::text, engine_name)) FROM analysis_results WHERE bounty_id = $1",
    )
    .bind(bounty_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    let total_staked: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(stake_amount)::text, '0') FROM bounty_submissions WHERE bounty_id = $1",
    )
    .bind(bounty_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or_else(|_| "0".to_string());

    Ok(Json(serde_json::json!({
        "bounty_id": bounty_id,
        "submissions": submissions,
        "participants": participants,
        "total_staked": total_staked
    })))
}

/// List active bounties
pub async fn list_active_bounties(
    State(state): State<crate::AppState>,
) -> Result<Json<Vec<Bounty>>, StatusCode> {
    let bounties = state.db.get_active_bounties(50, 0).await.map_err(|e| {
        tracing::error!("Failed to fetch active bounties: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(bounties))
}

/// List completed bounties
pub async fn list_completed_bounties(
    State(state): State<crate::AppState>,
) -> Result<Json<Vec<Bounty>>, StatusCode> {
    let bounties = sqlx::query_as::<_, Bounty>(
        r#"
        SELECT * FROM bounties
        WHERE bounty_status = 'completed'
        ORDER BY completed_at DESC NULLS LAST
        LIMIT 50
        "#,
    )
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch completed bounties: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(bounties))
}
