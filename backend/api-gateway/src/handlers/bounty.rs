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

// Request/Response DTOs
#[derive(Deserialize)]
pub struct CreateBountyRequest {
    pub title: String,
    pub description: String,
    pub target_url: Option<String>,
    pub target_hash: Option<String>,
    pub target_type: String, // "url", "file", "binary"
    pub reward_amount: i64,
    pub submission_id: Uuid,
    pub deadline: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct SubmitAnalysisRequest {
    pub engine_id: String,
    pub verdict: String, // "malicious", "benign", "suspicious"
    pub confidence: f32, // 0.0-1.0
    pub analysis_details: serde_json::Value,
    pub stake_amount: u64,
}
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

// handler Implementation
pub async fn create_bounty(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(request): Json<CreateBountyRequest>,
) -> Result<Json<Bounty>, StatusCode> {
    // Compute deadline_hours from the provided deadline
    let now = Utc::now();
    let deadline_hours = ((request.deadline - now).num_hours()).max(1) as i32;

    let model_request = crate::models::bounty::CreateBountyRequest {
        submission_id: request.submission_id,
        title: request.title,
        description: Some(request.description),
        reward_amount: request.reward_amount.to_string(),
        min_stake_amount: Some("0".to_string()),
        max_participants: None,
        deadline_hours: Some(deadline_hours),
        requires_verification: Some(false),
        priority_level: Some(1),
        consensus_threshold: None,
    };

    let bounty = state
        .db
        .create_bounty(model_request, claims.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create bounty: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Submit on-chain createBounty
    let reward_amount =
        ethers::types::U256::from_dec_str(&bounty.reward_amount).unwrap_or_default();
    let deadline_ts = bounty
        .deadline
        .map(|d| ethers::types::U256::from(d.timestamp() as u64))
        .unwrap_or(ethers::types::U256::from(
            (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as u64,
        ));

    // Derive artifact hash from the submission's file hash when available
    let artifact_hash = match state
        .db
        .get_submission_file_hash(request.submission_id)
        .await
    {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            tracing::debug!(
                "No file hash found for submission {}, using empty hash",
                request.submission_id
            );
            String::new()
        }
        Err(e) => {
            tracing::warn!(
                "Failed to fetch file hash for submission {}: {}",
                request.submission_id,
                e
            );
            String::new()
        }
    };
    let artifact_type = "file".to_string();

    let bc_params = crate::services::blockchain::CreateBountyParams {
        artifact_hash,
        artifact_type,
        reward_amount,
        deadline: deadline_ts,
        description: bounty.description.clone().unwrap_or_default(),
    };

    match state.blockchain.create_bounty(bc_params).await {
        Ok((tx_hash, on_chain_id)) => {
            let hash_str = format!("{tx_hash:?}");
            let chain_id = on_chain_id.as_u64() as i64;
            if let Err(e) = state
                .db
                .update_bounty_on_chain_id(bounty.id, &hash_str, chain_id)
                .await
            {
                tracing::warn!(
                    "Bounty created on-chain but failed to store on_chain_id: {}",
                    e
                );
            }
            tracing::info!("Bounty {} mapped to on-chain ID {}", bounty.id, chain_id);
        }
        Err(e) => {
            tracing::warn!("On-chain bounty creation failed (DB record exists): {}", e);
        }
    }

    Ok(Json(bounty))
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

pub async fn submit_analysis(
    State(state): State<crate::AppState>,
    _claims: crate::middleware::auth::Claims,
    Path(bounty_id): Path<Uuid>,
    Json(request): Json<SubmitAnalysisRequest>,
) -> Result<Json<SubmissionResponse>, StatusCode> {
    use crate::services::blockchain::SubmitAnalysisParams;
    use ethers::types::U256;

    // Look up the real on-chain bounty ID from DB
    let on_chain_id = state
        .db
        .get_bounty_on_chain_id(bounty_id)
        .await
        .map_err(|e| {
            tracing::error!("DB error looking up on_chain_id: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::error!(
                "Bounty {} has no on_chain_id — not yet confirmed on-chain",
                bounty_id
            );
            StatusCode::PRECONDITION_FAILED
        })?;

    // Map verdict string to uint8 enum value
    let verdict: u8 = match request.verdict.as_str() {
        "benign" => 1,
        "malicious" => 2,
        "suspicious" => 3,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let params = SubmitAnalysisParams {
        bounty_id: U256::from(on_chain_id as u64),
        verdict,
        confidence: U256::from((request.confidence * 100.0) as u64),
        stake_amount: U256::from(request.stake_amount),
        analysis_hash: serde_json::to_string(&request.analysis_details).unwrap_or_default(),
    };

    let _tx_hash = state
        .blockchain
        .submit_analysis(params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to submit analysis on-chain: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(SubmissionResponse {
        id: Uuid::new_v4(),
        bounty_id,
        engine_id: request.engine_id,
        verdict: request.verdict,
        confidence: request.confidence,
        stake_amount: request.stake_amount,
        submitted_at: chrono::Utc::now(),
        is_winner: None,
    }))
}

pub async fn finalize_bounty(
    State(state): State<crate::AppState>,
    _claims: crate::middleware::auth::Claims,
    Path(bounty_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    use ethers::types::U256;

    let chain_id = state
        .db
        .get_bounty_on_chain_id(bounty_id)
        .await
        .map_err(|e| {
            tracing::error!("DB error looking up on_chain_id: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::error!(
                "Bounty {} has no on_chain_id — not yet confirmed on-chain",
                bounty_id
            );
            StatusCode::PRECONDITION_FAILED
        })?;

    let on_chain_id = U256::from(chain_id as u64);

    state
        .blockchain
        .resolve_bounty(on_chain_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to finalize bounty on-chain: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::OK)
}

/// Update a bounty (owner only)
pub async fn update_bounty(
    State(state): State<crate::AppState>,
    claims: crate::middleware::auth::Claims,
    Path(bounty_id): Path<Uuid>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bounty = state
        .db
        .get_bounty_by_id(bounty_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if bounty.creator_id != claims.sub {
        return Err(StatusCode::FORBIDDEN);
    }

    // Only allow updates on active bounties
    if bounty.bounty_status != "active" {
        return Err(StatusCode::CONFLICT);
    }

    let title = payload.get("title").and_then(|v| v.as_str());
    let description = payload.get("description").and_then(|v| v.as_str());

    sqlx::query(
        "UPDATE bounties SET title = COALESCE($1, title), description = COALESCE($2, description), updated_at = NOW() WHERE id = $3"
    )
    .bind(title)
    .bind(description)
    .bind(bounty_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to update bounty: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(serde_json::json!({
        "id": bounty_id,
        "message": "Bounty updated successfully"
    })))
}

/// Cancel a bounty (owner only, must be active)
pub async fn cancel_bounty(
    State(state): State<crate::AppState>,
    claims: crate::middleware::auth::Claims,
    Path(bounty_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let bounty = state
        .db
        .get_bounty_by_id(bounty_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if bounty.creator_id != claims.sub {
        return Err(StatusCode::FORBIDDEN);
    }

    if bounty.bounty_status != "active" {
        return Err(StatusCode::CONFLICT);
    }

    state
        .db
        .update_bounty_status(bounty_id, "cancelled")
        .await
        .map_err(|e| {
            tracing::error!("Failed to cancel bounty: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::OK)
}

/// Extend bounty deadline (owner only)
pub async fn extend_bounty(
    State(state): State<crate::AppState>,
    claims: crate::middleware::auth::Claims,
    Path(bounty_id): Path<Uuid>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bounty = state
        .db
        .get_bounty_by_id(bounty_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if bounty.creator_id != claims.sub {
        return Err(StatusCode::FORBIDDEN);
    }

    let new_deadline = payload
        .get("deadline")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc))
        .ok_or(StatusCode::BAD_REQUEST)?;

    if new_deadline <= chrono::Utc::now() {
        return Err(StatusCode::BAD_REQUEST);
    }

    sqlx::query("UPDATE bounties SET deadline = $1, updated_at = NOW() WHERE id = $2")
        .bind(new_deadline)
        .bind(bounty_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to extend bounty deadline: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "id": bounty_id,
        "new_deadline": new_deadline,
        "message": "Bounty deadline extended"
    })))
}

/// Claim bounty reward (participant only, bounty must be completed)
pub async fn claim_reward(
    State(state): State<crate::AppState>,
    claims: crate::middleware::auth::Claims,
    Path(bounty_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bounty = state
        .db
        .get_bounty_by_id(bounty_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if bounty.bounty_status != "completed" {
        return Err(StatusCode::CONFLICT);
    }

    let chain_id = state
        .db
        .get_bounty_on_chain_id(bounty_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;

    Ok(Json(serde_json::json!({
        "bounty_id": bounty_id,
        "on_chain_id": chain_id,
        "user_id": claims.sub,
        "message": "Rewards are distributed automatically during bounty resolution. Check your wallet for received rewards.",
        "status": "resolved"
    })))
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
