use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

/// Query parameters for listing analyses
#[derive(Debug, Deserialize)]
pub struct ListAnalysesQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub status: Option<String>,
    pub verdict: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Response for analysis list
#[derive(Debug, Serialize)]
pub struct AnalysisListResponse {
    pub analyses: Vec<AnalysisSummary>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
}

/// Summary of an analysis
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AnalysisSummary {
    pub id: Uuid,
    pub file_hash: Option<String>,
    pub status: Option<String>,
    pub verdict: Option<String>,
    pub confidence: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Analysis stats
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisStats {
    pub total_analyses: i64,
    pub pending: i64,
    pub completed: i64,
    pub malicious_count: i64,
    pub benign_count: i64,
    pub suspicious_count: i64,
    // Extra fields the frontend dashboard expects
    pub total_submissions: i64,
    pub active_analyses: i64,
    pub completed_today: i64,
    pub threats_detected: i64,
    pub total_engines: i64,
}

/// Get analysis by ID
pub async fn get_analysis(
    State(state): State<AppState>,
    Path(analysis_id): Path<Uuid>,
) -> Result<Json<AnalysisSummary>, StatusCode> {
    let row = sqlx::query_as::<_, AnalysisSummary>(
        "SELECT id, file_hash, status, verdict, confidence::float8 as confidence, created_at, completed_at FROM analyses WHERE id = $1"
    )
    .bind(analysis_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error fetching analysis: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match row {
        Some(analysis) => Ok(Json(analysis)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Get analysis details (same as get_analysis for now)
pub async fn get_analysis_details(
    state: State<AppState>,
    path: Path<Uuid>,
) -> Result<Json<AnalysisSummary>, StatusCode> {
    get_analysis(state, path).await
}

/// List all analyses with filters
pub async fn list_analyses(
    State(state): State<AppState>,
    Query(params): Query<ListAnalysesQuery>,
) -> Result<Json<AnalysisListResponse>, StatusCode> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page.saturating_sub(1)) * limit;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM analyses")
        .fetch_one(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("DB error counting analyses: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let analyses = sqlx::query_as::<_, AnalysisSummary>(
        "SELECT id, file_hash, status, verdict, confidence::float8 as confidence, created_at, completed_at
         FROM analyses ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error listing analyses: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(AnalysisListResponse {
        analyses,
        total,
        page,
        limit,
    }))
}

/// Get analysis statistics
pub async fn get_analysis_stats(
    State(state): State<AppState>,
) -> Result<Json<AnalysisStats>, StatusCode> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM analyses")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0);

    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM analyses WHERE status = 'pending'")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0);

    let completed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM analyses WHERE status = 'completed'")
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    let malicious: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM analyses WHERE verdict = 'malicious'")
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    let benign: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM analyses WHERE verdict = 'benign'")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0);

    let suspicious: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM analyses WHERE verdict = 'suspicious'")
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    // Extra dashboard fields
    let total_submissions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bounty_submissions")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(total); // fallback to analyses count

    let active_analyses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analyses WHERE status IN ('pending', 'processing')",
    )
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(pending);

    let completed_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analyses WHERE status = 'completed' AND completed_at >= CURRENT_DATE",
    )
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    let total_engines: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM engines WHERE is_active = true")
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    Ok(Json(AnalysisStats {
        total_analyses: total,
        pending,
        completed,
        malicious_count: malicious,
        benign_count: benign,
        suspicious_count: suspicious,
        total_submissions,
        active_analyses,
        completed_today,
        threats_detected: malicious + suspicious,
        total_engines,
    }))
}

/// Get analyses by bounty
pub async fn get_analyses_by_bounty(
    State(state): State<AppState>,
    Path(bounty_id): Path<Uuid>,
) -> Result<Json<Vec<AnalysisSummary>>, StatusCode> {
    let analyses = sqlx::query_as::<_, AnalysisSummary>(
        "SELECT id, file_hash, status, verdict, confidence::float8 as confidence, created_at, completed_at
         FROM analyses WHERE bounty_id = $1 ORDER BY created_at DESC"
    )
    .bind(bounty_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(analyses))
}

/// Get analyses by file hash
pub async fn get_analyses_by_hash(
    State(state): State<AppState>,
    Path(file_hash): Path<String>,
) -> Result<Json<Vec<AnalysisSummary>>, StatusCode> {
    let analyses = sqlx::query_as::<_, AnalysisSummary>(
        "SELECT id, file_hash, status, verdict, confidence::float8 as confidence, created_at, completed_at
         FROM analyses WHERE file_hash = $1 ORDER BY created_at DESC"
    )
    .bind(&file_hash)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(analyses))
}

/// Submit analysis (standalone, not via bounty route)
pub async fn submit_analysis(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bounty_id = payload
        .get("bounty_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let file_hash = payload
        .get("file_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let verdict = payload
        .get("verdict")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Validate verdict value
    if !["benign", "malicious", "suspicious"].contains(&verdict) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let confidence = payload
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let analysis_id = Uuid::new_v4();
    let now = chrono::Utc::now();

    sqlx::query(
        r#"INSERT INTO analyses (id, bounty_id, analyst_id, file_hash, verdict, confidence, status, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $7)"#
    )
    .bind(analysis_id)
    .bind(bounty_id)
    .bind(claims.sub)
    .bind(file_hash)
    .bind(verdict)
    .bind(confidence)
    .bind(now)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to insert analysis: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(serde_json::json!({
        "id": analysis_id,
        "bounty_id": bounty_id,
        "analyst_id": claims.sub,
        "verdict": verdict,
        "confidence": confidence,
        "status": "pending",
        "created_at": now
    })))
}

/// Dispute an analysis result
pub async fn dispute_analysis(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(analysis_id): Path<Uuid>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify analysis exists
    let analysis = sqlx::query_as::<_, AnalysisSummary>(
        "SELECT id, file_hash, status, verdict, confidence::float8 as confidence, created_at, completed_at FROM analyses WHERE id = $1"
    )
    .bind(analysis_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Can only dispute completed analyses
    if analysis.status.as_deref() != Some("completed") {
        return Err(StatusCode::CONFLICT);
    }

    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("No reason provided");

    // Update analysis status to disputed
    sqlx::query("UPDATE analyses SET status = 'disputed', updated_at = NOW() WHERE id = $1")
        .bind(analysis_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to dispute analysis: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "analysis_id": analysis_id,
        "status": "disputed",
        "disputed_by": claims.sub,
        "reason": reason,
        "message": "Analysis has been disputed and flagged for review"
    })))
}
