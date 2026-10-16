use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::identity::{bearer_map, fetch_identity, UserIdentity};
use crate::AppState;

/// User profile response
#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub ethereum_address: Option<String>,
    pub reputation_score: f64,
    pub total_submissions: u32,
    pub successful_submissions: u32,
    pub accuracy_rate: f64,
    pub total_earnings: String,
    pub rank: Option<u32>,
    pub joined_at: DateTime<Utc>,
    pub last_active_at: Option<DateTime<Utc>>,
}

/// Update user profile request
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub ethereum_address: Option<String>,
    pub bio: Option<String>,
    pub notification_preferences: Option<serde_json::Value>,
}

/// User statistics
#[derive(Debug, Serialize)]
pub struct UserStats {
    pub total_analyses: u64,
    pub total_bounties_created: u64,
    pub total_bounties_participated: u64,
    pub total_rewards_earned: String,
    pub total_rewards_paid: String,
    pub average_accuracy: f64,
    pub streak_days: u32,
}

/// Get current user profile
///
/// GET /api/v1/users/me — identity is owned by user-service; proxy to it.
pub async fn get_current_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    _claims: crate::middleware::auth::Claims,
) -> Result<Json<UserProfile>, StatusCode> {
    let hm = bearer_map(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let u = fetch_identity(&state, hm)
        .await
        .map_err(|c| StatusCode::from_u16(c).unwrap_or(StatusCode::BAD_GATEWAY))?;
    Ok(Json(identity_to_profile(u)))
}

/// Map a user-service identity into the gateway's `UserProfile`. Reputation and
/// submission stats are owned by other services; use `/users/me/stats` for those.
fn identity_to_profile(u: UserIdentity) -> UserProfile {
    UserProfile {
        id: u.id,
        username: u.username,
        email: u.email,
        ethereum_address: u.ethereum_address,
        reputation_score: 0.0,
        total_submissions: 0,
        successful_submissions: 0,
        accuracy_rate: 0.0,
        total_earnings: "0".to_string(),
        rank: None,
        joined_at: u.created_at,
        last_active_at: None,
    }
}

/// Get user profile by ID
///
/// GET /api/v1/users/:id
pub async fn get_user_by_id(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserProfile>, StatusCode> {
    let user = state
        .db
        .get_user_by_id(user_id)
        .await
        .map_err(|e| {
            tracing::error!("Database error fetching user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(UserProfile {
        id: user.id,
        username: user.username,
        email: user.email,
        ethereum_address: user.wallet_address,
        reputation_score: user.reputation_score as f64,
        total_submissions: 0,
        successful_submissions: 0,
        accuracy_rate: 0.0,
        total_earnings: "0".to_string(),
        rank: None,
        joined_at: user.created_at,
        last_active_at: Some(user.updated_at),
    }))
}

fn api_err(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({
            "error": message,
            "status": status.as_u16(),
        })),
    )
}

/// Update current user profile.
///
/// PUT /api/v1/users/me — identity and profile writes are owned by user-service.
/// This handler validates the obvious shape, then forwards the change. It does
/// not update the gateway's copy of `users`.
pub async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    _claims: crate::middleware::auth::Claims,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfile>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(ref username) = payload.username {
        if !(3..=50).contains(&username.len())
            || !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "username must be 3-50 characters and contain only letters, numbers, or underscore",
            ));
        }
    }
    if let Some(ref email) = payload.email {
        let ok = email.len() <= 255
            && email.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
            });
        if !ok {
            return Err(api_err(StatusCode::BAD_REQUEST, "email is not valid"));
        }
    }

    let hm = bearer_map(&headers).ok_or_else(|| {
        api_err(StatusCode::UNAUTHORIZED, "missing or invalid bearer token")
    })?;

    let body = serde_json::json!({
        "username": payload.username,
        "email": payload.email,
        "bio": payload.bio,
    });
    let resp = state
        .proxy
        .put("user-service", "/api/v1/account", body, Some(hm.clone()))
        .await
        .map_err(|_| api_err(StatusCode::BAD_GATEWAY, "user-service unavailable"))?;
    if !resp.status().is_success() {
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let text = resp.text().await.unwrap_or_default();
        let message = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "profile update failed".to_string());
        return Err(api_err(status, &message));
    }

    let u = fetch_identity(&state, hm).await.map_err(|c| {
        api_err(
            StatusCode::from_u16(c).unwrap_or(StatusCode::BAD_GATEWAY),
            "updated, but the new profile could not be read",
        )
    })?;
    Ok(Json(identity_to_profile(u)))
}

/// Get user statistics
///
/// GET /api/v1/users/me/stats
/// Get user statistics
///
/// GET /api/v1/users/me/stats
pub async fn get_user_stats(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
) -> Result<Json<UserStats>, StatusCode> {
    let stats = state
        .db
        .get_user_analysis_stats(claims.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch user stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .unwrap_or(crate::services::database::UserAnalysisStats {
            total_analyses: Some(0),
            avg_confidence: Some(0.0),
            malicious_detections: Some(0),
            benign_detections: Some(0),
        });

    // Query bounty and reward stats
    let bounties_created: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM bounties WHERE creator_id = $1")
            .bind(claims.sub)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or((0,));

    let bounties_participated: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT bounty_id) FROM bounty_submissions WHERE engine_id = $1::text",
    )
    .bind(claims.sub.to_string())
    .fetch_one(state.db.pool())
    .await
    .unwrap_or((0,));

    let rewards_earned: (Option<i64>,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount), 0) FROM payouts WHERE recipient = $1 AND status = 'Processed'"
    )
    .bind(claims.sub.to_string())
    .fetch_one(state.db.pool())
    .await
    .unwrap_or((Some(0),));

    let rewards_paid: (Option<i64>,) = sqlx::query_as(
        "SELECT COALESCE(SUM(CAST(reward_amount AS BIGINT)), 0) FROM bounties WHERE creator_id = $1 AND bounty_status = 'completed'"
    )
    .bind(claims.sub)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or((Some(0),));

    // Streak: count consecutive days with at least one analysis
    let streak_days: (i64,) = sqlx::query_as(
        r#"
        WITH daily AS (
            SELECT DATE(created_at) as d FROM analysis_results
            WHERE engine_id = $1::text
            GROUP BY DATE(created_at)
            ORDER BY d DESC
        ),
        ranked AS (
            SELECT d, d - INTERVAL '1 day' * ROW_NUMBER() OVER (ORDER BY d DESC) AS grp
            FROM daily
        )
        SELECT COUNT(*) FROM ranked
        WHERE grp = (SELECT grp FROM ranked LIMIT 1)
        "#,
    )
    .bind(claims.sub.to_string())
    .fetch_one(state.db.pool())
    .await
    .unwrap_or((0,));

    Ok(Json(UserStats {
        total_analyses: stats.total_analyses.unwrap_or(0) as u64,
        total_bounties_created: bounties_created.0 as u64,
        total_bounties_participated: bounties_participated.0 as u64,
        total_rewards_earned: rewards_earned.0.unwrap_or(0).to_string(),
        total_rewards_paid: rewards_paid.0.unwrap_or(0).to_string(),
        average_accuracy: stats.avg_confidence.unwrap_or(0.0),
        streak_days: streak_days.0 as u32,
    }))
}

/// Get user activity history
///
/// GET /api/v1/users/me/activity
pub async fn get_user_activity(
    State(state): State<AppState>,
    Query(params): Query<ActivityQuery>,
) -> Result<Json<ActivityListResponse>, StatusCode> {
    // Fetch recent activity from analysis_results and bounty_submissions
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = ((page.saturating_sub(1)) * limit) as i64;

    let activities: Vec<Activity> = sqlx::query_as::<_, Activity>(
        r#"
        SELECT
            id,
            'analysis' AS activity_type,
            CONCAT('Analysis on bounty ', bounty_id) AS description,
            json_build_object('verdict', verdict, 'confidence', confidence) AS metadata,
            created_at AS timestamp
        FROM analysis_results
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit as i64)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM analysis_results")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or((0,));

    Ok(Json(ActivityListResponse {
        activities,
        total: total.0 as u64,
        page,
        limit,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ActivityQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub activity_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActivityListResponse {
    pub activities: Vec<Activity>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Activity {
    pub id: Uuid,
    pub activity_type: String,
    pub description: String,
    pub metadata: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

/// Delete the current account.
///
/// DELETE /api/v1/users/me
///
/// user-service owns the soft-delete and the audit row. The gateway does not
/// write `users` itself — that copy was drifting from the identity service.
pub async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    _claims: crate::middleware::auth::Claims,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let hm = bearer_map(&headers).ok_or_else(|| {
        api_err(StatusCode::UNAUTHORIZED, "missing or invalid bearer token")
    })?;
    let resp = state
        .proxy
        .delete("user-service", "/api/v1/account", Some(hm))
        .await
        .map_err(|_| api_err(StatusCode::BAD_GATEWAY, "user-service unavailable"))?;
    if resp.status().is_success() {
        // Explicit account removal also removes that user's uploads and queues
        // their object keys for deletion. There is no time-based purge.
        if let Ok(paths) = state.db.file_paths_for_user(_claims.sub).await {
            for path in paths {
                let _ = state.redis.push_to_queue("artifact_deletions", &path).await;
            }
        }
        let _ = state.db.delete_file_submissions_for_user(_claims.sub).await;
        return Ok(StatusCode::NO_CONTENT);
    }
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    Err(api_err(status, "account deletion failed"))
}

/// Get another user's stats by ID
pub async fn get_user_stats_by_id(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserStats>, StatusCode> {
    let stats = state
        .db
        .get_user_analysis_stats(user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch user stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .unwrap_or(crate::services::database::UserAnalysisStats {
            total_analyses: Some(0),
            avg_confidence: Some(0.0),
            malicious_detections: Some(0),
            benign_detections: Some(0),
        });

    Ok(Json(UserStats {
        total_analyses: stats.total_analyses.unwrap_or(0) as u64,
        total_bounties_created: 0,
        total_bounties_participated: 0,
        total_rewards_earned: "0".to_string(),
        total_rewards_paid: "0".to_string(),
        average_accuracy: stats.avg_confidence.unwrap_or(0.0),
        streak_days: 0,
    }))
}

/// List current user's API keys
pub async fn list_api_keys(
    State(_state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    Ok(Json(vec![]))
}

/// Revoke an API key
pub async fn revoke_api_key(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND user_id = $2")
        .bind(key_id)
        .bind(claims.sub)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke API key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}
