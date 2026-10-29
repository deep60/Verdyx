use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

/// Leaderboard entry
#[derive(Debug, Serialize)]
pub struct LeaderboardEntry {
    pub rank: u32,
    pub user_id: Uuid,
    pub username: Option<String>,
    pub reputation_score: i32,
}

/// Leaderboard query parameters
#[derive(Debug, Deserialize)]
pub struct LeaderboardQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Leaderboard response
#[derive(Debug, Serialize)]
pub struct LeaderboardResponse {
    pub entries: Vec<LeaderboardEntry>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
}

/// User reputation response
#[derive(Debug, Serialize)]
pub struct UserReputation {
    pub user_id: Uuid,
    pub username: Option<String>,
    pub reputation_score: i32,
    pub rank: Option<i64>,
}

/// Reputation history entry
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReputationHistoryEntry {
    pub id: Uuid,
    pub event_type: String,
    pub score_change: f64,
    pub new_score: f64,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

/// Reputation history response
#[derive(Debug, Serialize)]
pub struct ReputationHistoryResponse {
    pub entries: Vec<ReputationHistoryEntry>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
    pub current_score: i32,
}

/// DB row for leaderboard
#[derive(sqlx::FromRow)]
struct LeaderboardRow {
    id: Uuid,
    username: Option<String>,
    reputation_score: i32,
}

/// Get global leaderboard
pub async fn get_leaderboard(
    State(state): State<AppState>,
    Query(params): Query<LeaderboardQuery>,
) -> Result<Json<LeaderboardResponse>, StatusCode> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = (page.saturating_sub(1)) * limit;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_active = true")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0);

    let rows = sqlx::query_as::<_, LeaderboardRow>(
        "SELECT id, username, reputation_score FROM users WHERE is_active = true
         ORDER BY reputation_score DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error fetching leaderboard: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let base_rank = offset;
    let entries: Vec<LeaderboardEntry> = rows
        .into_iter()
        .enumerate()
        .map(|(i, row)| LeaderboardEntry {
            rank: base_rank + i as u32 + 1,
            user_id: row.id,
            username: row.username,
            reputation_score: row.reputation_score,
        })
        .collect();

    Ok(Json(LeaderboardResponse {
        entries,
        total,
        page,
        limit,
    }))
}

/// Get top analysts (top 10)
pub async fn get_top_analysts(
    State(state): State<AppState>,
) -> Result<Json<Vec<LeaderboardEntry>>, StatusCode> {
    let rows = sqlx::query_as::<_, LeaderboardRow>(
        "SELECT id, username, reputation_score FROM users WHERE is_active = true
         ORDER BY reputation_score DESC LIMIT 10",
    )
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let entries: Vec<LeaderboardEntry> = rows
        .into_iter()
        .enumerate()
        .map(|(i, row)| LeaderboardEntry {
            rank: i as u32 + 1,
            user_id: row.id,
            username: row.username,
            reputation_score: row.reputation_score,
        })
        .collect();

    Ok(Json(entries))
}

/// Get user reputation by ID
pub async fn get_user_reputation(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserReputation>, StatusCode> {
    let user = sqlx::query_as::<_, LeaderboardRow>(
        "SELECT id, username, reputation_score FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Calculate rank
    let rank: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) + 1 FROM users WHERE reputation_score > $1 AND is_active = true",
    )
    .bind(user.reputation_score)
    .fetch_optional(state.db.pool())
    .await
    .unwrap_or(None);

    Ok(Json(UserReputation {
        user_id: user.id,
        username: user.username,
        reputation_score: user.reputation_score,
        rank,
    }))
}

/// Get reputation history for a user
pub async fn get_reputation_history(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Query(params): Query<LeaderboardQuery>,
) -> Result<Json<ReputationHistoryResponse>, StatusCode> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page.saturating_sub(1)) * limit;

    // Get current score
    let current_score: i32 = sqlx::query_scalar("SELECT reputation_score FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .unwrap_or(0);

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM reputation_history WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    let entries = sqlx::query_as::<_, ReputationHistoryEntry>(
        "SELECT id, event_type, score_change::float8, new_score::float8, reason, created_at
         FROM reputation_history WHERE user_id = $1
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ReputationHistoryResponse {
        entries,
        total,
        page,
        limit,
        current_score,
    }))
}

/// List available badges (static)
pub async fn list_available_badges(
    State(_state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    Ok(Json(vec![
        serde_json::json!({"id": "first_analysis", "name": "First Analysis", "description": "Complete your first analysis", "tier": "bronze"}),
        serde_json::json!({"id": "ten_analyses", "name": "Veteran Analyst", "description": "Complete 10 analyses", "tier": "silver"}),
        serde_json::json!({"id": "high_accuracy", "name": "Sharp Eye", "description": "Achieve 90% accuracy over 20 analyses", "tier": "gold"}),
        serde_json::json!({"id": "bounty_hunter", "name": "Bounty Hunter", "description": "Win 5 bounties", "tier": "gold"}),
        serde_json::json!({"id": "top_ten", "name": "Elite", "description": "Reach the top 10 leaderboard", "tier": "platinum"}),
    ]))
}

/// Claim badge — check eligibility and award
pub async fn claim_badge(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let badge_id = payload
        .get("badge_id")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Validate badge exists in known set
    let (badge_name, required_count) = match badge_id {
        "first_analysis" => ("First Analysis", 1i64),
        "ten_analyses" => ("Veteran Analyst", 10),
        "high_accuracy" => ("Sharp Eye", 20),
        "bounty_hunter" => ("Bounty Hunter", 5),
        "top_ten" => ("Elite", 0), // Checked via leaderboard position
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // Check eligibility based on badge type
    let eligible = if badge_id == "top_ten" {
        // Check if user is in top 10 by reputation
        let rank: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) + 1 FROM users WHERE reputation_score > (SELECT COALESCE(reputation_score, 0) FROM users WHERE id = $1)"
        )
        .bind(claims.sub)
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(999);

        rank <= 10
    } else {
        // Count completed analyses for this user
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM analyses WHERE analyst_id = $1 AND status = 'completed'",
        )
        .bind(claims.sub)
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0);

        count >= required_count
    };

    if !eligible {
        return Ok(Json(serde_json::json!({
            "badge_id": badge_id,
            "eligible": false,
            "message": format!("You have not yet met the requirements for the '{}' badge", badge_name)
        })));
    }

    // Record the badge claim in reputation_history
    let _ = sqlx::query(
        r#"INSERT INTO reputation_history (id, user_id, event_type, score_change, new_score, reason, created_at)
           VALUES ($1, $2, 'badge_claimed', 0, COALESCE((SELECT reputation_score FROM users WHERE id = $2), 0), $3, NOW())"#
    )
    .bind(Uuid::new_v4())
    .bind(claims.sub)
    .bind(format!("Claimed badge: {badge_name}"))
    .execute(state.db.pool())
    .await;

    Ok(Json(serde_json::json!({
        "badge_id": badge_id,
        "badge_name": badge_name,
        "eligible": true,
        "claimed": true,
        "user_id": claims.sub,
        "message": format!("Badge '{}' claimed successfully!", badge_name)
    })))
}

/// Analyst standings from reputation-service.
///
/// That service owns accuracy, win streak, and earnings. The gateway only
/// attaches usernames from its own users table. If reputation-service is
/// down, the response falls back to reputation score alone so the page
/// still renders.
pub async fn get_standings(
    State(state): State<AppState>,
    Query(params): Query<LeaderboardQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100);
    let base = std::env::var("REPUTATION_SERVICE_URL")
        .unwrap_or_else(|_| "http://localhost:8087".to_string());
    let url = format!(
        "{}/api/v1/reputation/leaderboard?limit={limit}",
        base.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(rows) = body.get("leaderboard").and_then(|v| v.as_array()) {
                    let ids: Vec<Uuid> = rows
                        .iter()
                        .filter_map(|row| {
                            row.get("user_id")
                                .and_then(|v| v.as_str())
                                .and_then(|s| Uuid::parse_str(s).ok())
                        })
                        .collect();
                    let names = lookup_usernames(&state, &ids).await;
                    let analysts: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|row| {
                            let user_id = row.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
                            let username = Uuid::parse_str(user_id)
                                .ok()
                                .and_then(|id| names.get(&id).cloned())
                                .flatten()
                                .unwrap_or_else(|| {
                                    row.get("username")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("analyst")
                                        .to_string()
                                });
                            serde_json::json!({
                                "rank": row.get("rank"),
                                "userId": user_id,
                                "username": username,
                                "score": row.get("score"),
                                "accuracyRate": row.get("accuracy_rate"),
                                "totalSubmissions": row.get("total_submissions"),
                                "currentStreak": row.get("current_streak").cloned().unwrap_or(serde_json::json!(0)),
                                "totalEarned": row.get("total_earned").cloned().unwrap_or(serde_json::json!("0")),
                                "badgesCount": row.get("badges_count").cloned().unwrap_or(serde_json::json!(0)),
                            })
                        })
                        .collect();
                    return Ok(Json(serde_json::json!({
                        "source": "reputation-service",
                        "analysts": analysts,
                    })));
                }
            }
        }
    }

    tracing::warn!("reputation-service standings unavailable; using gateway scores");
    let rows = sqlx::query_as::<_, LeaderboardRow>(
        "SELECT id, username, reputation_score FROM users WHERE is_active = true
         ORDER BY reputation_score DESC LIMIT $1",
    )
    .bind(limit as i64)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error fetching standings fallback: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let analysts: Vec<serde_json::Value> = rows
        .into_iter()
        .enumerate()
        .map(|(i, row)| {
            serde_json::json!({
                "rank": i + 1,
                "userId": row.id,
                "username": row.username.unwrap_or_else(|| "analyst".to_string()),
                "score": row.reputation_score,
                "accuracyRate": null,
                "totalSubmissions": null,
                "currentStreak": null,
                "totalEarned": null,
                "badgesCount": null,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "source": "gateway",
        "analysts": analysts,
    })))
}

async fn lookup_usernames(
    state: &AppState,
    ids: &[Uuid],
) -> std::collections::HashMap<Uuid, Option<String>> {
    if ids.is_empty() {
        return std::collections::HashMap::new();
    }
    let rows = sqlx::query_as::<_, (Uuid, Option<String>)>(
        "SELECT id, username FROM users WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();
    rows.into_iter().collect()
}
