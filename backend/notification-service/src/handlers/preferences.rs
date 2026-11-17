use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use crate::AppState;

fn user_from_headers(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok())
}

#[derive(Debug, Deserialize)]
pub struct UpdatePreferencesRequest {
    pub email_enabled: Option<bool>,
    pub push_enabled: Option<bool>,
    pub webhook_enabled: Option<bool>,
    pub websocket_enabled: Option<bool>,
    pub email_address: Option<String>,
    pub push_token: Option<String>,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
}

pub async fn get_preferences(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(user_id) = user_from_headers(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing x-user-id" })),
        );
    };

    let row = sqlx::query_as::<_, PreferencesRow>(
        r#"
        SELECT user_id, email_enabled, push_enabled, webhook_enabled, websocket_enabled,
               email_address, push_token, webhook_url
        FROM notification_preferences
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&state.db_pool)
    .await;

    match row {
        Ok(Some(p)) => (StatusCode::OK, Json(json!({ "preferences": p }))),
        // Return defaults if none stored yet.
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "preferences": {
                    "user_id": user_id,
                    "email_enabled": true,
                    "push_enabled": true,
                    "webhook_enabled": false,
                    "websocket_enabled": true,
                }
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

pub async fn update_preferences(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UpdatePreferencesRequest>,
) -> (StatusCode, Json<Value>) {
    let Some(user_id) = user_from_headers(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing x-user-id" })),
        );
    };

    // Upsert with COALESCE so omitted fields keep their stored value.
    let res = sqlx::query(
        r#"
        INSERT INTO notification_preferences
            (user_id, email_enabled, push_enabled, webhook_enabled, websocket_enabled,
             email_address, push_token, webhook_url, webhook_secret)
        VALUES ($1,
                COALESCE($2, true),
                COALESCE($3, true),
                COALESCE($4, false),
                COALESCE($5, true),
                $6, $7, $8, $9)
        ON CONFLICT (user_id) DO UPDATE SET
            email_enabled = COALESCE($2, notification_preferences.email_enabled),
            push_enabled = COALESCE($3, notification_preferences.push_enabled),
            webhook_enabled = COALESCE($4, notification_preferences.webhook_enabled),
            websocket_enabled = COALESCE($5, notification_preferences.websocket_enabled),
            email_address = COALESCE($6, notification_preferences.email_address),
            push_token = COALESCE($7, notification_preferences.push_token),
            webhook_url = COALESCE($8, notification_preferences.webhook_url),
            webhook_secret = COALESCE($9, notification_preferences.webhook_secret),
            updated_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(req.email_enabled)
    .bind(req.push_enabled)
    .bind(req.webhook_enabled)
    .bind(req.websocket_enabled)
    .bind(req.email_address)
    .bind(req.push_token)
    .bind(req.webhook_url)
    .bind(req.webhook_secret)
    .execute(&state.db_pool)
    .await;

    match res {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "preferences updated" })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct PreferencesRow {
    user_id: Uuid,
    email_enabled: bool,
    push_enabled: bool,
    webhook_enabled: bool,
    websocket_enabled: bool,
    email_address: Option<String>,
    push_token: Option<String>,
    webhook_url: Option<String>,
}

/// `DELETE /api/v1/notifications/user-data`: removes a deleted account's
/// preferences (email address, webhook URL and signing secret) and its
/// history. Called by the gateway, which sets `x-user-id`.
pub async fn delete_user_data(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(user_id) = user_from_headers(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing x-user-id" })),
        );
    };
    let result = async {
        let mut tx = state.db_pool.begin().await?;
        let history = sqlx::query("DELETE FROM notification_history WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        let prefs = sqlx::query("DELETE FROM notification_preferences WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok::<_, sqlx::Error>((history, prefs))
    }
    .await;
    match result {
        Ok((history, prefs)) => (
            StatusCode::OK,
            Json(json!({ "deleted": { "history": history, "preferences": prefs } })),
        ),
        Err(e) => {
            tracing::error!("Failed to delete notification data for {}: {}", user_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not delete notification data" })),
            )
        }
    }
}
