use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

/// Webhook configuration
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Webhook {
    pub id: Uuid,
    pub user_id: Uuid,
    pub url: String,
    pub events: Vec<String>,
    pub secret: Option<String>,
    pub is_active: bool,
    pub description: Option<String>,
    pub headers: Option<serde_json::Value>,
    pub retry_max_attempts: Option<i32>,
    pub retry_interval_seconds: Option<i32>,
    pub exponential_backoff: Option<bool>,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Register webhook request
#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
    pub description: Option<String>,
    pub headers: Option<serde_json::Value>,
}

/// Update webhook request
#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub is_active: Option<bool>,
    pub description: Option<String>,
    pub headers: Option<serde_json::Value>,
}

/// Webhook delivery log
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub attempt_number: Option<i32>,
    pub triggered_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Webhook list query
#[derive(Debug, Deserialize)]
pub struct WebhookQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Webhook list response
#[derive(Debug, Serialize)]
pub struct WebhookListResponse {
    pub webhooks: Vec<Webhook>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
}

/// Delivery list response
#[derive(Debug, Serialize)]
pub struct DeliveryListResponse {
    pub deliveries: Vec<WebhookDelivery>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
}

/// Delivery query
#[derive(Debug, Deserialize)]
pub struct DeliveryQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Test webhook request
#[derive(Debug, Deserialize)]
pub struct TestWebhookRequest {
    pub event_type: String,
    pub sample_payload: Option<serde_json::Value>,
}

/// Available webhook events
#[derive(Debug, Serialize)]
pub struct WebhookEvent {
    pub name: String,
    pub description: String,
    pub category: String,
}

fn is_safe_webhook_url(raw_url: &str) -> bool {
    let parsed = match reqwest::Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let lower = host.to_lowercase();
    if lower == "localhost"
        || lower == "0.0.0.0"
        || lower == "::1"
        || lower.starts_with("127.")
        || lower.starts_with("10.")
        || lower.starts_with("192.168.")
        || lower.starts_with("169.254.")
        || lower.ends_with(".internal")
        || lower.ends_with(".local")
    {
        return false;
    }
    true
}

// ─── Handlers ───

/// Create a webhook
pub async fn create_webhook(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(payload): Json<RegisterWebhookRequest>,
) -> Result<Json<Webhook>, StatusCode> {
    if !is_safe_webhook_url(&payload.url) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate a random secret for HMAC signing
    let secret = format!(
        "whsec_{}",
        uuid::Uuid::new_v4().to_string().replace("-", "")
    );
    let webhook_id = Uuid::new_v4();
    let user_id = claims.sub;

    let webhook = sqlx::query_as::<_, Webhook>(
        "INSERT INTO webhooks (id, user_id, url, events, secret, description, headers)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *",
    )
    .bind(webhook_id)
    .bind(user_id)
    .bind(&payload.url)
    .bind(&payload.events)
    .bind(&secret)
    .bind(&payload.description)
    .bind(&payload.headers)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error creating webhook: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(webhook))
}

/// List user's webhooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Query(params): Query<WebhookQuery>,
) -> Result<Json<WebhookListResponse>, StatusCode> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page.saturating_sub(1)) * limit;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE user_id = $1")
        .bind(claims.sub)
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0);

    let webhooks = sqlx::query_as::<_, Webhook>(
        "SELECT * FROM webhooks WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(claims.sub)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error listing webhooks: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(WebhookListResponse {
        webhooks,
        total,
        page,
        limit,
    }))
}

/// Get webhook by ID
pub async fn get_webhook(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(webhook_id): Path<Uuid>,
) -> Result<Json<Webhook>, StatusCode> {
    let webhook =
        sqlx::query_as::<_, Webhook>("SELECT * FROM webhooks WHERE id = $1 AND user_id = $2")
            .bind(webhook_id)
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(webhook))
}

/// Update webhook
pub async fn update_webhook(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(webhook_id): Path<Uuid>,
    Json(payload): Json<UpdateWebhookRequest>,
) -> Result<Json<Webhook>, StatusCode> {
    if let Some(ref u) = payload.url {
        if !is_safe_webhook_url(u) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Build dynamic UPDATE query
    let webhook = sqlx::query_as::<_, Webhook>(
        "UPDATE webhooks SET
            url = COALESCE($2, url),
            events = COALESCE($3, events),
            is_active = COALESCE($4, is_active),
            description = COALESCE($5, description),
            headers = COALESCE($6, headers),
            updated_at = NOW()
         WHERE id = $1 AND user_id = $7
         RETURNING *",
    )
    .bind(webhook_id)
    .bind(&payload.url)
    .bind(&payload.events)
    .bind(payload.is_active)
    .bind(&payload.description)
    .bind(&payload.headers)
    .bind(claims.sub)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error updating webhook: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(webhook))
}

/// Delete webhook
pub async fn delete_webhook(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(webhook_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND user_id = $2")
        .bind(webhook_id)
        .bind(claims.sub)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("DB error deleting webhook: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Test webhook by sending a sample event
pub async fn test_webhook(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(webhook_id): Path<Uuid>,
    Json(payload): Json<TestWebhookRequest>,
) -> Result<Json<WebhookDelivery>, StatusCode> {
    // Verify ownership of the webhook
    let webhook =
        sqlx::query_as::<_, Webhook>("SELECT * FROM webhooks WHERE id = $1 AND user_id = $2")
            .bind(webhook_id)
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?;

    if !is_safe_webhook_url(&webhook.url) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let test_payload = payload.sample_payload.unwrap_or(serde_json::json!({
        "event": payload.event_type,
        "test": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }));

    // Send HTTP POST to webhook URL
    let client = reqwest::Client::new();
    let result = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Event", &payload.event_type)
        .json(&test_payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let (status, status_code, response_body, error_message) = match result {
        Ok(resp) => {
            let code = resp.status().as_u16() as i16;
            let body = resp.text().await.unwrap_or_default();
            if (200..300).contains(&code) {
                ("success".to_string(), Some(code), Some(body), None)
            } else {
                (
                    "failed".to_string(),
                    Some(code),
                    Some(body),
                    Some(format!("HTTP {code}")),
                )
            }
        }
        Err(e) => ("failed".to_string(), None, None, Some(e.to_string())),
    };

    // Record delivery
    let delivery = sqlx::query_as::<_, WebhookDelivery>(
        "INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, status_code, response_body, error_message, attempt_number, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, NOW())
         RETURNING *"
    )
    .bind(Uuid::new_v4())
    .bind(webhook_id)
    .bind(&payload.event_type)
    .bind(&test_payload)
    .bind(&status)
    .bind(status_code)
    .bind(&response_body)
    .bind(&error_message)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error recording delivery: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(delivery))
}

/// Get webhook deliveries
pub async fn get_webhook_deliveries(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(webhook_id): Path<Uuid>,
    Query(params): Query<DeliveryQuery>,
) -> Result<Json<DeliveryListResponse>, StatusCode> {
    // Verify ownership of the webhook first
    let owns: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM webhooks WHERE id = $1 AND user_id = $2")
            .bind(webhook_id)
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if owns.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page.saturating_sub(1)) * limit;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = $1")
            .bind(webhook_id)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    let deliveries = sqlx::query_as::<_, WebhookDelivery>(
        "SELECT * FROM webhook_deliveries WHERE webhook_id = $1
         ORDER BY triggered_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(webhook_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(DeliveryListResponse {
        deliveries,
        total,
        page,
        limit,
    }))
}

/// List available webhook events
pub async fn list_available_events(
    State(_state): State<AppState>,
) -> Result<Json<Vec<WebhookEvent>>, StatusCode> {
    Ok(Json(vec![
        WebhookEvent {
            name: "analysis.completed".into(),
            description: "Analysis completed".into(),
            category: "analysis".into(),
        },
        WebhookEvent {
            name: "bounty.created".into(),
            description: "New bounty created".into(),
            category: "bounty".into(),
        },
        WebhookEvent {
            name: "bounty.submission".into(),
            description: "Analysis submitted to bounty".into(),
            category: "bounty".into(),
        },
        WebhookEvent {
            name: "bounty.finalized".into(),
            description: "Bounty resolved with winner".into(),
            category: "bounty".into(),
        },
        WebhookEvent {
            name: "transaction.confirmed".into(),
            description: "Blockchain tx confirmed".into(),
            category: "transaction".into(),
        },
        WebhookEvent {
            name: "reputation.updated".into(),
            description: "Reputation score changed".into(),
            category: "reputation".into(),
        },
    ]))
}
