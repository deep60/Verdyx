use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::services::siem;
use crate::AppState;

/// A refusal with a reason the website can show.
type ApiError = (StatusCode, Json<serde_json::Value>);

fn bad(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg.into() })),
    )
}

fn internal(e: sqlx::Error) -> ApiError {
    tracing::error!("DB error in webhooks: {}", e);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": "something went wrong" })),
    )
}

fn not_found() -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "no such destination" })),
    )
}

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
    /// `webhook`, `splunk` or `sentinel`.
    pub kind: String,
    /// Destination settings (see `services::siem::validate`).
    pub config: serde_json::Value,
    /// Sealed; never sent back.
    #[serde(skip_serializing)]
    pub credential: Option<String>,
    pub has_credential: bool,
}

/// Register webhook request
#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
    pub description: Option<String>,
    pub headers: Option<serde_json::Value>,
    /// `webhook` (default), `splunk` or `sentinel`.
    pub kind: Option<String>,
    pub config: Option<serde_json::Value>,
    /// The HEC token (Splunk) or the app's client key (Sentinel).
    pub credential: Option<String>,
}

/// Update webhook request
#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub is_active: Option<bool>,
    pub description: Option<String>,
    pub headers: Option<serde_json::Value>,
    /// Replaces the settings when given.
    pub config: Option<serde_json::Value>,
    /// Replaces the stored credential when given and not empty.
    pub credential: Option<String>,
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

/// See `services::webhook_delivery::check_url`; hosts are checked again,
/// by resolved address, when a delivery connects.
fn is_safe_webhook_url(raw_url: &str) -> bool {
    crate::services::webhook_delivery::check_url(raw_url).is_ok()
}

/// Every event must be one that's delivered (or `*` for all).
fn events_ok(events: &[String]) -> bool {
    !events.is_empty()
        && events.len() <= 20
        && events.iter().all(|e| shared::webhooks::is_known_event(e))
}

// ─── Handlers ───

/// Create a webhook
pub async fn create_webhook(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(payload): Json<RegisterWebhookRequest>,
) -> Result<Json<Webhook>, ApiError> {
    let kind = payload.kind.as_deref().unwrap_or(siem::KIND_WEBHOOK);
    if !siem::is_kind(kind) {
        return Err(bad("unknown destination type"));
    }
    if !events_ok(&payload.events) {
        return Err(bad("choose at least one event"));
    }
    let credential = payload
        .credential
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    if credential.is_some_and(|c| !siem::credential_ok(c)) {
        return Err(bad("that credential doesn't look right"));
    }
    let config = siem::validate(
        kind,
        &payload.url,
        payload.config.as_ref().unwrap_or(&serde_json::Value::Null),
        credential.is_some(),
    )
    .map_err(bad)?;
    let sealed = match kind {
        siem::KIND_WEBHOOK => None,
        _ => credential
            .map(|c| siem::CredentialKey::from_config(&state.config.security.jwt_secret).seal(c)),
    };

    // Generate a random secret for HMAC signing
    let secret = format!(
        "whsec_{}",
        uuid::Uuid::new_v4().to_string().replace("-", "")
    );
    let webhook_id = Uuid::new_v4();
    let user_id = claims.sub;

    let webhook = sqlx::query_as::<_, Webhook>(
        "INSERT INTO webhooks (id, user_id, url, events, secret, description, headers, kind, config, credential)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *",
    )
    .bind(webhook_id)
    .bind(user_id)
    .bind(&payload.url)
    .bind(&payload.events)
    .bind(&secret)
    .bind(&payload.description)
    .bind(if kind == siem::KIND_WEBHOOK {
        payload.headers.clone()
    } else {
        None
    })
    .bind(kind)
    .bind(&config)
    .bind(&sealed)
    .fetch_one(state.db.pool())
    .await
    .map_err(internal)?;

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
) -> Result<Json<Webhook>, ApiError> {
    let current =
        sqlx::query_as::<_, Webhook>("SELECT * FROM webhooks WHERE id = $1 AND user_id = $2")
            .bind(webhook_id)
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .map_err(internal)?
            .ok_or_else(not_found)?;
    if let Some(ref events) = payload.events {
        if !events_ok(events) {
            return Err(bad("choose at least one event"));
        }
    }
    let credential = payload
        .credential
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    if credential.is_some_and(|c| !siem::credential_ok(c)) {
        return Err(bad("that credential doesn't look right"));
    }
    // Check the destination as it will be after the change.
    let url = payload.url.clone().unwrap_or_else(|| current.url.clone());
    let config = siem::validate(
        &current.kind,
        &url,
        payload.config.as_ref().unwrap_or(&current.config),
        credential.is_some() || current.has_credential,
    )
    .map_err(bad)?;
    let sealed = match current.kind.as_str() {
        siem::KIND_WEBHOOK => None,
        _ => credential
            .map(|c| siem::CredentialKey::from_config(&state.config.security.jwt_secret).seal(c)),
    };

    // Build dynamic UPDATE query
    let webhook = sqlx::query_as::<_, Webhook>(
        "UPDATE webhooks SET
            url = COALESCE($2, url),
            events = COALESCE($3, events),
            is_active = COALESCE($4, is_active),
            description = COALESCE($5, description),
            headers = COALESCE($6, headers),
            config = $8,
            credential = COALESCE($9, credential),
            updated_at = NOW()
         WHERE id = $1 AND user_id = $7
         RETURNING *",
    )
    .bind(webhook_id)
    .bind(&payload.url)
    .bind(&payload.events)
    .bind(payload.is_active)
    .bind(&payload.description)
    .bind(if current.kind == siem::KIND_WEBHOOK {
        payload.headers.clone()
    } else {
        None
    })
    .bind(claims.sub)
    .bind(&config)
    .bind(&sealed)
    .fetch_optional(state.db.pool())
    .await
    .map_err(internal)?
    .ok_or_else(not_found)?;

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

    if payload.event_type == shared::webhooks::ALL
        || !shared::webhooks::is_known_event(&payload.event_type)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let data = payload.sample_payload.unwrap_or(serde_json::json!({
        "test": true,
        "message": "This is a test delivery from Verdyx."
    }));

    use crate::services::webhook_delivery as wd;
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let key = siem::CredentialKey::from_config(&state.config.security.jwt_secret);
    let target = wd::Target {
        url: webhook.url.clone(),
        secret: webhook.secret.clone(),
        headers: webhook.headers.clone(),
        kind: webhook.kind.clone(),
        config: webhook.config.clone(),
        credential: webhook.credential.as_deref().and_then(|c| key.open(c)),
        sentinel_login: None,
    };
    let result = wd::send(
        &wd::client(false),
        &target,
        id,
        &payload.event_type,
        now,
        &data,
        &wd::web_url(),
    )
    .await;

    // Record delivery
    let delivery = sqlx::query_as::<_, WebhookDelivery>(
        "INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, status_code, response_body, error_message, attempt_number, triggered_at, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, NOW())
         RETURNING *"
    )
    .bind(id)
    .bind(webhook_id)
    .bind(&payload.event_type)
    .bind(&data)
    .bind(if result.ok { "success" } else { "failed" })
    .bind(result.status_code)
    .bind(&result.response_body)
    .bind(&result.error)
    .bind(now)
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
    Ok(Json(
        shared::webhooks::EVENTS
            .iter()
            .map(|(name, description)| WebhookEvent {
                name: (*name).into(),
                description: (*description).into(),
                category: name.split('.').next().unwrap_or("other").into(),
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_credential_is_never_serialised() {
        let now = Utc::now();
        let w = Webhook {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            url: "https://splunk.example.com:8088".into(),
            events: vec!["*".into()],
            secret: None,
            is_active: true,
            description: None,
            headers: None,
            retry_max_attempts: None,
            retry_interval_seconds: None,
            exponential_backoff: None,
            last_triggered_at: None,
            created_at: now,
            updated_at: now,
            kind: "splunk".into(),
            config: serde_json::json!({"index": "sec"}),
            credential: Some("v1:sealed".into()),
            has_credential: true,
        };
        let v = serde_json::to_value(&w).unwrap();
        assert!(v.get("credential").is_none());
        assert_eq!(v["has_credential"], true);
        assert_eq!(v["kind"], "splunk");
        assert!(!v.to_string().contains("v1:sealed"));
    }
}
