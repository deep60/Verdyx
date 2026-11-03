//! Shared helpers for proxying user-identity operations to `user-service`.
//!
//! Under the microservices design, `user-service` owns user identity. The
//! gateway forwards the caller's bearer token and adapts user-service's
//! snake_case `UserPublic` shape into whatever the gateway endpoint returns.

use std::collections::HashMap;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;

/// Build a single-entry header map forwarding the incoming `Authorization`
/// header to a downstream service. `None` when the header is missing/!UTF-8.
pub fn bearer_map(headers: &HeaderMap) -> Option<HashMap<String, String>> {
    let token = crate::middleware::auth::request_token(headers)?;
    let mut map = HashMap::new();
    map.insert("Authorization".to_string(), format!("Bearer {token}"));
    Some(map)
}

/// user-service's public user identity (`GET /api/v1/auth/me`).
#[derive(Debug, Clone, Deserialize)]
pub struct UserIdentity {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub ethereum_address: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub kyc_status: String,
    #[serde(default)]
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
}

/// Fetch the authenticated user's identity from user-service.
/// On failure returns the downstream HTTP status code (or 502 if unreachable).
pub async fn fetch_identity(
    state: &AppState,
    auth_headers: HashMap<String, String>,
) -> Result<UserIdentity, u16> {
    let resp = state
        .proxy
        .get("user-service", "/api/v1/auth/me", Some(auth_headers))
        .await
        .map_err(|e| {
            tracing::error!("user-service unreachable: {e}");
            502u16
        })?;

    let code = resp.status().as_u16();
    if resp.status().is_success() {
        resp.json::<UserIdentity>().await.map_err(|e| {
            tracing::error!("invalid user-service identity response: {e}");
            502u16
        })
    } else {
        Err(code)
    }
}
