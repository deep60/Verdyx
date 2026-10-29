//! Browser-facing forwards onto consensus-service.
//!
//! The React app only talks to this gateway. Commit-reveal, disputes, and
//! delayed grades already live on consensus-service; these handlers pass the
//! JSON through and attach the signed-in user so a dispute has an initiator.

use axum::{
    body::Body,
    extract::Path,
    http::{Response, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

use crate::middleware::auth::Claims;

fn consensus_base_url() -> String {
    std::env::var("CONSENSUS_SERVICE_URL")
        .unwrap_or_else(|_| "http://localhost:8085".to_string())
}

async fn forward(
    method: reqwest::Method,
    path: String,
    body: Option<Value>,
    user_id: Option<Uuid>,
) -> Response<Body> {
    let url = format!("{}{}", consensus_base_url().trim_end_matches('/'), path);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("consensus client: {e}") })),
            )
                .into_response();
        }
    };

    let mut req = client.request(method, &url);
    if let Some(id) = user_id {
        req = req.header("x-user-id", id.to_string());
    }
    if let Some(body) = body {
        req = req.json(&body);
    }

    match req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let bytes = resp.bytes().await.unwrap_or_default();
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(bytes))
                .unwrap_or_else(|_| {
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({ "error": "empty consensus response" })),
                    )
                        .into_response()
                })
        }
        Err(e) => {
            tracing::warn!("consensus-service unreachable at {url}: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "consensus-service unavailable" })),
            )
                .into_response()
        }
    }
}

fn require_self(claims: &Claims, body: &Value) -> Result<(), Response<Body>> {
    let engine_id = body.get("engine_id").and_then(|v| v.as_str()).unwrap_or("");
    if engine_id != claims.sub.to_string() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "engine_id must be the signed-in user" })),
        )
            .into_response());
    }
    Ok(())
}

pub async fn get_phase(Path(bounty_id): Path<Uuid>) -> Response<Body> {
    forward(
        reqwest::Method::GET,
        format!("/api/v1/voting/bounty/{bounty_id}/phase"),
        None,
        None,
    )
    .await
}

pub async fn commit_vote(
    claims: Claims,
    Path(bounty_id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response<Body> {
    if let Err(resp) = require_self(&claims, &body) {
        return resp;
    }
    forward(
        reqwest::Method::POST,
        format!("/api/v1/voting/bounty/{bounty_id}/commit"),
        Some(body),
        Some(claims.sub),
    )
    .await
}

pub async fn reveal_vote(
    claims: Claims,
    Path(bounty_id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response<Body> {
    if let Err(resp) = require_self(&claims, &body) {
        return resp;
    }
    forward(
        reqwest::Method::POST,
        format!("/api/v1/voting/bounty/{bounty_id}/reveal"),
        Some(body),
        Some(claims.sub),
    )
    .await
}

pub async fn create_dispute(claims: Claims, Json(body): Json<Value>) -> Response<Body> {
    forward(
        reqwest::Method::POST,
        "/api/v1/disputes/create".to_string(),
        Some(body),
        Some(claims.sub),
    )
    .await
}

pub async fn get_bounty_disputes(Path(bounty_id): Path<Uuid>) -> Response<Body> {
    forward(
        reqwest::Method::GET,
        format!("/api/v1/disputes/bounty/{bounty_id}"),
        None,
        None,
    )
    .await
}

pub async fn get_grade(Path(bounty_id): Path<Uuid>) -> Response<Body> {
    forward(
        reqwest::Method::GET,
        format!("/api/v1/grades/{bounty_id}"),
        None,
        None,
    )
    .await
}
