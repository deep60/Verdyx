//! Read and submit verdict grades.
//!
//! The regrader worker writes grades on its own schedule; these endpoints exist
//! so a retro-scan job or a human can supply one directly, and so the "how
//! often was the crowd wrong?" number is queryable.

use crate::models::*;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

fn err_response(e: ConsensusError) -> (StatusCode, Json<Value>) {
    let status = match &e {
        ConsensusError::NotFound(_) => StatusCode::NOT_FOUND,
        ConsensusError::ValidationError(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": e.to_string() })))
}

fn parse_uuid(s: &str) -> Result<Uuid, (StatusCode, Json<Value>)> {
    Uuid::parse_str(s).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid id" })),
        )
    })
}

/// `GET /api/v1/grades/{bounty_id}` -- the current grade, if graded.
pub async fn get_grade(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.consensus_service.get_grade(bounty_id).await {
        Ok(Some(g)) => (StatusCode::OK, Json(json!(g))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "bounty has not been graded yet" })),
        ),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/grades/{bounty_id}` -- supply a grade from outside the worker
/// (a retro-scan hit, an upheld dispute, or an admin correction).
///
/// The original verdict is never taken from the request body; it is read from
/// the stored consensus result, so a caller cannot record a grade against a
/// verdict the system never reached.
pub async fn submit_grade(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
    Json(payload): Json<SubmitGradeRequest>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state
        .consensus_service
        .record_grade(
            bounty_id,
            &payload.graded_verdict,
            payload.grade_source,
            payload.sample_hash.as_deref(),
            payload.notes.as_deref(),
        )
        .await
    {
        Ok(g) => (StatusCode::OK, Json(json!(g))),
        Err(e) => err_response(e),
    }
}

/// `GET /api/v1/grading/stats` -- how often consensus was overturned.
pub async fn get_stats(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    match state.consensus_service.grading_stats().await {
        Ok(s) => (StatusCode::OK, Json(json!(s))),
        Err(e) => err_response(e),
    }
}
