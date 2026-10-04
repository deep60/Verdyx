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

/// Map a ConsensusError to an HTTP status + JSON body.
fn err_response(e: ConsensusError) -> (StatusCode, Json<Value>) {
    let status = match &e {
        ConsensusError::NotFound(_) => StatusCode::NOT_FOUND,
        ConsensusError::ValidationError(_) => StatusCode::BAD_REQUEST,
        ConsensusError::InsufficientSubmissions { .. } => StatusCode::CONFLICT,
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

pub async fn get_bounty_consensus(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.consensus_service.get_stored(bounty_id).await {
        Ok(Some(resp)) => (StatusCode::OK, Json(json!(resp))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no consensus for bounty" })),
        ),
        Err(e) => err_response(e),
    }
}

pub async fn calculate_consensus(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
    Json(payload): Json<ConsensusCalculationRequest>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let _ = payload.force_recalculate; // recalculation is always fresh
    match state
        .consensus_service
        .calculate_and_store(bounty_id, false)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => err_response(e),
    }
}

pub async fn get_submission_consensus(
    State(state): State<Arc<AppState>>,
    Path(submission_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    // A submission belongs to a bounty; we treat the path id as bounty id here
    // since votes are aggregated per bounty.
    let id = match parse_uuid(&submission_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.consensus_service.get_stored(id).await {
        Ok(Some(resp)) => (StatusCode::OK, Json(json!(resp))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no consensus found" })),
        ),
        Err(e) => err_response(e),
    }
}

pub async fn get_consensus_stats(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.consensus_service.load_votes(bounty_id).await {
        Ok(votes) => (
            StatusCode::OK,
            Json(json!({
                "bounty_id": bounty_id,
                "total_votes": votes.len(),
                "engines": votes.iter().map(|v| v.engine_id.clone()).collect::<Vec<_>>(),
            })),
        ),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/consensus/bounty/{bounty_id}/vote`
///
/// Records one engine's or analyst's verdict for a bounty. This is how votes
/// enter consensus-service; without it the aggregator has nothing to aggregate.
///
/// `sample_hash` should always be supplied. It is what lets the regrader
/// re-scan the right artifact after the grading delay -- a vote without one
/// still counts toward consensus but leaves the bounty ungradable.
pub async fn record_vote(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
    Json(payload): Json<RecordVoteRequest>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    if payload.engine_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "engine_id must not be empty" })),
        );
    }

    match state
        .consensus_service
        .record_vote(
            bounty_id,
            &payload.engine_id,
            &payload.verdict,
            payload.confidence,
            payload.reputation_score,
            payload.sample_hash.as_deref(),
        )
        .await
    {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "bounty_id": bounty_id,
                "engine_id": payload.engine_id,
                "recorded": true,
                "gradable": payload.sample_hash.is_some(),
            })),
        ),
        Err(e) => err_response(e),
    }
}
