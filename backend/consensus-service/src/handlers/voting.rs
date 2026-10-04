//! Commit-reveal voting endpoints.
//!
//! Two-phase voting: during the commit window a voter publishes only a hash of
//! their verdict, so nobody can read -- or copy -- anyone else's vote. Once the
//! window shuts they publish the plaintext and the hash is verified.

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

/// `GET /api/v1/voting/bounty/{bounty_id}/phase`
///
/// Which phase the bounty is in and when it ends. Deliberately reveals
/// counts only -- how many committed, how many revealed -- never any verdict.
pub async fn get_phase(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.consensus_service.voting_phase(bounty_id).await {
        Ok(status) => (StatusCode::OK, Json(json!(status))),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/voting/bounty/{bounty_id}/commit`
///
/// Register a commitment. The service learns nothing about the vote itself.
pub async fn commit_vote(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
    Json(payload): Json<CommitVoteRequest>,
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
        .commit_vote(bounty_id, &payload.engine_id, &payload.commitment)
        .await
    {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "bounty_id": bounty_id,
                "engine_id": payload.engine_id,
                "committed": true,
            })),
        ),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/voting/bounty/{bounty_id}/reveal`
///
/// Disclose a committed vote. Accepted only if it hashes to the stored
/// commitment, which is what proves it is the vote that was committed to.
pub async fn reveal_vote(
    State(state): State<Arc<AppState>>,
    Path(bounty_id): Path<String>,
    Json(payload): Json<RevealVoteRequest>,
) -> (StatusCode, Json<Value>) {
    let bounty_id = match parse_uuid(&bounty_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.consensus_service.reveal_vote(bounty_id, &payload).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "bounty_id": bounty_id,
                "engine_id": payload.engine_id,
                "revealed": true,
                "verdict": payload.verdict,
            })),
        ),
        Err(e) => err_response(e),
    }
}
