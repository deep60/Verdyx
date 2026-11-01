use crate::models::*;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};
use std::sync::Arc;

/// Map a PaymentError to an HTTP status + JSON body.
fn map_err(e: PaymentError) -> (StatusCode, Json<Value>) {
    let status = match &e {
        PaymentError::ValidationError(_) => StatusCode::BAD_REQUEST,
        PaymentError::InsufficientBalance(_) => StatusCode::BAD_REQUEST,
        PaymentError::NotFound(_) => StatusCode::NOT_FOUND,
        PaymentError::AlreadyProcessed(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": e.to_string() })))
}

pub async fn deposit_bounty_reward(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DepositBountyRequest>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.record_deposit_intent(&payload).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => map_err(e),
    }
}

pub async fn distribute_bounty_reward(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DistributeBountyRequest>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.distribute_reward(&payload).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => map_err(e),
    }
}

pub async fn lock_stake(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LockStakeRequest>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.record_stake_lock(&payload).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => map_err(e),
    }
}

pub async fn unlock_stake(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UnlockStakeRequest>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.unlock_stake(payload.stake_id).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => map_err(e),
    }
}

pub async fn slash_stake(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SlashStakeRequest>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.slash_stake(&payload).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => map_err(e),
    }
}

pub async fn withdraw_funds(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WithdrawRequest>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.process_withdrawal(&payload).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => map_err(e),
    }
}

pub async fn get_balance(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.get_token_balance(&address).await {
        Ok(balance) => (
            StatusCode::OK,
            Json(json!({
                "address": address,
                "balance": format!("{}", balance),
                "token": "THREAT"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to get balance: {}", e)
            })),
        ),
    }
}

pub async fn get_transactions(
    State(_state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> (StatusCode, Json<Value>) {
    // Transaction history is populated by blockchain event sync
    (
        StatusCode::OK,
        Json(json!({
            "address": address,
            "transactions": [],
            "note": "Transaction history is populated by blockchain event sync"
        })),
    )
}

pub async fn get_transaction_status(
    State(state): State<Arc<AppState>>,
    Path(tx_hash): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.get_tx_receipt(&tx_hash).await {
        Ok(Some(receipt)) => {
            let status = if receipt.status() {
                "confirmed"
            } else {
                "failed"
            };
            (
                StatusCode::OK,
                Json(json!({
                    "tx_hash": tx_hash,
                    "status": status,
                    "block_number": receipt.block_number,
                    "gas_used": receipt.gas_used.to_string()
                })),
            )
        }
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "tx_hash": tx_hash,
                "status": "pending"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to get transaction status: {}", e)
            })),
        ),
    }
}

pub async fn estimate_gas(
    State(state): State<Arc<AppState>>,
    Json(_payload): Json<EstimateGasRequest>,
) -> (StatusCode, Json<Value>) {
    match state.payment_service.estimate_gas_for_transfer().await {
        Ok(gas) => (
            StatusCode::OK,
            Json(json!({
                "estimated_gas_cost": format!("{}", gas),
                "unit": "wei"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to estimate gas: {}", e)
            })),
        ),
    }
}
