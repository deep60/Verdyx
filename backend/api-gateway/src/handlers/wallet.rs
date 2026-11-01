use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Decimal;
use uuid::Uuid;

use crate::AppState;

/// Wallet balance response
#[derive(Debug, Serialize)]
pub struct WalletBalance {
    pub address: String,
    pub balance: String,
    pub staked: String,
    pub available: String,
    pub pending_rewards: String,
    pub total_earned: String,
    pub total_spent: String,
}

/// Transaction history query
#[derive(Debug, Deserialize)]
pub struct TransactionQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub transaction_type: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Transaction history response
#[derive(Debug, Serialize)]
pub struct TransactionListResponse {
    pub transactions: Vec<Transaction>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

/// Individual transaction
#[derive(Debug, Serialize)]
pub struct Transaction {
    pub id: Uuid,
    pub transaction_hash: Option<String>,
    pub transaction_type: String,
    pub amount: String,
    pub from_address: Option<String>,
    pub to_address: Option<String>,
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Withdraw request
#[derive(Debug, Deserialize)]
pub struct WithdrawRequest {
    pub amount: String,
    pub to_address: String,
}

/// Stake request
#[derive(Debug, Deserialize)]
pub struct StakeRequest {
    pub amount: String,
    pub bounty_id: Uuid,
}

/// Connect wallet request
#[derive(Debug, Deserialize)]
pub struct ConnectWalletRequest {
    pub address: String,
    pub signature: String,
    pub message: String,
}

/// Get wallet balance
///
/// GET /api/v1/wallet/balance
pub async fn get_balance(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
) -> Result<Json<WalletBalance>, StatusCode> {
    let wallet_address: String =
        sqlx::query_scalar::<_, Option<String>>("SELECT wallet_address FROM users WHERE id = $1")
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .ok()
            .flatten()
            .flatten()
            .unwrap_or_default();

    let on_chain_balance = if let Ok(addr) = wallet_address.parse::<alloy::primitives::Address>() {
        if !addr.is_zero() {
            state
                .blockchain
                .get_token_balance(addr)
                .await
                .map(|b| b.to_string())
                .unwrap_or_else(|_| "0".to_string())
        } else {
            "0".to_string()
        }
    } else {
        "0".to_string()
    };

    let staked: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(stake_amount)::text, '0') FROM bounty_submissions WHERE analyst_id = $1",
    )
    .bind(claims.sub)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or_else(|_| "0".to_string());

    let total_earned: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount)::text, '0') FROM payouts WHERE recipient_id = $1 AND status = 'completed'",
    )
    .bind(claims.sub)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or_else(|_| "0".to_string());

    let pending_rewards: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount)::text, '0') FROM payouts WHERE recipient_id = $1 AND status = 'pending'",
    )
    .bind(claims.sub)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or_else(|_| "0".to_string());

    let total_spent: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(reward_amount)::text, '0') FROM bounties WHERE creator_id = $1",
    )
    .bind(claims.sub)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or_else(|_| "0".to_string());

    Ok(Json(WalletBalance {
        address: wallet_address,
        balance: on_chain_balance.clone(),
        staked,
        available: on_chain_balance,
        pending_rewards,
        total_earned,
        total_spent,
    }))
}

/// Get wallet balance by address
///
/// GET /api/v1/wallet/balance/:address
pub async fn get_balance_by_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<WalletBalance>, StatusCode> {
    let balance_str = if let Ok(addr) = address.parse::<alloy::primitives::Address>() {
        if !addr.is_zero() {
            state
                .blockchain
                .get_token_balance(addr)
                .await
                .map(|b| b.to_string())
                .unwrap_or_else(|_| "0".to_string())
        } else {
            "0".to_string()
        }
    } else {
        "0".to_string()
    };

    Ok(Json(WalletBalance {
        address: address.clone(),
        balance: balance_str.clone(),
        staked: "0".to_string(),
        available: balance_str,
        pending_rewards: "0".to_string(),
        total_earned: "0".to_string(),
        total_spent: "0".to_string(),
    }))
}

/// Get transaction history
///
/// GET /api/v1/wallet/transactions
pub async fn get_transactions(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Query(params): Query<TransactionQuery>,
) -> Result<Json<TransactionListResponse>, StatusCode> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page.saturating_sub(1)) * limit;

    let wallet_address: Option<String> =
        sqlx::query_scalar::<_, Option<String>>("SELECT wallet_address FROM users WHERE id = $1")
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .ok()
            .flatten()
            .flatten();

    #[derive(sqlx::FromRow)]
    struct TxRow {
        id: Uuid,
        transaction_hash: Option<String>,
        transaction_type: String,
        amount: Decimal,
        status: String,
        created_at: DateTime<Utc>,
    }

    let rows = sqlx::query_as::<_, TxRow>(
        r#"
        SELECT id, tx_hash AS transaction_hash, 'payout' AS transaction_type, amount, status, created_at
        FROM payouts
        WHERE recipient_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(claims.sub)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payouts WHERE recipient_id = $1")
        .bind(claims.sub)
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0);

    let transactions = rows
        .into_iter()
        .map(|r| Transaction {
            id: r.id,
            transaction_hash: r.transaction_hash,
            transaction_type: r.transaction_type,
            amount: r.amount.to_string(),
            from_address: None,
            to_address: wallet_address.clone(),
            status: r.status,
            timestamp: r.created_at,
            metadata: serde_json::json!({}),
        })
        .collect();

    Ok(Json(TransactionListResponse {
        transactions,
        total: total as u64,
        page,
        limit,
    }))
}

/// Connect wallet — verify signature and link address to user
///
/// POST /api/v1/wallet/connect
pub async fn connect_wallet(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(payload): Json<ConnectWalletRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify signature: recover address from message + signature
    let signature = payload
        .signature
        .parse::<alloy::primitives::Signature>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let recovered = signature
        .recover_address_from_msg(payload.message.as_str())
        .map_err(|e| {
            tracing::warn!("Signature recovery failed: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    let recovered_addr = format!("{recovered:?}");

    // Check recovered address matches claimed address (case-insensitive)
    if recovered_addr.to_lowercase() != payload.address.to_lowercase() {
        tracing::warn!(
            "Signature mismatch: recovered={}, claimed={}",
            recovered_addr,
            payload.address
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Save wallet address to user record
    sqlx::query("UPDATE users SET wallet_address = $1, updated_at = NOW() WHERE id = $2")
        .bind(&payload.address)
        .bind(claims.sub)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to update wallet address: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "address": payload.address,
        "message": "Wallet connected successfully",
        "user_id": claims.sub
    })))
}

/// Disconnect wallet — remove address from user record
///
/// POST /api/v1/wallet/disconnect
pub async fn disconnect_wallet(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE users SET wallet_address = NULL, updated_at = NOW() WHERE id = $1")
        .bind(claims.sub)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to disconnect wallet: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::OK)
}

/// Withdraw funds
///
/// POST /api/v1/wallet/withdraw
pub async fn withdraw(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(payload): Json<WithdrawRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let amount_dec = payload
        .amount
        .parse::<Decimal>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if amount_dec <= Decimal::ZERO {
        return Err(StatusCode::BAD_REQUEST);
    }

    let _addr = payload
        .to_address
        .parse::<alloy::primitives::Address>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let payout_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payouts (id, recipient_id, amount, status, created_at) VALUES ($1, $2, $3, 'pending', NOW())",
    )
    .bind(payout_id)
    .bind(claims.sub)
    .bind(amount_dec)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to record withdrawal request: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(serde_json::json!({
        "id": payout_id,
        "amount": payload.amount,
        "to_address": payload.to_address,
        "message": "Withdrawal request queued for processing",
        "status": "pending"
    })))
}

/// Stake tokens for bounty analysis
/// NOTE: The contract requires the user to call ThreatToken.approve(bountyManagerAddr, amount)
/// from the frontend before calling submitAnalysis. This endpoint records the intent.
///
/// POST /api/v1/wallet/stake
pub async fn stake_tokens(
    State(_state): State<AppState>,
    Json(payload): Json<StakeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Staking happens during submitAnalysis — the contract does transferFrom.
    // Frontend must: 1) approve(), 2) POST /bounties/:id/submit
    Ok(Json(serde_json::json!({
        "message": "Staking is performed during analysis submission. Please approve tokens first, then submit analysis.",
        "bounty_id": payload.bounty_id,
        "amount": payload.amount,
        "steps": [
            "1. Call ThreatToken.approve(bountyManagerAddress, stakeAmount) from wallet",
            "2. POST /api/v1/bounties/{bounty_id}/submit with your analysis"
        ]
    })))
}

/// Unstake tokens
/// NOTE: Stakes are returned automatically during bounty resolution via resolveBounty
///
/// POST /api/v1/wallet/unstake/:bounty_id
pub async fn unstake_tokens(
    State(_state): State<AppState>,
    Path(bounty_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Stakes are returned during resolveBounty — no manual unstake needed
    Ok(Json(serde_json::json!({
        "message": "Stakes are returned automatically when the bounty is resolved",
        "bounty_id": bounty_id
    })))
}

/// Claim rewards
/// NOTE: Rewards are distributed during resolveBounty
///
/// POST /api/v1/wallet/claim-rewards
pub async fn claim_rewards(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Rewards are distributed during resolveBounty — handled by the contract
    Ok(Json(serde_json::json!({
        "message": "Rewards are distributed automatically during bounty resolution",
        "note": "Check your transaction history for reward distributions"
    })))
}
