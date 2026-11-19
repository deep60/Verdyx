// backend/bounty-manager/src/handlers/withdrawal.rs

use crate::handlers::bounty_crud::BountyManagerState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::Serialize;
use shared::types::ApiResponse;

/// Claimable balance for an address, mirroring the contract's pull-payment ledger.
///
/// After a bounty is resolved, rewards, returned stakes and refunds are *credited*
/// in the `BountyManager` contract rather than pushed. Users claim them by calling
/// `withdraw()` on-chain. This endpoint surfaces how much is currently claimable so
/// the frontend can prompt the user to withdraw.
#[derive(Debug, Serialize)]
pub struct ClaimableBalance {
    pub address: String,
    /// Amount claimable via `BountyManager.withdraw()`, in wei, as a decimal
    /// string (18-decimal amounts don't fit in a JSON number).
    pub claimable: String,
    pub has_claimable: bool,
}

/// GET /withdrawals/{address}
///
/// Returns the amount the given address can withdraw from the BountyManager
/// pull-payment ledger. Returns 503 if the service has no blockchain client
/// configured, and 400 for a malformed address.
pub async fn get_claimable(
    State(state): State<BountyManagerState>,
    Path(address): Path<String>,
) -> Result<Json<ApiResponse<ClaimableBalance>>, StatusCode> {
    let blockchain = state.blockchain.as_ref().ok_or_else(|| {
        tracing::warn!("Claimable balance requested but blockchain client is not configured");
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    let claimable = blockchain
        .get_pending_withdrawal(&address)
        .await
        .map_err(|e| {
            // An unparseable address is a client error; everything else is upstream.
            use crate::services::blockchain::BlockchainError;
            match e {
                BlockchainError::InvalidAddress(_) => StatusCode::BAD_REQUEST,
                other => {
                    tracing::error!(
                        "Failed to read pending withdrawal for {}: {}",
                        address,
                        other
                    );
                    StatusCode::BAD_GATEWAY
                }
            }
        })?;

    Ok(Json(ApiResponse::success(ClaimableBalance {
        address,
        has_claimable: !claimable.is_zero(),
        claimable: claimable.to_string(),
    })))
}
