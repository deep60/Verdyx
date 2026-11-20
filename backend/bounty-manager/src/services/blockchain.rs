//! Read-only access to the chain.
//!
//! This service holds no signing key. Bounties are posted, staked on,
//! resolved and withdrawn from in each person's own wallet; the contract pays
//! rewards itself. What's left here are reads: claimable balances, token
//! balances and transaction receipts.
//!
//! The two contract reads are declared below with `sol!`, so the service needs
//! no ABI files at runtime.

use alloy::primitives::{Address, TxHash, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::sol;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

sol! {
    #[sol(rpc)]
    interface IBountyManager {
        function pendingWithdrawals(address account) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IThreatToken {
        function balanceOf(address account) external view returns (uint256);
    }
}

#[derive(Debug, Clone)]
pub struct BlockchainService {
    client: RootProvider,
    bounty_manager: Address,
    threat_token: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockchainError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Contract error: {0}")]
    ContractError(String),
}

impl From<anyhow::Error> for BlockchainError {
    fn from(e: anyhow::Error) -> Self {
        BlockchainError::ContractError(e.to_string())
    }
}

impl BlockchainService {
    pub fn new(
        rpc_url: &str,
        bounty_manager_address: &str,
        threat_token_address: &str,
    ) -> Result<Self, BlockchainError> {
        let url = rpc_url
            .parse()
            .map_err(|e| BlockchainError::ConnectionError(format!("bad RPC URL: {e}")))?;
        let client = RootProvider::new_http(url);

        let bm_addr: Address = bounty_manager_address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(bounty_manager_address.to_string()))?;

        let tt_addr: Address = threat_token_address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(threat_token_address.to_string()))?;

        Ok(Self {
            client,
            bounty_manager: bm_addr,
            threat_token: tt_addr,
        })
    }

    /// Read the amount an address can claim via `BountyManager.withdraw()`.
    ///
    /// Reflects the contract's pull-payment ledger (`pendingWithdrawals(address)`),
    /// letting the API surface claimable balances so users know to withdraw.
    pub async fn get_pending_withdrawal(&self, address: &str) -> Result<U256, BlockchainError> {
        let addr: Address = address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(address.to_string()))?;

        IBountyManager::new(self.bounty_manager, &self.client)
            .pendingWithdrawals(addr)
            .call()
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))
    }

    /// Verify a transaction by checking its receipt
    pub async fn verify_transaction(&self, tx_hash: &str) -> Result<bool, BlockchainError> {
        let hash: TxHash = tx_hash
            .parse()
            .map_err(|_| BlockchainError::ContractError("Invalid transaction hash".to_string()))?;

        let receipt = self
            .client
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?;

        match receipt {
            Some(r) => Ok(r.status()),
            None => Ok(false), // Transaction not yet mined
        }
    }

    /// Get transaction status from chain
    pub async fn get_transaction_status(
        &self,
        tx_hash: &str,
    ) -> Result<TransactionStatus, BlockchainError> {
        let hash: TxHash = tx_hash
            .parse()
            .map_err(|_| BlockchainError::ContractError("Invalid transaction hash".to_string()))?;

        let receipt = self
            .client
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?;

        match receipt {
            Some(r) => {
                if r.status() {
                    Ok(TransactionStatus::Confirmed)
                } else {
                    Ok(TransactionStatus::Failed)
                }
            }
            None => Ok(TransactionStatus::Pending),
        }
    }

    /// Get token balance for an address
    pub async fn get_balance(&self, address: &str) -> Result<U256, BlockchainError> {
        let addr: Address = address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(address.to_string()))?;

        IThreatToken::new(self.threat_token, &self.client)
            .balanceOf(addr)
            .call()
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))
    }

    /// Health check — verifies RPC connectivity
    pub async fn health_check(&self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.client.get_block_number()).await,
            Ok(Ok(_))
        )
    }
}
