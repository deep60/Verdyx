//! Read-only access to the chain.
//!
//! This service holds no signing key. Bounties are posted, staked on,
//! resolved and withdrawn from in each person's own wallet; the contract pays
//! rewards itself. What's left here are reads: claimable balances, token
//! balances and transaction receipts.

use anyhow::Result;
use ethers::{
    abi::Abi,
    contract::Contract,
    providers::{Http, Middleware, Provider},
    types::{Address, H256, U256},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

type BlockchainClient = Provider<Http>;

#[derive(Debug, Clone)]
pub struct BlockchainService {
    client: Arc<BlockchainClient>,
    bounty_manager: Contract<BlockchainClient>,
    threat_token: Contract<BlockchainClient>,
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
        bounty_manager_abi: Abi,
        threat_token_abi: Abi,
    ) -> Result<Self, BlockchainError> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?
            .interval(Duration::from_millis(1000));

        let client = Arc::new(provider);

        let bm_addr: Address = bounty_manager_address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(bounty_manager_address.to_string()))?;

        let tt_addr: Address = threat_token_address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(threat_token_address.to_string()))?;

        let bounty_manager = Contract::new(bm_addr, bounty_manager_abi, Arc::clone(&client));
        let threat_token = Contract::new(tt_addr, threat_token_abi, Arc::clone(&client));

        Ok(Self {
            client,
            bounty_manager,
            threat_token,
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

        let amount: U256 = self
            .bounty_manager
            .method("pendingWithdrawals", (addr,))
            .map_err(|e| BlockchainError::ContractError(e.to_string()))?
            .call()
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?;

        Ok(amount)
    }

    /// Verify a transaction by checking its receipt
    pub async fn verify_transaction(&self, tx_hash: &str) -> Result<bool, BlockchainError> {
        let hash: H256 = tx_hash
            .parse()
            .map_err(|_| BlockchainError::ContractError("Invalid transaction hash".to_string()))?;

        let receipt = self
            .client
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?;

        match receipt {
            Some(r) => Ok(r.status == Some(1.into())),
            None => Ok(false), // Transaction not yet mined
        }
    }

    /// Get transaction status from chain
    pub async fn get_transaction_status(
        &self,
        tx_hash: &str,
    ) -> Result<TransactionStatus, BlockchainError> {
        let hash: H256 = tx_hash
            .parse()
            .map_err(|_| BlockchainError::ContractError("Invalid transaction hash".to_string()))?;

        let receipt = self
            .client
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?;

        match receipt {
            Some(r) => {
                if r.status == Some(1.into()) {
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

        let balance: U256 = self
            .threat_token
            .method("balanceOf", (addr,))
            .map_err(|e| BlockchainError::ContractError(e.to_string()))?
            .call()
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?;

        Ok(balance)
    }

    /// Health check — verifies RPC connectivity
    pub async fn health_check(&self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.client.get_block_number()).await,
            Ok(Ok(_))
        )
    }
}
