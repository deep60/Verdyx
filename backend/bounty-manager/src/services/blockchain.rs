// backend/bounty-manager/src/services/blockchain.rs

use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    json_abi::JsonAbi,
    primitives::{Address, TxHash, U256},
    providers::{DynProvider, Provider, RootProvider},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

type BlockchainClient = DynProvider;

#[derive(Debug, Clone)]
pub struct BlockchainService {
    client: BlockchainClient,
    signer_address: Address,
    bounty_manager: ContractInstance<BlockchainClient>,
    threat_token: ContractInstance<BlockchainClient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StakeTransaction {
    pub transaction_hash: String,
    pub from_address: String,
    pub amount: u64,
    pub bounty_id: Uuid,
    pub block_number: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PayoutTransaction {
    pub transaction_hash: String,
    pub to_address: String,
    pub amount: u64,
    pub bounty_id: Uuid,
    pub block_number: Option<u64>,
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
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        chain_id: u64,
        bounty_manager_address: &str,
        threat_token_address: &str,
        bounty_manager_abi: JsonAbi,
        threat_token_abi: JsonAbi,
    ) -> Result<Self, BlockchainError> {
        let url = rpc_url
            .parse::<alloy::transports::http::reqwest::Url>()
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?;
        let provider = RootProvider::new_http(url).erased();

        let signer = private_key
            .parse::<PrivateKeySigner>()
            .map_err(|e| BlockchainError::ConnectionError(format!("Invalid private key: {e}")))?;
        let signer_address = signer.address();

        let client = shared::evm::with_signer(provider, signer, chain_id);

        let bm_addr: Address = bounty_manager_address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(bounty_manager_address.to_string()))?;

        let tt_addr: Address = threat_token_address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(threat_token_address.to_string()))?;

        let bounty_manager =
            ContractInstance::new(bm_addr, client.clone(), Interface::new(bounty_manager_abi));
        let threat_token =
            ContractInstance::new(tt_addr, client.clone(), Interface::new(threat_token_abi));

        Ok(Self {
            client,
            signer_address,
            bounty_manager,
            threat_token,
        })
    }

    /// Send a contract call and wait for it to be mined.
    async fn send_and_wait(
        &self,
        contract: &ContractInstance<BlockchainClient>,
        function: &str,
        args: &[DynSolValue],
    ) -> Result<(TxHash, Option<TransactionReceipt>), BlockchainError> {
        let pending_tx = contract
            .function(function, args)
            .map_err(|e| BlockchainError::ContractError(e.to_string()))?
            .send()
            .await
            .map_err(|e| BlockchainError::TransactionFailed(e.to_string()))?;

        let tx_hash = *pending_tx.tx_hash();

        let receipt = shared::evm::wait_for_receipt(&self.client, tx_hash, 1)
            .await
            .map_err(|e| BlockchainError::TransactionFailed(e.to_string()))?;

        Ok((tx_hash, receipt))
    }

    /// Read a contract's single `uint256` return value.
    async fn read_uint(
        &self,
        contract: &ContractInstance<BlockchainClient>,
        function: &str,
        args: &[DynSolValue],
    ) -> Result<U256, BlockchainError> {
        contract
            .function(function, args)
            .map_err(|e| BlockchainError::ContractError(e.to_string()))?
            .call()
            .await
            .map_err(|e| BlockchainError::ConnectionError(e.to_string()))?
            .first()
            .and_then(DynSolValue::as_uint)
            .map(|(value, _)| value)
            .ok_or_else(|| BlockchainError::ContractError(format!("{function} returned no uint")))
    }

    /// Approve and stake tokens for a bounty analysis submission
    /// Calls ThreatToken.approve(bountyManagerAddress, amount)
    pub async fn create_stake_transaction(
        &self,
        _from_address: &str,
        bounty_id: Uuid,
        amount: u64,
    ) -> Result<StakeTransaction, BlockchainError> {
        let amount_u256 = U256::from(amount);

        // Approve BountyManager to spend tokens
        let bm_address = *self.bounty_manager.address();
        let (tx_hash, receipt) = self
            .send_and_wait(
                &self.threat_token,
                "approve",
                &[
                    DynSolValue::Address(bm_address),
                    DynSolValue::Uint(amount_u256, 256),
                ],
            )
            .await?;

        let block_number = receipt.and_then(|r| r.block_number);

        Ok(StakeTransaction {
            transaction_hash: format!("{tx_hash:?}"),
            from_address: format!("{:?}", self.signer_address),
            amount,
            bounty_id,
            block_number,
        })
    }

    /// Distribute payout: Transfer tokens to an analyst
    /// Calls ThreatToken.transfer(to, amount)
    pub async fn create_payout_transaction(
        &self,
        to_address: &str,
        bounty_id: Uuid,
        amount: u64,
    ) -> Result<PayoutTransaction, BlockchainError> {
        let to: Address = to_address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(to_address.to_string()))?;

        let amount_u256 = U256::from(amount);

        let (tx_hash, receipt) = self
            .send_and_wait(
                &self.threat_token,
                "transfer",
                &[
                    DynSolValue::Address(to),
                    DynSolValue::Uint(amount_u256, 256),
                ],
            )
            .await?;

        let block_number = receipt.and_then(|r| r.block_number);

        Ok(PayoutTransaction {
            transaction_hash: format!("{tx_hash:?}"),
            to_address: to_address.to_string(),
            amount,
            bounty_id,
            block_number,
        })
    }

    /// Trigger on-chain resolution of a bounty.
    ///
    /// Calls `BountyManager.resolveBounty(uint256)`. Resolution is decoupled from
    /// submission in the contract, so a keeper (this service) must call it once the
    /// bounty is eligible (deadline passed or enough analyses). The contract enforces
    /// eligibility with its own `require`s, so a premature/duplicate call reverts and
    /// surfaces here as `TransactionFailed`.
    pub async fn resolve_bounty(&self, on_chain_bounty_id: u64) -> Result<String, BlockchainError> {
        let bounty_id = U256::from(on_chain_bounty_id);

        // Waits for the receipt so callers know the resolution actually mined.
        let (tx_hash, _) = self
            .send_and_wait(
                &self.bounty_manager,
                "resolveBounty",
                &[DynSolValue::Uint(bounty_id, 256)],
            )
            .await?;

        Ok(format!("{tx_hash:?}"))
    }

    /// Read the amount an address can claim via `BountyManager.withdraw()`.
    ///
    /// Reflects the contract's pull-payment ledger (`pendingWithdrawals(address)`),
    /// letting the API surface claimable balances so users know to withdraw.
    pub async fn get_pending_withdrawal(&self, address: &str) -> Result<u64, BlockchainError> {
        let addr: Address = address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(address.to_string()))?;

        let amount = self
            .read_uint(
                &self.bounty_manager,
                "pendingWithdrawals",
                &[DynSolValue::Address(addr)],
            )
            .await?;

        u64::try_from(amount).map_err(|e| BlockchainError::ContractError(e.to_string()))
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
    pub async fn get_balance(&self, address: &str) -> Result<u64, BlockchainError> {
        let addr: Address = address
            .parse()
            .map_err(|_| BlockchainError::InvalidAddress(address.to_string()))?;

        let balance = self
            .read_uint(
                &self.threat_token,
                "balanceOf",
                &[DynSolValue::Address(addr)],
            )
            .await?;

        u64::try_from(balance).map_err(|e| BlockchainError::ContractError(e.to_string()))
    }

    /// Expose the client for use by sync services
    pub fn get_client(&self) -> &BlockchainClient {
        &self.client
    }

    /// Health check — verifies RPC connectivity
    pub async fn health_check(&self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.client.get_block_number()).await,
            Ok(Ok(_))
        )
    }
}
