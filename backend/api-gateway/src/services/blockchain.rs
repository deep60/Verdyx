//! Handles all blockchain interactions including:
//! - Smart contract deployments and interactions
//! - Bounty creation and management
//! - Token transfers and staking
//! - Reputation system updates
//! - Transaction monitoring

use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    json_abi::JsonAbi as Abi, //(Abi - Application Binary Interface)
    primitives::{Address, TxHash, U256},
    providers::{DynProvider, Provider, RootProvider},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::config;
use crate::models::TransactionStatus;

/// Blockchain client wrapper
type BlockchainClient = DynProvider;
type Contract = ContractInstance<BlockchainClient>;

// Emitted by BountyManager.createBounty; carries the on-chain bounty ID.
sol! {
    event BountyCreated(
        uint256 indexed bountyId,
        address indexed creator,
        string artifactHash,
        uint256 reward,
        uint256 deadline
    );
}

/// Smart contract instances
#[derive(Clone)]
pub struct ContractInstances {
    pub bounty_manager: Contract,
    pub threat_token: Contract,
    pub reputation_system: Contract,
}

/// Blockchain service for handling Web3 operations
pub struct BlockchainService {
    client: BlockchainClient,
    contracts: ContractInstances,
    config: config::BlockchainConfig,
    pending_transactions: Arc<RwLock<HashMap<TxHash, PendingTransaction>>>,
    nonce_manager: Arc<Mutex<u64>>,
}

/// Pending transaction tracking
#[derive(Debug, Clone)]
struct PendingTransaction {
    pub hash: TxHash,
    pub tx_type: TransactionType,
    pub created_at: DateTime<Utc>,
    pub retry_count: u32,
    pub user_id: Option<Uuid>,
    pub bounty_id: Option<Uuid>,
}

/// Types of blockchain transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    CreateBounty,
    SubmitAnalysis,
    StakeTokens,
    ClaimReward,
    UpdateReputation,
    TokenTransfer,
}

/// Bounty creation parameters (matches BountyManager.createBounty ABI)
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBountyParams {
    pub artifact_hash: String, // IPFS hash of the artifact
    pub artifact_type: String, // "file", "url", etc.
    pub reward_amount: U256,   // Token reward amount
    pub deadline: U256,        // Unix timestamp deadline
    pub description: String,   // Bounty description
}

/// Analysis submission parameters (matches BountyManager.submitAnalysis ABI)
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitAnalysisParams {
    pub bounty_id: U256,       // On-chain bounty ID
    pub verdict: u8,           // ThreatVerdict enum: 0=Pending, 1=Benign, 2=Malicious, 3=Suspicious
    pub confidence: U256,      // Confidence 0-100
    pub stake_amount: U256,    // Tokens to stake (ERC20 transferFrom, not msg.value)
    pub analysis_hash: String, // IPFS hash of detailed analysis
}

/// Blockchain transaction result
#[derive(Debug, Serialize)]
pub struct TransactionResult {
    pub hash: TxHash,
    pub status: TransactionStatus,
    pub block_number: Option<u64>,
    pub gas_used: Option<U256>,
    pub confirmations: u64,
}

/// Bounty info from blockchain (matches BountyManager.Bounty struct)
#[derive(Debug, Serialize, Deserialize)]
pub struct BountyOnChain {
    pub id: U256,
    pub creator: Address,
    pub artifact_hash: String,
    pub artifact_type: String,
    pub reward_amount: U256,
    pub deadline: U256,
    pub description: String,
    pub status: u8, // BountyStatus enum: 0=Active, 1=InReview, 2=Completed, 3=Cancelled, 4=Disputed
    pub consensus_verdict: u8, // ThreatVerdict enum
    pub total_staked: U256,
    pub analysis_count: U256,
    pub created_at: U256,
}

impl BlockchainService {
    /// Create a new blockchain service instance
    pub async fn new(config: config::BlockchainConfig) -> Result<Self> {
        // Setup provider
        let url = config
            .rpc_url
            .parse()
            .context("Failed to create HTTP provider")?;
        let provider = RootProvider::new_http(url).erased();

        // Setup wallet. Don't hard-fail startup on a missing/placeholder key
        // (blockchain disabled in CI/dev where the key is empty or the all-zero
        // sentinel, which is not a valid secp256k1 scalar). Fall back to a
        // deterministic throwaway dev key so the gateway still binds and serves
        // its non-chain routes; on-chain *writes* will fail at send-time (the
        // same behaviour as an unreachable RPC below) until a real key is set.
        let wallet = match config.private_key.parse::<PrivateKeySigner>() {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(
                    "Invalid/placeholder blockchain private key ({e}); using a throwaway \
                     dev key. On-chain transactions are disabled until a valid \
                     BLOCKCHAIN_PRIVATE_KEY / TREASURY_PRIVATE_KEY is configured."
                );
                // Well-known Hardhat account #0 key — valid scalar, dev-only.
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                    .parse::<PrivateKeySigner>()
                    .expect("hardcoded dev key is a valid secp256k1 scalar")
            }
        };

        // Create client
        let address = wallet.address();
        let client = shared::evm::with_signer(provider, wallet, config.chain_id);

        // Get current nonce. Don't hard-fail startup if the RPC is unreachable
        // (blockchain disabled in CI/dev, or a momentary node outage): start at
        // nonce 0 so the gateway still binds and serves its non-chain routes.
        // It is refreshed on the next on-chain transaction.
        let nonce = match client.get_transaction_count(address).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    "Blockchain RPC unreachable at startup ({e}); starting with nonce 0. \
                     On-chain features are unavailable until the RPC is reachable."
                );
                0
            }
        };

        // Load contract ABIs and create instances (no network calls)
        let contracts = Self::load_contracts(&client, &config).await?;

        Ok(Self {
            client,
            contracts,
            config,
            pending_transactions: Arc::new(RwLock::new(HashMap::new())),
            nonce_manager: Arc::new(Mutex::new(nonce)),
        })
    }

    /// Load smart contract instances
    /// Parse a configured contract address, falling back to the zero address.
    ///
    /// Returns `Address::ZERO` for anything unusable -- empty, whitespace, or
    /// malformed -- after logging which variable was at fault. A zero address
    /// is already the project's "chain disabled" sentinel, and it is inert:
    /// contract *reads* return nothing and *writes* fail at send time with a
    /// clear error, which is the same failure mode as an unreachable RPC.
    ///
    /// Startup must never depend on chain configuration being present.
    fn parse_contract_address(var_name: &str, raw: &str) -> Address {
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            tracing::warn!(
                "{var_name} is not set; on-chain calls through this contract are disabled"
            );
            return Address::ZERO;
        }

        match trimmed.parse::<Address>() {
            Ok(addr) => {
                if addr.is_zero() {
                    tracing::warn!(
                        "{var_name} is the zero address; on-chain calls through this contract are disabled"
                    );
                }
                addr
            }
            Err(e) => {
                tracing::warn!(
                    "{var_name} is not a valid address ({e}); treating as unset. \
                     On-chain calls through this contract are disabled until it is corrected."
                );
                Address::ZERO
            }
        }
    }

    async fn load_contracts(
        client: &BlockchainClient,
        config: &config::BlockchainConfig,
    ) -> Result<ContractInstances> {
        // Bind Contract instances to the configured on-chain addresses,
        // using ABIs loaded from the extracted JSON (see get_*_abi below). These
        // are live contract handles — reads/writes hit the chain via `client`.

        // Addresses are parsed leniently, matching how the wallet and nonce
        // above already behave: a blank or malformed address must not stop the
        // gateway from binding and serving its many non-chain routes.
        //
        // This was a real outage. With blank contract addresses the parse
        // propagated, `BlockchainService::new` failed, `main` aborted, and the
        // container never became healthy -- for a service whose chain features
        // are optional and, in production today, disabled entirely.
        let bounty_manager_address = Self::parse_contract_address(
            "BOUNTY_MANAGER_ADDRESS",
            &config.contracts.bounty_manager,
        );
        let threat_token_address =
            Self::parse_contract_address("THREAT_TOKEN_ADDRESS", &config.contracts.threat_token);
        let reputation_system_address = Self::parse_contract_address(
            "REPUTATION_SYSTEM_ADDRESS",
            &config.contracts.reputation_system,
        );

        // ABIs are loaded from the extracted contract JSON at startup.
        let bounty_manager_abi = Self::get_bounty_manager_abi();
        let threat_token_abi = Self::get_threat_token_abi();
        let reputation_system_abi = Self::get_reputation_system_abi();

        let bounty_manager = Contract::new(
            bounty_manager_address,
            client.clone(),
            Interface::new(bounty_manager_abi),
        );

        let threat_token = Contract::new(
            threat_token_address,
            client.clone(),
            Interface::new(threat_token_abi),
        );

        let reputation_system = Contract::new(
            reputation_system_address,
            client.clone(),
            Interface::new(reputation_system_abi),
        );

        Ok(ContractInstances {
            bounty_manager,
            threat_token,
            reputation_system,
        })
    }

    /// Send a contract call with the configured gas limit and price.
    ///
    /// The price is set as both 1559 fee fields, so the transaction pays exactly
    /// that price per gas.
    async fn send_call(
        &self,
        contract: &Contract,
        function: &str,
        args: &[DynSolValue],
    ) -> Result<TxHash> {
        let gas_price = u128::from(self.config.gas_price_gwei) * 1_000_000_000;
        let pending_tx = contract
            .function(function, args)?
            .gas(self.config.gas_limit)
            .max_fee_per_gas(gas_price)
            .max_priority_fee_per_gas(gas_price)
            .send()
            .await?;

        Ok(*pending_tx.tx_hash())
    }

    /// Read a contract's single `uint256` return value.
    async fn read_uint(
        &self,
        contract: &Contract,
        function: &str,
        args: &[DynSolValue],
    ) -> Result<U256> {
        contract
            .function(function, args)?
            .call()
            .await?
            .first()
            .and_then(DynSolValue::as_uint)
            .map(|(value, _)| value)
            .with_context(|| format!("{function} did not return a uint256"))
    }

    /// Create a new bounty on the blockchain
    /// ABI: createBounty(string artifactHash, string artifactType, uint256 rewardAmount, uint256 deadline, string description) returns (uint256)
    /// Returns (tx_hash, on_chain_bounty_id) — the on-chain ID is the contract's incremental bountyCounter
    pub async fn create_bounty(&self, params: CreateBountyParams) -> Result<(TxHash, U256)> {
        let tx_hash = self
            .send_call(
                &self.contracts.bounty_manager,
                "createBounty",
                &[
                    DynSolValue::String(params.artifact_hash),
                    DynSolValue::String(params.artifact_type),
                    DynSolValue::Uint(params.reward_amount, 256),
                    DynSolValue::Uint(params.deadline, 256),
                    DynSolValue::String(params.description),
                ],
            )
            .await
            .context("Failed to send create bounty transaction")?;

        self.track_pending_transaction(tx_hash, TransactionType::CreateBounty, None, None)
            .await;

        // Wait for receipt and parse BountyCreated event to get the on-chain bounty ID.
        // BountyCreated(uint256 indexed bountyId, address indexed creator, string artifactHash, uint256 reward, uint256 deadline)
        // The bountyId is topic[1] (first indexed param after the event signature in topic[0]).
        let receipt: TransactionReceipt = shared::evm::wait_for_receipt(&self.client, tx_hash, 1)
            .await
            .context("Failed waiting for create bounty receipt")?
            .ok_or_else(|| anyhow::anyhow!("No receipt for create bounty tx"))?;

        // Verify event signature + contract address before extracting the bounty ID.
        // BountyCreated(uint256 indexed bountyId, address indexed creator, string artifactHash, uint256 reward, uint256 deadline)
        let bounty_created_sig = BountyCreated::SIGNATURE_HASH;
        let bounty_manager_addr: Address = self
            .config
            .contracts
            .bounty_manager
            .parse()
            .unwrap_or_default();

        let on_chain_id = receipt
            .inner
            .logs()
            .iter()
            .find_map(|log| {
                // Must originate from the bounty manager contract
                if log.address() != bounty_manager_addr {
                    return None;
                }
                // topic[0] must be the BountyCreated event signature
                if log.topics().first() != Some(&bounty_created_sig) {
                    return None;
                }
                // topic[1] = bountyId (indexed uint256)
                log.topics().get(1).map(|t| U256::from_be_bytes(t.0))
            })
            .unwrap_or_else(|| {
                tracing::warn!("Could not parse BountyCreated event, defaulting on_chain_id to 0");
                U256::ZERO
            });

        tracing::info!(
            "Created bounty tx: {:?}, on_chain_id: {}",
            tx_hash,
            on_chain_id
        );
        Ok((tx_hash, on_chain_id))
    }

    /// Submit analysis for a bounty
    /// ABI: submitAnalysis(uint256 bountyId, uint8 verdict, uint256 confidence, uint256 stakeAmount, string analysisHash)
    /// Note: The contract uses ERC20 transferFrom for staking, NOT msg.value
    pub async fn submit_analysis(&self, params: SubmitAnalysisParams) -> Result<TxHash> {
        let tx_hash = self
            .send_call(
                &self.contracts.bounty_manager,
                "submitAnalysis",
                &[
                    DynSolValue::Uint(params.bounty_id, 256),
                    DynSolValue::Uint(U256::from(params.verdict), 8),
                    DynSolValue::Uint(params.confidence, 256),
                    DynSolValue::Uint(params.stake_amount, 256),
                    DynSolValue::String(params.analysis_hash),
                ],
            )
            .await
            .context("Failed to send submit analysis transaction")?;

        self.track_pending_transaction(tx_hash, TransactionType::SubmitAnalysis, None, None)
            .await;

        tracing::info!("Submitted analysis transaction: {:?}", tx_hash);
        Ok(tx_hash)
    }

    /// Stake tokens for analysis submission (approve BountyManager to spend tokens)
    pub async fn stake_tokens(&self, amount: U256, user_id: Uuid) -> Result<TxHash> {
        let tx_hash = self
            .send_call(
                &self.contracts.threat_token,
                "approve",
                &[
                    DynSolValue::Address(self.config.contracts.bounty_manager.parse::<Address>()?),
                    DynSolValue::Uint(amount, 256),
                ],
            )
            .await
            .context("Failed to send stake tokens transaction")?;

        self.track_pending_transaction(tx_hash, TransactionType::StakeTokens, Some(user_id), None)
            .await;

        tracing::info!("Staked tokens transaction: {:?}", tx_hash);
        Ok(tx_hash)
    }

    /// Resolve a bounty (triggers consensus calculation and reward distribution)
    /// ABI: resolveBounty(uint256 bountyId)
    /// Note: There is no "claimReward" in the contract — rewards are distributed automatically when bounty resolves
    pub async fn resolve_bounty(&self, bounty_id: U256) -> Result<TxHash> {
        let tx_hash = self
            .send_call(
                &self.contracts.bounty_manager,
                "resolveBounty",
                &[DynSolValue::Uint(bounty_id, 256)],
            )
            .await
            .context("Failed to send resolve bounty transaction")?;

        self.track_pending_transaction(
            tx_hash,
            TransactionType::ClaimReward, // Reusing enum for now
            None,
            None,
        )
        .await;

        tracing::info!("Resolved bounty transaction: {:?}", tx_hash);
        Ok(tx_hash)
    }

    /// Update user reputation on blockchain
    /// ABI: updateReputation(address engine, bool success)
    pub async fn update_reputation(&self, user_address: Address, success: bool) -> Result<TxHash> {
        let tx_hash = self
            .send_call(
                &self.contracts.reputation_system,
                "updateReputation",
                &[
                    DynSolValue::Address(user_address),
                    DynSolValue::Bool(success),
                ],
            )
            .await
            .context("Failed to send update reputation transaction")?;

        self.track_pending_transaction(tx_hash, TransactionType::UpdateReputation, None, None)
            .await;

        tracing::info!("Updated reputation transaction: {:?}", tx_hash);
        Ok(tx_hash)
    }

    /// Get bounty info from blockchain
    /// ABI: getBounty(uint256 bountyId) returns (Bounty)
    /// Returns full Bounty struct as a tuple of 12 values
    pub async fn get_bounty(&self, bounty_id: U256) -> Result<BountyOnChain> {
        let output = self
            .contracts
            .bounty_manager
            .function("getBounty", &[DynSolValue::Uint(bounty_id, 256)])?
            .call()
            .await
            .context("Failed to get bounty")?;

        let fields = output
            .first()
            .and_then(DynSolValue::as_tuple)
            .filter(|fields| fields.len() == 12)
            .context("getBounty did not return a 12-field Bounty struct")?;
        let uint = |i: usize| {
            fields[i]
                .as_uint()
                .map(|(value, _)| value)
                .with_context(|| format!("getBounty field {i} is not a uint"))
        };
        let string = |i: usize| {
            fields[i]
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("getBounty field {i} is not a string"))
        };

        Ok(BountyOnChain {
            id: uint(0)?,
            creator: fields[1]
                .as_address()
                .context("getBounty field 1 is not an address")?,
            artifact_hash: string(2)?,
            artifact_type: string(3)?,
            reward_amount: uint(4)?,
            deadline: uint(5)?,
            description: string(6)?,
            status: uint(7)?.to::<u8>(),
            consensus_verdict: uint(8)?.to::<u8>(),
            total_staked: uint(9)?,
            analysis_count: uint(10)?,
            created_at: uint(11)?,
        })
    }

    /// Get user's token balance
    pub async fn get_token_balance(&self, user_address: Address) -> Result<U256> {
        self.read_uint(
            &self.contracts.threat_token,
            "balanceOf",
            &[DynSolValue::Address(user_address)],
        )
        .await
        .context("Failed to get token balance")
    }

    /// Get user's reputation score from blockchain
    /// ABI: getReputation(address engine) returns (uint256)
    pub async fn get_reputation_score(&self, user_address: Address) -> Result<U256> {
        self.read_uint(
            &self.contracts.reputation_system,
            "getReputation",
            &[DynSolValue::Address(user_address)],
        )
        .await
        .context("Failed to get reputation score")
    }

    /// Check transaction status
    pub async fn get_transaction_status(&self, tx_hash: TxHash) -> Result<TransactionResult> {
        let receipt = self.client.get_transaction_receipt(tx_hash).await?;
        let current_block = self.client.get_block_number().await?;

        match receipt {
            Some(receipt) => {
                let confirmations =
                    current_block.saturating_sub(receipt.block_number.unwrap_or_default());
                let status = if receipt.status() {
                    if confirmations >= self.config.confirmation_blocks {
                        TransactionStatus::Confirmed
                    } else {
                        TransactionStatus::Pending
                    }
                } else {
                    TransactionStatus::Failed
                };

                Ok(TransactionResult {
                    hash: tx_hash,
                    status,
                    block_number: receipt.block_number,
                    gas_used: Some(U256::from(receipt.gas_used)),
                    confirmations,
                })
            }
            None => Ok(TransactionResult {
                hash: tx_hash,
                status: TransactionStatus::Pending,
                block_number: None,
                gas_used: None,
                confirmations: 0,
            }),
        }
    }

    /// Monitor pending transactions and update their status
    pub async fn monitor_transactions(&self) -> Result<()> {
        let mut pending_txs = self.pending_transactions.write().await;
        let mut completed_hashes = Vec::new();

        for (hash, pending_tx) in pending_txs.iter_mut() {
            match self.get_transaction_status(*hash).await {
                Ok(result) => {
                    match result.status {
                        TransactionStatus::Confirmed | TransactionStatus::Failed => {
                            tracing::info!(
                                "Transaction {} completed with status: {:?}",
                                hash,
                                result.status
                            );
                            completed_hashes.push(*hash);
                        }
                        TransactionStatus::Pending => {
                            // Check if transaction is too old and needs retry
                            let age = Utc::now().signed_duration_since(pending_tx.created_at);
                            if age.num_minutes() > 10
                                && pending_tx.retry_count < self.config.retry_attempts
                            {
                                pending_tx.retry_count += 1;
                                tracing::warn!(
                                    "Transaction {} is taking too long, retry count: {}",
                                    hash,
                                    pending_tx.retry_count
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to check transaction status for {}: {}", hash, e);
                }
            }
        }

        // Remove completed transactions
        for hash in completed_hashes {
            pending_txs.remove(&hash);
        }

        Ok(())
    }

    /// Track a pending transaction
    async fn track_pending_transaction(
        &self,
        hash: TxHash,
        tx_type: TransactionType,
        user_id: Option<Uuid>,
        bounty_id: Option<Uuid>,
    ) {
        let pending_tx = PendingTransaction {
            hash,
            tx_type,
            created_at: Utc::now(),
            retry_count: 0,
            user_id,
            bounty_id,
        };

        let mut pending_txs = self.pending_transactions.write().await;
        pending_txs.insert(hash, pending_tx);
    }

    /// Get next nonce for transactions
    async fn get_next_nonce(&self) -> u64 {
        let mut nonce_guard = self.nonce_manager.lock().await;
        let nonce = *nonce_guard;
        *nonce_guard += 1;
        nonce
    }

    // Load real ABIs from compiled contract artifacts
    /// Load an ABI, degrading to an empty one rather than panicking.
    ///
    /// ABI paths are resolved relative to the working directory (the image
    /// sets `WORKDIR /app` and copies `abis/` there), so a binary started from
    /// anywhere else used to panic the whole process at startup. An empty ABI
    /// is inert in the same way the zero address is: contract *construction*
    /// succeeds, and any `method(...)` lookup fails at call time with a clear
    /// error instead of taking the gateway down with it.
    fn load_abi_or_empty(label: &str, loaded: Result<Abi>) -> Abi {
        match loaded {
            Ok(abi) => abi,
            Err(e) => {
                tracing::warn!(
                    "Could not load the {label} ABI ({e}); on-chain calls to this contract are \
                     disabled. Run blockchain/scripts/extract-abis.sh and ensure abis/ is present \
                     in the working directory."
                );
                Abi::default()
            }
        }
    }

    fn get_bounty_manager_abi() -> Abi {
        Self::load_abi_or_empty(
            "BountyManager",
            crate::services::abi_loader::load_bounty_manager_abi(),
        )
    }

    fn get_threat_token_abi() -> Abi {
        Self::load_abi_or_empty(
            "ThreatToken",
            crate::services::abi_loader::load_threat_token_abi(),
        )
    }

    fn get_reputation_system_abi() -> Abi {
        Self::load_abi_or_empty(
            "ReputationSystem",
            crate::services::abi_loader::load_reputation_system_abi(),
        )
    }
}

/// Helper functions for blockchain operations
impl BlockchainService {
    /// Calculate gas price based on network conditions
    pub async fn estimate_gas_price(&self) -> Result<U256> {
        let gas_price = self
            .client
            .get_gas_price()
            .await
            .context("Failed to get gas price")?;

        // Add 10% buffer
        Ok(U256::from(gas_price) * U256::from(110) / U256::from(100))
    }

    /// Validate Ethereum address
    pub fn validate_address(address: &str) -> Result<Address> {
        address
            .parse::<Address>()
            .context("Invalid Ethereum address format")
    }

    /// Health check for blockchain service
    /// Pings the RPC endpoint with a 5-second timeout to verify connectivity
    pub async fn health_check(&self) -> bool {
        match tokio::time::timeout(Duration::from_secs(5), self.client.get_block_number()).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                tracing::warn!("Blockchain health check failed: {}", e);
                false
            }
            Err(_) => {
                tracing::warn!("Blockchain health check timed out");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_address() {
        let valid_address = "0x742b15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34";
        assert!(BlockchainService::validate_address(valid_address).is_ok());

        let invalid_address = "invalid_address";
        assert!(BlockchainService::validate_address(invalid_address).is_err());
    }

    #[test]
    fn valid_contract_address_is_used_as_configured() {
        let addr = BlockchainService::parse_contract_address(
            "BOUNTY_MANAGER_ADDRESS",
            "0x742b15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34",
        );
        assert!(!addr.is_zero());
        assert_eq!(
            format!("{addr:?}").to_lowercase(),
            "0x742b15c2d1f7a9fe9a8d2f1b22d7e3af95c30b34"
        );
    }

    /// Regression: a blank contract address used to propagate a parse error
    /// out of `load_contracts`, fail `BlockchainService::new`, abort `main`,
    /// and leave the container permanently unhealthy -- for a service whose
    /// chain features are optional and currently disabled in production.
    /// Unset config must degrade, never crash.
    #[test]
    fn unset_contract_address_degrades_instead_of_failing() {
        for raw in ["", "   ", "\t"] {
            let addr = BlockchainService::parse_contract_address("THREAT_TOKEN_ADDRESS", raw);
            assert!(
                addr.is_zero(),
                "an unset address must fall back to the zero address, got {addr:?}"
            );
        }
    }

    /// A typo in an address is a configuration mistake, not a reason to take
    /// the whole gateway offline.
    #[test]
    fn malformed_contract_address_degrades_instead_of_failing() {
        for raw in [
            "not-an-address",
            "0x123",                                         // too short
            "0xZZZZ15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34",    // non-hex
            "742b15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34extra", // too long
        ] {
            let addr = BlockchainService::parse_contract_address("REPUTATION_SYSTEM_ADDRESS", raw);
            assert!(
                addr.is_zero(),
                "a malformed address must fall back to zero, got {addr:?} for {raw:?}"
            );
        }
    }

    /// Surrounding whitespace is a copy-paste artefact, not a malformed value.
    #[test]
    fn contract_address_tolerates_surrounding_whitespace() {
        let addr = BlockchainService::parse_contract_address(
            "BOUNTY_MANAGER_ADDRESS",
            "  0x742b15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34\n",
        );
        assert!(
            !addr.is_zero(),
            "a padded but valid address must still parse"
        );
    }

    /// The documented "chain disabled" sentinel must be accepted quietly
    /// rather than treated as a failure.
    #[test]
    fn zero_address_sentinel_is_accepted() {
        let addr = BlockchainService::parse_contract_address(
            "BOUNTY_MANAGER_ADDRESS",
            "0x0000000000000000000000000000000000000000",
        );
        assert!(addr.is_zero());
    }

    /// A missing ABI file must not panic the process at startup.
    #[test]
    fn missing_abi_degrades_to_an_empty_abi() {
        let abi = BlockchainService::load_abi_or_empty(
            "BountyManager",
            Err(anyhow::anyhow!("no such file")),
        );
        assert!(
            abi.functions().next().is_none(),
            "a failed ABI load must yield an empty ABI, not panic"
        );
    }

    /// Regression: CI's smoke test runs with no chain node, a placeholder key and
    /// blank addresses, and the gateway must still start.
    #[tokio::test]
    async fn unreachable_rpc_does_not_stop_startup() {
        let service = BlockchainService::new(config::BlockchainConfig {
            rpc_url: "http://127.0.0.1:1".to_string(),
            chain_id: 1,
            private_key: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            contracts: config::ContractsConfig {
                bounty_manager: String::new(),
                threat_token: String::new(),
                reputation_system: String::new(),
                governance: None,
            },
            gas_limit: 1,
            gas_price_gwei: 1,
            gas_price_multiplier: 1.0,
            max_gas_price_gwei: 1,
            confirmation_blocks: 1,
            transaction_timeout_seconds: 1,
            retry_attempts: 1,
            retry_delay_ms: 1,
        })
        .await
        .expect("startup must not depend on the chain");

        assert!(!service.health_check().await);
        assert!(service.get_token_balance(Address::ZERO).await.is_err());
    }

    /// Create, read, stake on, submit to and resolve a bounty through the
    /// service, on real contracts. See `shared::evm_testing` for how to run it.
    #[tokio::test]
    #[ignore = "needs a local chain and compiled contracts"]
    async fn local_chain_bounty_lifecycle() {
        use shared::evm_testing::{LocalChain, ADMIN_KEY, ANALYST_KEY, TOKEN};

        let chain = LocalChain::deploy().await;
        // `abi_loader` resolves `abis/` against the working directory.
        std::env::set_current_dir(shared::evm_testing::abis_dir().join("..")).unwrap();

        let config = |private_key: &str| config::BlockchainConfig {
            rpc_url: chain.rpc_url.clone(),
            chain_id: chain.chain_id,
            private_key: private_key.to_string(),
            contracts: config::ContractsConfig {
                bounty_manager: format!("{:?}", chain.bounty_manager),
                threat_token: format!("{:?}", chain.token),
                reputation_system: format!("{:?}", chain.reputation),
                governance: None,
            },
            gas_limit: 3_000_000,
            gas_price_gwei: 50,
            gas_price_multiplier: 1.0,
            max_gas_price_gwei: 100,
            confirmation_blocks: 0,
            transaction_timeout_seconds: 60,
            retry_attempts: 1,
            retry_delay_ms: 10,
        };
        let creator = BlockchainService::new(config(ADMIN_KEY)).await.unwrap();
        let analyst = BlockchainService::new(config(ANALYST_KEY)).await.unwrap();
        assert!(creator.health_check().await);

        let balance_before = creator
            .get_token_balance(chain.admin_address)
            .await
            .unwrap();

        // Allowance for the bounty escrow, sent through the service.
        let reward = TOKEN * U256::from(100);
        let approve = creator.stake_tokens(reward, Uuid::new_v4()).await.unwrap();
        wait_mined(&creator, approve).await;

        let deadline = U256::from(chain.now().await + 2 * 3600);
        let (tx_hash, on_chain_id) = creator
            .create_bounty(CreateBountyParams {
                artifact_hash: "QmGatewayArtifact".to_string(),
                artifact_type: "file".to_string(),
                reward_amount: reward,
                deadline,
                description: "gateway round trip".to_string(),
            })
            .await
            .unwrap();
        assert_ne!(
            on_chain_id,
            U256::ZERO,
            "the event's bounty ID must be read"
        );

        let status = creator.get_transaction_status(tx_hash).await.unwrap();
        assert!(matches!(status.status, TransactionStatus::Confirmed));
        assert!(status.block_number.is_some());
        assert!(status.gas_used.is_some_and(|gas| gas > U256::ZERO));

        // Reward left the creator's wallet for escrow.
        let balance_after = creator
            .get_token_balance(chain.admin_address)
            .await
            .unwrap();
        assert_eq!(balance_before - balance_after, reward);

        let bounty = creator.get_bounty(on_chain_id).await.unwrap();
        assert_eq!(bounty.id, on_chain_id);
        assert_eq!(bounty.creator, chain.admin_address);
        assert_eq!(bounty.artifact_hash, "QmGatewayArtifact");
        assert_eq!(bounty.artifact_type, "file");
        assert_eq!(bounty.reward_amount, reward);
        assert_eq!(bounty.deadline, deadline);
        assert_eq!(bounty.description, "gateway round trip");
        assert_eq!(bounty.status, 0, "a new bounty is Active");
        assert_eq!(bounty.analysis_count, U256::ZERO);

        let submit = analyst
            .submit_analysis(SubmitAnalysisParams {
                bounty_id: on_chain_id,
                verdict: 2,
                confidence: U256::from(90),
                stake_amount: TOKEN * U256::from(10),
                analysis_hash: "QmAnalysis".to_string(),
            })
            .await
            .unwrap();
        wait_mined(&analyst, submit).await;
        let bounty = creator.get_bounty(on_chain_id).await.unwrap();
        assert_eq!(bounty.analysis_count, U256::from(1));
        assert_eq!(bounty.total_staked, TOKEN * U256::from(10));

        assert!(
            creator
                .get_reputation_score(chain.analyst_address)
                .await
                .unwrap()
                > U256::ZERO
        );

        // Too early. The gas limit is fixed by config, so nothing estimates the
        // call first. Anvil mines the revert; Hardhat also fails the send.
        match creator.resolve_bounty(on_chain_id).await {
            Ok(early) => {
                wait_mined(&creator, early).await;
                let early = creator.get_transaction_status(early).await.unwrap();
                assert!(matches!(early.status, TransactionStatus::Failed));
            }
            Err(e) => assert!(format!("{e:#}").contains("Cannot resolve yet"), "{e:#}"),
        }

        chain.advance_time(3 * 3600).await;
        let resolve = creator.resolve_bounty(on_chain_id).await.unwrap();
        wait_mined(&creator, resolve).await;
        let resolved = creator.get_transaction_status(resolve).await.unwrap();
        assert!(matches!(resolved.status, TransactionStatus::Confirmed));
        assert_eq!(creator.get_bounty(on_chain_id).await.unwrap().status, 2);
    }

    async fn wait_mined(service: &BlockchainService, hash: TxHash) {
        shared::evm::wait_for_receipt(&service.client, hash, 1)
            .await
            .unwrap()
            .expect("transaction mined");
    }

    /// API responses carry these types, so their JSON must not change shape.
    #[test]
    fn chain_types_keep_their_json_form() {
        let result = TransactionResult {
            hash: TxHash::repeat_byte(0xab),
            status: TransactionStatus::Pending,
            block_number: None,
            gas_used: Some(U256::from(21_000)),
            confirmations: 0,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["hash"], format!("0x{}", "ab".repeat(32)));
        assert_eq!(json["gas_used"], "0x5208");

        let address = "0x742b15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34"
            .parse::<Address>()
            .unwrap();
        let lowercase = "0x742b15c2d1f7a9fe9a8d2f1b22d7e3af95c30b34";
        assert_eq!(format!("{address:?}"), lowercase);
        assert_eq!(serde_json::to_value(address).unwrap(), lowercase);
        assert_eq!(serde_json::to_value(U256::ZERO).unwrap(), "0x0");
    }
}
