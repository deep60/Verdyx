pub mod web3_client;

pub use web3_client::{
    AnalysisSubmission, BountyInfo, ContractAddresses, ReputationScore, Web3Client,
};

use anyhow::{Context, Result};
use ethers::types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Configuration for blockchain connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub private_key: Option<String>,
    pub contract_addresses: ContractAddresses,
    pub gas_limit: Option<U256>,
    pub gas_price_multiplier: Option<f64>,
}

impl BlockchainConfig {
    /// Creates a new blockchain configuration
    pub fn new(
        rpc_url: String,
        chain_id: u64,
        bounty_manager: &str,
        reputation_system: &str,
        threat_token: &str,
    ) -> Result<Self> {
        let contract_addresses = ContractAddresses {
            bounty_manager: Address::from_str(bounty_manager)
                .context("Invalid bounty manager address")?,
            reputation_system: Address::from_str(reputation_system)
                .context("Invalid reputation system address")?,
            threat_token: Address::from_str(threat_token)
                .context("Invalid threat token address")?,
        };

        Ok(Self {
            rpc_url,
            chain_id,
            private_key: None,
            contract_addresses,
            gas_limit: None,
            gas_price_multiplier: None,
        })
    }

    /// Sets the private key for the configuration
    pub fn with_private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the gas limit for transactions
    pub fn with_gas_limit(mut self, gas_limit: U256) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Sets the gas price multiplier
    pub fn with_gas_price_multiplier(mut self, multiplier: f64) -> Self {
        self.gas_price_multiplier = Some(multiplier);
        self
    }

    /// Creates a Web3Client from this configuration
    pub async fn create_client(&self) -> Result<Web3Client> {
        Web3Client::new(
            &self.rpc_url,
            self.private_key.as_deref(),
            self.chain_id,
            self.contract_addresses.clone(),
        )
        .await
    }
}

/// Error types specific to blockchain operations
#[derive(Debug, thiserror::Error)]
pub enum BlockchainError {
    #[error("Invalid contract address: {address}")]
    InvalidAddress { address: String },

    #[error("Transaction failed: {reason}")]
    TransactionFailed { reason: String },

    #[error("Insufficient balance: required {required} ETH, available {available} ETH")]
    InsufficientBalance { required: String, available: String },

    #[error("Contract call failed: {reason}")]
    ContractError { reason: String },

    #[error("Network connection error: {reason}")]
    NetworkError { reason: String },

    #[error("Invalid bounty: {reason}")]
    InvalidBounty { reason: String },

    #[error("Unauthorized operation")]
    Unauthorized,

    #[error("Timeout waiting for transaction confirmation")]
    TransactionTimeout,
}

/// Result type alias for blockchain operations
pub type BlockchainResult<T> = Result<T, BlockchainError>;

/// Threat analysis verdict
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatVerdict {
    Benign = 0,
    Malicious = 1,
    Suspicious = 2,
    Unknown = 3,
}

impl From<u8> for ThreatVerdict {
    fn from(value: u8) -> Self {
        match value {
            0 => ThreatVerdict::Benign,
            1 => ThreatVerdict::Malicious,
            2 => ThreatVerdict::Suspicious,
            _ => ThreatVerdict::Unknown,
        }
    }
}

impl From<ThreatVerdict> for u8 {
    fn from(verdict: ThreatVerdict) -> Self {
        verdict as u8
    }
}

/// Bounty status on the blockchain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BountyStatus {
    Active = 0,
    Completed = 1,
    Expired = 2,
    Cancelled = 3,
}

impl From<u8> for BountyStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => BountyStatus::Active,
            1 => BountyStatus::Completed,
            2 => BountyStatus::Expired,
            _ => BountyStatus::Cancelled,
        }
    }
}

/// Blockchain service trait for dependency injection and testing
#[async_trait::async_trait]
pub trait BlockchainService: Send + Sync {
    /// Create a new bounty on the blockchain
    async fn create_bounty(
        &self,
        file_hash: &str,
        reward_amount: U256,
        deadline: U256,
        min_stake: U256,
    ) -> BlockchainResult<H256>;

    /// Submit threat analysis to a bounty
    async fn submit_analysis(
        &self,
        bounty_id: H256,
        verdict: ThreatVerdict,
        confidence: u8,
        stake_amount: U256,
        evidence_hash: &str,
    ) -> BlockchainResult<H256>;

    /// Get bounty information
    async fn get_bounty(&self, bounty_id: H256) -> BlockchainResult<Option<BountyInfo>>;

    /// Get active bounties
    async fn get_active_bounties(&self, limit: usize) -> BlockchainResult<Vec<BountyInfo>>;

    /// Get reputation score for an analyzer
    async fn get_reputation(&self, analyzer: Address) -> BlockchainResult<Option<ReputationScore>>;

    /// Get token balance for an address
    async fn get_token_balance(&self, address: Address) -> BlockchainResult<U256>;

    /// Complete a bounty and distribute rewards
    async fn complete_bounty(&self, bounty_id: H256) -> BlockchainResult<H256>;

    /// Get analysis submissions for a bounty
    async fn get_submissions(&self, bounty_id: H256) -> BlockchainResult<Vec<AnalysisSubmission>>;
}

/// Predefined configurations for different networks
pub struct NetworkConfigs;

impl NetworkConfigs {
    /// Ethereum mainnet configuration
    pub fn ethereum_mainnet(
        infura_api_key: &str,
        bounty_manager: &str,
        reputation_system: &str,
        threat_token: &str,
    ) -> Result<BlockchainConfig> {
        BlockchainConfig::new(
            format!("https://mainnet.infura.io/v3/{}", infura_api_key),
            1,
            bounty_manager,
            reputation_system,
            threat_token,
        )
    }

    /// Ethereum Sepolia testnet configuration
    pub fn ethereum_sepolia(
        infura_api_key: &str,
        bounty_manager: &str,
        reputation_system: &str,
        threat_token: &str,
    ) -> Result<BlockchainConfig> {
        BlockchainConfig::new(
            format!("https://sepolia.infura.io/v3/{}", infura_api_key),
            11155111,
            bounty_manager,
            reputation_system,
            threat_token,
        )
    }

    /// Polygon mainnet configuration
    pub fn polygon_mainnet(
        bounty_manager: &str,
        reputation_system: &str,
        threat_token: &str,
    ) -> Result<BlockchainConfig> {
        BlockchainConfig::new(
            "https://polygon-rpc.com".to_string(),
            137,
            bounty_manager,
            reputation_system,
            threat_token,
        )
    }

    /// Polygon Mumbai testnet configuration
    pub fn polygon_mumbai(
        bounty_manager: &str,
        reputation_system: &str,
        threat_token: &str,
    ) -> Result<BlockchainConfig> {
        BlockchainConfig::new(
            "https://rpc-mumbai.maticvigil.com".to_string(),
            80001,
            bounty_manager,
            reputation_system,
            threat_token,
        )
    }

    /// Local development configuration (Hardhat/Ganache)
    pub fn local_development(
        rpc_url: Option<&str>,
        bounty_manager: &str,
        reputation_system: &str,
        threat_token: &str,
    ) -> Result<BlockchainConfig> {
        BlockchainConfig::new(
            rpc_url.unwrap_or("http://localhost:8545").to_string(),
            31337,
            bounty_manager,
            reputation_system,
            threat_token,
        )
    }
}

/// Blockchain event types for real-time monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockchainEvent {
    BountyCreated {
        bounty_id: H256,
        creator: Address,
        file_hash: String,
        reward: U256,
        deadline: U256,
    },
    AnalysisSubmitted {
        bounty_id: H256,
        analyzer: Address,
        verdict: ThreatVerdict,
        confidence: u8,
        stake: U256,
    },
    BountyCompleted {
        bounty_id: H256,
        consensus_verdict: ThreatVerdict,
        total_reward: U256,
        participants: u32,
    },
    ReputationUpdated {
        analyzer: Address,
        old_score: U256,
        new_score: U256,
        accuracy: u8,
    },
    TokensDistributed {
        bounty_id: H256,
        recipients: Vec<Address>,
        amounts: Vec<U256>,
    },
}

/// Utility functions for blockchain operations
pub mod utils {
    use super::*;
    use ethers::types::Bytes;
    use ethers::utils::{format_ether, keccak256, parse_ether};

    /// Converts ETH amount to Wei
    pub fn eth_to_wei(eth_amount: &str) -> Result<U256> {
        parse_ether(eth_amount).context("Failed to parse ETH amount")
    }

    /// Converts Wei to ETH string
    pub fn wei_to_eth(wei_amount: U256) -> String {
        format_ether(wei_amount)
    }

    /// Generates a hash for file content
    pub fn hash_file_content(content: &[u8]) -> H256 {
        keccak256(content).into()
    }

    /// Generates a hash for a string
    pub fn hash_string(input: &str) -> H256 {
        keccak256(input.as_bytes()).into()
    }

    /// Converts address to checksum format
    pub fn to_checksum_address(address: &Address) -> String {
        ethers::utils::to_checksum(address, None)
    }

    /// Validates if a string is a valid Ethereum address
    pub fn is_valid_address(address_str: &str) -> bool {
        Address::from_str(address_str).is_ok()
    }

    /// Generates a deterministic bounty ID from file hash and creator
    pub fn generate_bounty_id(file_hash: &str, creator: Address, timestamp: U256) -> H256 {
        let data = format!("{}{:?}{}", file_hash, creator, timestamp);
        keccak256(data.as_bytes()).into()
    }

    /// Converts timestamp to human-readable format
    pub fn timestamp_to_datetime(timestamp: U256) -> Result<chrono::DateTime<chrono::Utc>> {
        use chrono::{DateTime, TimeZone, Utc};

        let timestamp_secs = timestamp.as_u64() as i64;
        Ok(Utc
            .timestamp_opt(timestamp_secs, 0)
            .single()
            .context("Invalid timestamp")?)
    }

    /// Gets current Unix timestamp as U256
    pub fn current_timestamp() -> U256 {
        use std::time::{SystemTime, UNIX_EPOCH};

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        U256::from(duration.as_secs())
    }

    /// Calculates deadline timestamp from current time plus duration in seconds
    pub fn calculate_deadline(duration_seconds: u64) -> U256 {
        current_timestamp() + U256::from(duration_seconds)
    }

    /// Calculate consensus verdict from submissions weighted by stake
    pub fn calculate_consensus(submissions: &[AnalysisSubmission]) -> Option<(ThreatVerdict, u8)> {
        if submissions.is_empty() {
            return None;
        }

        let mut verdict_stakes: HashMap<ThreatVerdict, U256> = HashMap::new();
        let mut verdict_confidences: HashMap<ThreatVerdict, Vec<u8>> = HashMap::new();

        for submission in submissions {
            let current_stake = verdict_stakes
                .entry(submission.verdict.clone())
                .or_insert(U256::zero());
            *current_stake += submission.stake_amount;

            verdict_confidences
                .entry(submission.verdict.clone())
                .or_insert_with(Vec::new)
                .push(submission.confidence);
        }

        // Find verdict with highest total stake
        let (consensus_verdict, _) = verdict_stakes.iter().max_by_key(|(_, &stake)| stake)?;

        // Calculate weighted average confidence for the consensus verdict
        let confidences = verdict_confidences.get(consensus_verdict)?;
        let avg_confidence = confidences.iter().sum::<u8>() / confidences.len() as u8;

        Some((consensus_verdict.clone(), avg_confidence))
    }

    /// Calculate reputation score based on accuracy and participation
    pub fn calculate_reputation_score(
        total_submissions: u32,
        correct_predictions: u32,
        total_earned: U256,
        total_staked: U256,
    ) -> U256 {
        if total_submissions == 0 {
            return U256::zero();
        }

        let accuracy = (correct_predictions * 100) / total_submissions; // Percentage
        let volume_factor = total_submissions.min(100); // Cap at 100

        // Simple reputation formula: (accuracy * volume_factor) + earning_bonus
        let base_score = U256::from(accuracy * volume_factor);
        let earning_bonus = if total_staked > U256::zero() {
            (total_earned * U256::from(10)) / total_staked // 10% of earning ratio
        } else {
            U256::zero()
        };

        base_score + earning_bonus
    }
}

/// Constants used throughout the blockchain module
pub mod constants {
    use ethers::types::U256;

    /// Minimum stake amount for analysis submissions (in Wei) - 0.1 ETH
    pub const MIN_STAKE_AMOUNT: U256 = U256([100000000000000000u64, 0, 0, 0]);

    /// Maximum bounty duration in seconds (30 days)
    pub const MAX_BOUNTY_DURATION: u64 = 30 * 24 * 60 * 60;

    /// Minimum bounty duration in seconds (1 hour)
    pub const MIN_BOUNTY_DURATION: u64 = 60 * 60;

    /// Gas limit for bounty creation transactions
    pub const BOUNTY_CREATION_GAS_LIMIT: U256 = U256([300000, 0, 0, 0]);

    /// Gas limit for analysis submission transactions
    pub const ANALYSIS_SUBMISSION_GAS_LIMIT: U256 = U256([200000, 0, 0, 0]);

    /// Gas limit for token transfer transactions
    pub const TOKEN_TRANSFER_GAS_LIMIT: U256 = U256([100000, 0, 0, 0]);

    /// Default gas price multiplier for faster transactions
    pub const DEFAULT_GAS_PRICE_MULTIPLIER: f64 = 1.2;

    /// Number of confirmations to wait for critical transactions
    pub const CONFIRMATION_BLOCKS: u64 = 3;

    /// Reputation score scaling factor
    pub const REPUTATION_SCALE_FACTOR: U256 = U256([1000, 0, 0, 0]);

    /// Maximum confidence score (percentage)
    pub const MAX_CONFIDENCE: u8 = 100;

    /// Minimum confidence score for submissions
    pub const MIN_CONFIDENCE: u8 = 51;
}

#[cfg(test)]
mod tests {
    use super::utils::*;
    use super::*;

    #[test]
    fn test_eth_wei_conversion() {
        let wei = eth_to_wei("1.0").unwrap();
        assert_eq!(wei, U256::from(1000000000000000000u64));

        let eth_str = wei_to_eth(wei);
        assert_eq!(eth_str, "1.000000000000000000");
    }

    #[test]
    fn test_address_validation() {
        assert!(is_valid_address(
            "0x742d35Cc6634C0532925a3b8D0fC9E0C4b17b3b0"
        ));
        assert!(!is_valid_address("invalid_address"));
        assert!(!is_valid_address("0x123")); // Too short
    }

    #[test]
    fn test_threat_verdict_conversion() {
        assert_eq!(ThreatVerdict::from(0u8), ThreatVerdict::Benign);
        assert_eq!(ThreatVerdict::from(1u8), ThreatVerdict::Malicious);
        assert_eq!(u8::from(ThreatVerdict::Suspicious), 2u8);
    }

    #[test]
    fn test_reputation_calculation() {
        let score = calculate_reputation_score(100, 80, U256::from(1000), U256::from(900));
        assert!(score > U256::zero());

        // Perfect accuracy should give higher score
        let perfect_score = calculate_reputation_score(50, 50, U256::from(500), U256::from(500));
        let imperfect_score = calculate_reputation_score(50, 25, U256::from(500), U256::from(500));
        assert!(perfect_score > imperfect_score);
    }

    #[test]
    fn test_network_configs() {
        let config = NetworkConfigs::ethereum_sepolia(
            "test_api_key",
            "0x742d35Cc6634C0532925a3b8D0fC9E0C4b17b3b0",
            "0x742d35Cc6634C0532925a3b8D0fC9E0C4b17b3b1",
            "0x742d35Cc6634C0532925a3b8D0fC9E0C4b17b3b2",
        )
        .unwrap();

        assert_eq!(config.chain_id, 11155111);
        assert!(config.rpc_url.contains("sepolia.infura.io"));
    }
}
