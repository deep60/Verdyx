use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Result type for payment operations
pub type PaymentResult<T> = Result<T, PaymentError>;

/// Payment error types
#[derive(Debug, Error)]
pub enum PaymentError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Insufficient balance: {0}")]
    InsufficientBalance(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Blockchain error: {0}")]
    BlockchainError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already processed: {0}")]
    AlreadyProcessed(String),

    #[error("Lock error: {0}")]
    LockError(String),

    /// An operation that needed the server to send tokens, which it no longer does.
    #[error("Not supported: {0}")]
    NotSupported(String),
}

/// Payment transaction record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Payment {
    pub id: Uuid,
    pub payment_type: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: Decimal,
    pub token_address: Option<String>,
    pub bounty_id: Option<Uuid>,
    pub submission_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub status: String,
    pub tx_hash: Option<String>,
    pub block_number: Option<i64>,
    pub gas_used: Option<Decimal>,
    pub gas_price: Option<Decimal>,
    pub nonce: Option<i64>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentType {
    BountyDeposit,
    BountyReward,
    StakeLock,
    StakeUnlock,
    StakeSlash,
    Withdrawal,
    Fee,
    Refund,
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for PaymentType {
    fn to_string(&self) -> String {
        match self {
            PaymentType::BountyDeposit => "bounty_deposit".to_string(),
            PaymentType::BountyReward => "bounty_reward".to_string(),
            PaymentType::StakeLock => "stake_lock".to_string(),
            PaymentType::StakeUnlock => "stake_unlock".to_string(),
            PaymentType::StakeSlash => "stake_slash".to_string(),
            PaymentType::Withdrawal => "withdrawal".to_string(),
            PaymentType::Fee => "fee".to_string(),
            PaymentType::Refund => "refund".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Pending,
    Processing,
    Confirmed,
    Completed,
    Failed,
    Cancelled,
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for PaymentStatus {
    fn to_string(&self) -> String {
        match self {
            PaymentStatus::Pending => "pending".to_string(),
            PaymentStatus::Processing => "processing".to_string(),
            PaymentStatus::Confirmed => "confirmed".to_string(),
            PaymentStatus::Completed => "completed".to_string(),
            PaymentStatus::Failed => "failed".to_string(),
            PaymentStatus::Cancelled => "cancelled".to_string(),
        }
    }
}

/// Stake record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Stake {
    pub id: Uuid,
    pub user_id: Uuid,
    pub bounty_id: Uuid,
    pub submission_id: Option<Uuid>,
    pub address: String,
    pub amount: Decimal,
    pub status: String,
    pub locked_at: DateTime<Utc>,
    pub unlock_at: DateTime<Utc>,
    pub unlocked_at: Option<DateTime<Utc>>,
    pub slashed_amount: Option<Decimal>,
    pub slashed_at: Option<DateTime<Utc>>,
    pub slash_reason: Option<String>,
    pub payment_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StakeStatus {
    Locked,
    Unlocked,
    Slashed,
    PartiallySlashed,
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for StakeStatus {
    fn to_string(&self) -> String {
        match self {
            StakeStatus::Locked => "locked".to_string(),
            StakeStatus::Unlocked => "unlocked".to_string(),
            StakeStatus::Slashed => "slashed".to_string(),
            StakeStatus::PartiallySlashed => "partially_slashed".to_string(),
        }
    }
}

/// User balance record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Balance {
    pub user_id: Uuid,
    pub address: String,
    pub available_balance: Decimal,
    pub locked_balance: Decimal,
    pub total_earned: Decimal,
    pub total_spent: Decimal,
    pub total_staked: Decimal,
    pub updated_at: DateTime<Utc>,
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub from: String,
    pub to: Option<String>,
    pub gas_used: Decimal,
    pub gas_price: Decimal,
    pub status: bool,
    pub logs: Vec<TransactionLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub log_index: u64,
}

/// API Request/Response types
#[derive(Debug, Serialize, Deserialize)]
pub struct DepositBountyRequest {
    pub bounty_id: Uuid,
    pub amount: Decimal,
    pub creator_address: String,
    pub token_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DistributeBountyRequest {
    pub bounty_id: Uuid,
    pub winner_address: String,
    pub winner_user_id: Uuid,
    pub submission_id: Uuid,
    pub amount: Decimal,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockStakeRequest {
    pub user_id: Uuid,
    pub bounty_id: Uuid,
    pub submission_id: Option<Uuid>,
    pub address: String,
    pub amount: Decimal,
    pub lock_duration_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockStakeRequest {
    pub stake_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlashStakeRequest {
    pub stake_id: Uuid,
    pub slash_amount: Decimal,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub user_id: Uuid,
    pub from_address: String,
    pub to_address: String,
    pub amount: Decimal,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EstimateGasRequest {
    pub payment_type: PaymentType,
    pub from_address: String,
    pub to_address: String,
    pub amount: Decimal,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub success: bool,
    pub payment_id: Option<Uuid>,
    pub tx_hash: Option<String>,
    pub message: String,
    pub estimated_completion_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub address: String,
    pub available_balance: Decimal,
    pub locked_balance: Decimal,
    pub total_balance: Decimal,
    pub total_earned: Decimal,
    pub total_spent: Decimal,
    pub total_staked: Decimal,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionStatusResponse {
    pub payment_id: Uuid,
    pub status: PaymentStatus,
    pub tx_hash: Option<String>,
    pub block_number: Option<i64>,
    pub confirmations: Option<u64>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GasEstimate {
    pub estimated_gas: Decimal,
    pub gas_price_gwei: Decimal,
    pub total_cost_eth: Decimal,
    pub total_cost_usd: Option<Decimal>,
}

/// Blockchain transaction parameters
#[derive(Debug, Clone)]
pub struct TxParams {
    pub from: String,
    pub to: String,
    pub value: Decimal,
    pub data: Option<Vec<u8>>,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<Decimal>,
    pub nonce: Option<u64>,
}
