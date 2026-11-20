use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub blockchain: BlockchainConfig,
    pub payment: PaymentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub treasury_address: String,
    pub token_contract_address: String,
    pub payment_contract_address: String,
    pub gas_price_multiplier: f64,
    pub max_gas_price_gwei: u64,
    pub confirmation_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConfig {
    pub min_withdraw_amount: String, // Wei amount
    pub max_withdraw_amount: String, // Wei amount
    pub withdraw_fee_percentage: f64,
    pub stake_lock_duration_seconds: u64,
    pub transaction_timeout_seconds: u64,
    pub max_retry_attempts: u32,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            server: ServerConfig {
                host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: std::env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8085".to_string())
                    .parse()?,
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL")?,
                max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
            },
            redis: RedisConfig {
                url: std::env::var("REDIS_URL")
                    .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            },
            blockchain: BlockchainConfig {
                rpc_url: std::env::var("BLOCKCHAIN_RPC_URL")?,
                chain_id: std::env::var("BLOCKCHAIN_CHAIN_ID")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()?,
                treasury_address: std::env::var("TREASURY_ADDRESS")?,
                token_contract_address: std::env::var("TOKEN_CONTRACT_ADDRESS")?,
                payment_contract_address: std::env::var("PAYMENT_CONTRACT_ADDRESS")?,
                gas_price_multiplier: std::env::var("GAS_PRICE_MULTIPLIER")
                    .unwrap_or_else(|_| "1.2".to_string())
                    .parse()?,
                max_gas_price_gwei: std::env::var("MAX_GAS_PRICE_GWEI")
                    .unwrap_or_else(|_| "500".to_string())
                    .parse()?,
                confirmation_blocks: std::env::var("CONFIRMATION_BLOCKS")
                    .unwrap_or_else(|_| "12".to_string())
                    .parse()?,
            },
            payment: PaymentConfig {
                min_withdraw_amount: std::env::var("MIN_WITHDRAW_AMOUNT")
                    .unwrap_or_else(|_| "1000000000000000000".to_string()), // 1 token
                max_withdraw_amount: std::env::var("MAX_WITHDRAW_AMOUNT")
                    .unwrap_or_else(|_| "1000000000000000000000".to_string()), // 1000 tokens
                withdraw_fee_percentage: std::env::var("WITHDRAW_FEE_PERCENTAGE")
                    .unwrap_or_else(|_| "0.5".to_string())
                    .parse()?,
                stake_lock_duration_seconds: std::env::var("STAKE_LOCK_DURATION")
                    .unwrap_or_else(|_| "86400".to_string()) // 24 hours
                    .parse()?,
                transaction_timeout_seconds: std::env::var("TRANSACTION_TIMEOUT")
                    .unwrap_or_else(|_| "300".to_string()) // 5 minutes
                    .parse()?,
                max_retry_attempts: std::env::var("MAX_RETRY_ATTEMPTS")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()?,
            },
        })
    }
}
