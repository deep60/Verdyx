// backend/bounty-manager/src/config.rs

use serde::{Deserialize, Serialize};
use std::env;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub blockchain: BlockchainConfig,
    pub redis: RedisConfig,
    pub bounty: BountyConfig,
    pub consensus: ConsensusConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
    pub idle_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub gas_price_gwei: u64,
    pub confirmation_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyConfig {
    pub min_stake_amount: u64,
    pub max_participants: u32,
    pub default_deadline_hours: u64,
    pub min_quality_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub min_submissions: u32,
    pub consensus_threshold: f32,
    pub voting_window_hours: u64,
    pub enable_weighted_voting: bool,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Config {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "3002".to_string())
                    .parse()
                    .map_err(|_| ConfigError::InvalidPort)?,
                workers: env::var("SERVER_WORKERS")
                    .unwrap_or_else(|_| "4".to_string())
                    .parse()
                    .unwrap_or(4),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL").unwrap_or_else(|_| {
                    "postgresql://verdyx:password@localhost/verdyx".to_string()
                }),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "20".to_string())
                    .parse()
                    .unwrap_or(20),
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or(5),
                connect_timeout: env::var("DB_CONNECT_TIMEOUT")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .unwrap_or(30),
                idle_timeout: env::var("DB_IDLE_TIMEOUT")
                    .unwrap_or_else(|_| "600".to_string())
                    .parse()
                    .unwrap_or(600),
            },
            blockchain: BlockchainConfig {
                rpc_url: env::var("BLOCKCHAIN_RPC_URL")
                    .unwrap_or_else(|_| "http://localhost:8545".to_string()),
                chain_id: env::var("BLOCKCHAIN_CHAIN_ID")
                    .unwrap_or_else(|_| "1337".to_string())
                    .parse()
                    .unwrap_or(1337),
                contract_address: env::var("BOUNTY_CONTRACT_ADDRESS")
                    .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string()),
                gas_price_gwei: env::var("GAS_PRICE_GWEI")
                    .unwrap_or_else(|_| "20".to_string())
                    .parse()
                    .unwrap_or(20),
                confirmation_blocks: env::var("CONFIRMATION_BLOCKS")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()
                    .unwrap_or(3),
            },
            redis: RedisConfig {
                url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
                max_connections: env::var("REDIS_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .unwrap_or(10),
            },
            bounty: BountyConfig {
                min_stake_amount: env::var("MIN_STAKE_AMOUNT")
                    .unwrap_or_else(|_| "1000".to_string())
                    .parse()
                    .unwrap_or(1000),
                max_participants: env::var("MAX_PARTICIPANTS")
                    .unwrap_or_else(|_| "100".to_string())
                    .parse()
                    .unwrap_or(100),
                default_deadline_hours: env::var("DEFAULT_DEADLINE_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse()
                    .unwrap_or(24),
                min_quality_score: env::var("MIN_QUALITY_SCORE")
                    .unwrap_or_else(|_| "0.7".to_string())
                    .parse()
                    .unwrap_or(0.7),
            },
            consensus: ConsensusConfig {
                min_submissions: env::var("MIN_SUBMISSIONS")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()
                    .unwrap_or(3),
                consensus_threshold: env::var("CONSENSUS_THRESHOLD")
                    .unwrap_or_else(|_| "0.75".to_string())
                    .parse()
                    .unwrap_or(0.75),
                voting_window_hours: env::var("VOTING_WINDOW_HOURS")
                    .unwrap_or_else(|_| "48".to_string())
                    .parse()
                    .unwrap_or(48),
                enable_weighted_voting: env::var("ENABLE_WEIGHTED_VOTING")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
            },
        })
    }

    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound)?;

        toml::from_str(&contents).map_err(|_| ConfigError::ParseError)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::InvalidPort);
        }

        if self.database.max_connections == 0 {
            return Err(ConfigError::InvalidConfig(
                "Max connections must be > 0".to_string(),
            ));
        }

        if self.consensus.consensus_threshold < 0.5 || self.consensus.consensus_threshold > 1.0 {
            return Err(ConfigError::InvalidConfig(
                "Consensus threshold must be between 0.5 and 1.0".to_string(),
            ));
        }

        if self.bounty.min_quality_score < 0.0 || self.bounty.min_quality_score > 1.0 {
            return Err(ConfigError::InvalidConfig(
                "Min quality score must be between 0.0 and 1.0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3002,
                workers: 4,
            },
            database: DatabaseConfig {
                url: "postgresql://verdyx:password@localhost/verdyx".to_string(),
                max_connections: 20,
                min_connections: 5,
                connect_timeout: 30,
                idle_timeout: 600,
            },
            blockchain: BlockchainConfig {
                rpc_url: "http://localhost:8545".to_string(),
                chain_id: 1337,
                contract_address: "0x0000000000000000000000000000000000000000".to_string(),
                gas_price_gwei: 20,
                confirmation_blocks: 3,
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
                max_connections: 10,
            },
            bounty: BountyConfig {
                min_stake_amount: 1000,
                max_participants: 100,
                default_deadline_hours: 24,
                min_quality_score: 0.7,
            },
            consensus: ConsensusConfig {
                min_submissions: 3,
                consensus_threshold: 0.75,
                voting_window_hours: 48,
                enable_weighted_voting: true,
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Configuration file not found")]
    FileNotFound,

    #[error("Failed to parse configuration")]
    ParseError,

    #[error("Invalid port number")]
    InvalidPort,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 3002);
        assert_eq!(config.consensus.min_submissions, 3);
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_consensus_threshold() {
        let mut config = Config::default();
        config.consensus.consensus_threshold = 1.5;
        assert!(config.validate().is_err());
    }
}
