use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub consensus: ConsensusConfig,
    pub grading: GradingConfig,
    pub commit_reveal: CommitRevealConfig,
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
pub struct ConsensusConfig {
    pub min_submissions: usize,
    pub max_submissions: usize,
    pub consensus_threshold: f64,
    pub weighted_voting: bool,
    pub reputation_weight: f64,
    pub confidence_weight: f64,
    pub time_weight: f64,
    pub dispute_threshold: f64,
    pub auto_finalize_hours: u64,
}

/// Delayed re-grading of finalized consensus results.
///
/// A finalized verdict is the crowd's opinion. After `delay_hours` we go back,
/// re-check the sample, and record what we believe now. Held-back payouts and
/// reputation settle against that grade instead of the original vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradingConfig {
    /// Master switch. Off by default: grading moves money, so it must be
    /// turned on deliberately per environment.
    pub enabled: bool,
    /// How long after finalization before a result is re-checked.
    /// Production default is 30 days; set it to minutes in testing so you do
    /// not have to wait a month to see the loop work.
    pub delay_hours: u64,
    /// How often the worker looks for due bounties.
    pub poll_interval_secs: u64,
    /// Max bounties graded per pass, so one tick cannot stampede the engine.
    pub batch_size: i64,
    /// Base URL of analysis-engine, used to re-scan a sample by hash.
    pub analysis_engine_url: String,
    /// Timeout for a single re-scan call.
    pub rescan_timeout_secs: u64,
}

/// Commit-reveal voting.
///
/// While the commit window is open a voter submits only a hash of their
/// verdict, so nobody can see -- or copy -- what anyone else chose. Once it
/// shuts, voters publish the plaintext and the hash is verified.
///
/// Off by default: turning it on changes the voting API, so it is a
/// deliberate per-environment switch rather than something that appears
/// under an existing deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRevealConfig {
    pub enabled: bool,
    /// How long commits are accepted, measured from the bounty's first commit.
    pub commit_window_hours: u64,
    /// How long reveals are accepted after the commit window shuts.
    pub reveal_window_hours: u64,
    /// Shortest salt a voter may use. A short salt is brute-forceable: with a
    /// handful of verdict/confidence combinations, an observer who can guess
    /// the salt can invert the commitment and learn the vote early, which
    /// defeats the entire mechanism.
    pub min_salt_len: usize,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            server: ServerConfig {
                host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: std::env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8087".to_string())
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
            consensus: ConsensusConfig {
                min_submissions: std::env::var("MIN_SUBMISSIONS")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()?,
                max_submissions: std::env::var("MAX_SUBMISSIONS")
                    .unwrap_or_else(|_| "100".to_string())
                    .parse()?,
                consensus_threshold: std::env::var("CONSENSUS_THRESHOLD")
                    .unwrap_or_else(|_| "0.66".to_string())
                    .parse()?,
                weighted_voting: std::env::var("WEIGHTED_VOTING")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
                reputation_weight: std::env::var("REPUTATION_WEIGHT")
                    .unwrap_or_else(|_| "0.5".to_string())
                    .parse()?,
                confidence_weight: std::env::var("CONFIDENCE_WEIGHT")
                    .unwrap_or_else(|_| "0.3".to_string())
                    .parse()?,
                time_weight: std::env::var("TIME_WEIGHT")
                    .unwrap_or_else(|_| "0.2".to_string())
                    .parse()?,
                dispute_threshold: std::env::var("DISPUTE_THRESHOLD")
                    .unwrap_or_else(|_| "0.4".to_string())
                    .parse()?,
                auto_finalize_hours: std::env::var("AUTO_FINALIZE_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse()?,
            },
            grading: GradingConfig {
                enabled: std::env::var("GRADING_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                delay_hours: std::env::var("GRADING_DELAY_HOURS")
                    .unwrap_or_else(|_| "720".to_string()) // 30 days
                    .parse()?,
                poll_interval_secs: std::env::var("GRADING_POLL_INTERVAL_SECS")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()?,
                batch_size: std::env::var("GRADING_BATCH_SIZE")
                    .unwrap_or_else(|_| "50".to_string())
                    .parse()?,
                analysis_engine_url: std::env::var("ANALYSIS_ENGINE_URL")
                    .unwrap_or_else(|_| "http://analysis-engine:8080".to_string()),
                rescan_timeout_secs: std::env::var("GRADING_RESCAN_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "120".to_string())
                    .parse()?,
            },
            commit_reveal: CommitRevealConfig {
                enabled: std::env::var("COMMIT_REVEAL_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                commit_window_hours: std::env::var("COMMIT_WINDOW_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse()?,
                reveal_window_hours: std::env::var("REVEAL_WINDOW_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse()?,
                min_salt_len: std::env::var("MIN_SALT_LEN")
                    .unwrap_or_else(|_| "16".to_string())
                    .parse()?,
            },
        })
    }
}
