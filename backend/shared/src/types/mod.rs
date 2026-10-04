//! Shared type definitions for the Verdyx threat intelligence platform
//!
//! This module contains all the common data structures, enums, and types used across
//! different services in the backend. It includes:
//!
//! - Core identifier types (UserId, BountyId, etc.)
//! - Blockchain-related types (addresses, transaction hashes)
//! - Analysis structures (verdicts, submissions, results)
//! - User and reputation system types
//! - API response structures
//! - WebSocket message types
//! - Error types and validation utilities

pub mod common;

// Re-export commonly used types for easier imports
pub use common::{
    AnalysisData,

    AnalysisId,
    AnalysisStatus,
    // Submissions and analysis
    AnalysisSubmission,
    AnalysisTarget,
    ApiCall,

    ApiError,
    // API types
    ApiResponse,
    BlockNumber,
    BountyId,
    // Bounty system
    BountyInfo,
    BountyStatus,

    CertificateInfo,
    // Errors
    CommonError,
    DynamicAnalysisResult,
    EngineId,

    EngineInfo,
    EngineMetrics,

    EngineType,
    // Blockchain types
    EthereumAddress,
    ExtractedString,
    FileOpType,
    FileOperation,
    HashType,

    // Indicators of Compromise
    IoC,
    IoCType,

    NetworkActivity,
    PEInfo,
    PaginatedResponse,

    ProcessActivity,
    RegistryOpType,
    RegistryOperation,
    SectionInfo,
    // Analysis results
    StaticAnalysisResult,
    StringEncoding,
    SubmissionId,
    SubmissionStatus,
    // Analysis types
    ThreatVerdict,
    TokenAmount,

    TransactionHash,
    // Core identifiers
    UserId,
    // User system
    UserInfo,
    // WebSocket messages
    WebSocketMessage,

    // YARA matching
    YaraMatch,
    YaraString,
    YaraStringMatch,

    DEFAULT_BOUNTY_DURATION,
    MAX_ANALYSIS_TIME,

    MAX_CONFIDENCE_SCORE,
    // Constants
    MAX_FILE_SIZE,
    MIN_CONFIDENCE_SCORE,
    MIN_STAKE_AMOUNT,
};

/// Empty body type for validation middleware (used when no body is expected)
#[derive(Debug, Clone, Copy, Default, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct EmptyBody;

impl validator::Validate for EmptyBody {}

// Type aliases for commonly used Result types
pub type Result<T> = std::result::Result<T, CommonError>;
pub type ApiResult<T> = std::result::Result<ApiResponse<T>, CommonError>;

// Additional utility functions that operate on the common types
impl BountyInfo {
    /// Check if the bounty is still active and accepting submissions
    pub fn is_accepting_submissions(&self) -> bool {
        matches!(self.status, BountyStatus::Active)
            && chrono::Utc::now() < self.expires_at
            && self
                .max_submissions
                .is_none_or(|max| self.current_submissions < max)
    }

    /// Check if the bounty has expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Get the remaining time until expiry in seconds
    pub fn time_until_expiry(&self) -> i64 {
        (self.expires_at - chrono::Utc::now()).num_seconds().max(0)
    }

    /// Get the completion percentage based on submissions
    pub fn completion_percentage(&self) -> f32 {
        if let Some(max) = self.max_submissions {
            (self.current_submissions as f32 / max as f32 * 100.0).min(100.0)
        } else {
            0.0 // Unlimited submissions
        }
    }
}

impl AnalysisSubmission {
    /// Check if this submission can still be modified
    pub fn is_modifiable(&self) -> bool {
        matches!(self.status, SubmissionStatus::Pending)
    }

    /// Check if this submission has been finalized (either rewarded or slashed)
    pub fn is_finalized(&self) -> bool {
        matches!(
            self.status,
            SubmissionStatus::Rewarded | SubmissionStatus::Slashed
        )
    }

    /// Get the potential reward amount based on confidence and stake
    pub fn potential_reward(&self, base_reward: TokenAmount) -> TokenAmount {
        // Higher confidence gets higher reward multiplier
        let confidence_multiplier = self.confidence_score as f64;
        (base_reward as f64 * confidence_multiplier) as TokenAmount
    }
}

impl UserInfo {
    /// Calculate the user's success rate
    pub fn success_rate(&self) -> f32 {
        if self.total_submissions == 0 {
            0.0
        } else {
            self.successful_submissions as f32 / self.total_submissions as f32
        }
    }

    /// Check if the user is considered an expert (high reputation and success rate)
    pub fn is_expert(&self) -> bool {
        self.reputation_score >= 1000 && self.success_rate() >= 0.85 && self.total_submissions >= 50
    }

    /// Get the user's trust level based on reputation and verification status
    pub fn trust_level(&self) -> TrustLevel {
        if !self.is_verified {
            return TrustLevel::Unverified;
        }

        match self.reputation_score {
            score if score >= 10000 => TrustLevel::Elite,
            score if score >= 5000 => TrustLevel::Expert,
            score if score >= 1000 => TrustLevel::Trusted,
            score if score >= 100 => TrustLevel::Established,
            score if score >= 0 => TrustLevel::New,
            _ => TrustLevel::Suspicious,
        }
    }

    /// Calculate net profit/loss
    pub fn net_earnings(&self) -> i128 {
        self.total_earned as i128 - self.total_staked as i128
    }
}

/// User trust levels based on reputation and verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Suspicious = -1,
    Unverified = 0,
    New = 1,
    Established = 2,
    Trusted = 3,
    Expert = 4,
    Elite = 5,
}

impl TrustLevel {
    /// Get the minimum stake multiplier for this trust level
    pub fn stake_multiplier(&self) -> f32 {
        match self {
            TrustLevel::Suspicious => 5.0, // Higher stake requirement
            TrustLevel::Unverified => 3.0,
            TrustLevel::New => 2.0,
            TrustLevel::Established => 1.5,
            TrustLevel::Trusted => 1.0,
            TrustLevel::Expert => 0.8,
            TrustLevel::Elite => 0.5, // Lower stake requirement
        }
    }

    /// Get the maximum allowed bounty amount for this trust level
    pub fn max_bounty_amount(&self) -> TokenAmount {
        match self {
            TrustLevel::Suspicious => 0, // Cannot create bounties
            TrustLevel::Unverified => 1_000_000_000_000_000_000, // 1 token
            TrustLevel::New => 10_000_000_000_000_000_000, // 10 tokens
            TrustLevel::Established => 100_000_000_000_000_000_000, // 100 tokens
            TrustLevel::Trusted => 1_000_000_000_000_000_000_000, // 1,000 tokens
            TrustLevel::Expert => 10_000_000_000_000_000_000_000, // 10,000 tokens
            TrustLevel::Elite => u128::MAX, // Unlimited
        }
    }
}

impl EngineMetrics {
    /// Calculate the overall engine score based on various metrics
    pub fn overall_score(&self) -> f32 {
        let accuracy_weight = 0.5;
        let speed_weight = 0.2;
        let reliability_weight = 0.3;

        // Normalize response time (faster is better, cap at 10 seconds)
        let speed_score = (10000.0 - self.response_time_avg.min(10000) as f32) / 10000.0;

        // Reliability based on total analyses (more analyses = more reliable)
        let reliability_score = (self.total_analyses as f32).min(1000.0) / 1000.0;

        (self.accuracy_rate * accuracy_weight)
            + (speed_score * speed_weight)
            + (reliability_score * reliability_weight)
    }

    /// Check if the engine meets minimum quality standards
    pub fn meets_quality_standards(&self) -> bool {
        self.accuracy_rate >= 0.8 && self.total_analyses >= 10 && self.response_time_avg <= 60000
        // 1 minute max
    }
}

impl<T> ApiResponse<T> {
    /// Create a successful API response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create an error API response
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ApiError {
                code: code.into(),
                message: message.into(),
                details: None,
            }),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create an error API response with details
    pub fn error_with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ApiError {
                code: code.into(),
                message: message.into(),
                details: Some(details),
            }),
            timestamp: chrono::Utc::now(),
        }
    }
}

impl<T> PaginatedResponse<T> {
    /// Create a new paginated response
    pub fn new(items: Vec<T>, total: u64, page: u32, page_size: u32) -> Self {
        let has_more = (page * page_size) < total as u32;
        Self {
            items,
            total,
            page,
            page_size,
            has_more,
        }
    }

    /// Get the total number of pages
    pub fn total_pages(&self) -> u32 {
        ((self.total as f64) / (self.page_size as f64)).ceil() as u32
    }

    /// Check if this is the first page
    pub fn is_first_page(&self) -> bool {
        self.page == 1
    }

    /// Check if this is the last page
    pub fn is_last_page(&self) -> bool {
        !self.has_more
    }
}

// Validation utilities
pub mod validation {
    use super::*;

    /// Validate that a confidence score is within the valid range
    pub fn validate_confidence_score(score: f32) -> Result<()> {
        if !(MIN_CONFIDENCE_SCORE..=MAX_CONFIDENCE_SCORE).contains(&score) {
            Err(CommonError::ValidationFailed(format!(
                "Confidence score must be between {MIN_CONFIDENCE_SCORE} and {MAX_CONFIDENCE_SCORE}"
            )))
        } else {
            Ok(())
        }
    }

    /// Validate that a stake amount meets the minimum requirement
    pub fn validate_stake_amount(amount: TokenAmount) -> Result<()> {
        if amount < MIN_STAKE_AMOUNT {
            Err(CommonError::ValidationFailed(format!(
                "Stake amount must be at least {MIN_STAKE_AMOUNT} wei"
            )))
        } else {
            Ok(())
        }
    }

    /// Validate Ethereum address format (basic check)
    pub fn validate_ethereum_address(address: &str) -> Result<()> {
        if address.len() != 42 || !address.starts_with("0x") {
            Err(CommonError::ValidationFailed(
                "Invalid Ethereum address format".to_string(),
            ))
        } else if !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            Err(CommonError::ValidationFailed(
                "Ethereum address contains invalid characters".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Validate hash format based on type
    pub fn validate_hash(hash_type: &HashType, hash_value: &str) -> Result<()> {
        let expected_length = match hash_type {
            HashType::Md5 => 32,
            HashType::Sha1 => 40,
            HashType::Sha256 => 64,
            HashType::Sha512 => 128,
        };

        if hash_value.len() != expected_length {
            return Err(CommonError::ValidationFailed(format!(
                "Invalid {} hash length. Expected {}, got {}",
                format!("{hash_type:?}").to_lowercase(),
                expected_length,
                hash_value.len()
            )));
        }

        if !hash_value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CommonError::ValidationFailed(
                "Hash contains invalid characters".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::str::FromStr;

    #[test]
    fn test_bounty_is_accepting_submissions() {
        let mut bounty = BountyInfo {
            id: uuid::Uuid::new_v4(),
            creator: uuid::Uuid::new_v4(),
            title: "Test Bounty".to_string(),
            description: "Test Description".to_string(),
            reward_amount: 1000,
            stake_requirement: 100,
            target: AnalysisTarget::Hash {
                hash_type: HashType::Sha256,
                hash_value: "test".to_string(),
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            status: BountyStatus::Active,
            max_submissions: Some(10),
            current_submissions: 5,
            tags: vec![],
            metadata: std::collections::HashMap::new(),
        };

        assert!(bounty.is_accepting_submissions());

        // Test with expired bounty
        bounty.expires_at = Utc::now() - Duration::hours(1);
        assert!(!bounty.is_accepting_submissions());

        // Test with max submissions reached
        bounty.expires_at = Utc::now() + Duration::hours(24);
        bounty.current_submissions = 10;
        assert!(!bounty.is_accepting_submissions());

        // Test with inactive status
        bounty.current_submissions = 5;
        bounty.status = BountyStatus::Completed;
        assert!(!bounty.is_accepting_submissions());
    }

    #[test]
    fn test_user_success_rate() {
        let user = UserInfo {
            id: uuid::Uuid::new_v4(),
            username: "test_user".to_string(),
            email: "test@example.com".to_string(),
            ethereum_address: "0x1234567890123456789012345678901234567890".to_string(),
            reputation_score: 1000,
            total_submissions: 100,
            successful_submissions: 85,
            total_earned: 10000,
            total_staked: 5000,
            specializations: vec!["malware".to_string()],
            created_at: Utc::now(),
            last_active: Utc::now(),
            is_verified: true,
            engine_info: None,
        };

        assert_eq!(user.success_rate(), 0.85);
        assert!(user.is_expert());
        assert_eq!(user.trust_level(), TrustLevel::Trusted);
        assert_eq!(user.net_earnings(), 5000);
    }

    #[test]
    fn test_threat_verdict_conversion() {
        assert_eq!(
            ThreatVerdict::from_str("malicious").unwrap(),
            ThreatVerdict::Malicious
        );
        assert_eq!(
            ThreatVerdict::from_str("BENIGN").unwrap(),
            ThreatVerdict::Benign
        );
        assert_eq!(
            ThreatVerdict::from_str("Suspicious").unwrap(),
            ThreatVerdict::Suspicious
        );
        assert_eq!(
            ThreatVerdict::from_str("unknown").unwrap(),
            ThreatVerdict::Unknown
        );
        assert!(ThreatVerdict::from_str("invalid").is_err());

        assert_eq!(ThreatVerdict::Malicious.to_string(), "malicious");
        assert_eq!(ThreatVerdict::default(), ThreatVerdict::Unknown);
    }

    #[test]
    fn test_trust_level_multipliers() {
        assert_eq!(TrustLevel::Elite.stake_multiplier(), 0.5);
        assert_eq!(TrustLevel::Suspicious.stake_multiplier(), 5.0);

        assert_eq!(TrustLevel::Elite.max_bounty_amount(), u128::MAX);
        assert_eq!(TrustLevel::Suspicious.max_bounty_amount(), 0);
    }

    #[test]
    fn test_validation_functions() {
        use validation::*;

        // Test confidence score validation
        assert!(validate_confidence_score(0.5).is_ok());
        assert!(validate_confidence_score(-0.1).is_err());
        assert!(validate_confidence_score(1.1).is_err());

        // Test stake amount validation
        assert!(validate_stake_amount(MIN_STAKE_AMOUNT).is_ok());
        assert!(validate_stake_amount(MIN_STAKE_AMOUNT - 1).is_err());

        // Test Ethereum address validation
        assert!(validate_ethereum_address("0x1234567890123456789012345678901234567890").is_ok());
        assert!(validate_ethereum_address("0x123").is_err()); // Too short
        assert!(validate_ethereum_address("1234567890123456789012345678901234567890").is_err()); // No 0x prefix
        assert!(validate_ethereum_address("0x123456789012345678901234567890123456789g").is_err()); // Invalid character

        // Test hash validation
        assert!(validate_hash(
            &HashType::Sha256,
            "1234567890123456789012345678901234567890123456789012345678901234"
        )
        .is_ok());
        assert!(validate_hash(&HashType::Sha256, "123").is_err()); // Too short
        assert!(validate_hash(&HashType::Md5, "12345678901234567890123456789012").is_ok());
        assert!(validate_hash(&HashType::Md5, "1234567890123456789012345678901g").is_err());
        // Invalid character
    }

    #[test]
    fn test_paginated_response() {
        let items = vec![1, 2, 3, 4, 5];
        let response = PaginatedResponse::new(items, 100, 1, 5);

        assert_eq!(response.total_pages(), 20);
        assert!(response.is_first_page());
        assert!(!response.is_last_page());
        assert!(response.has_more);

        let last_page = PaginatedResponse::new(vec![96, 97, 98, 99, 100], 100, 20, 5);
        assert!(!last_page.is_first_page());
        assert!(last_page.is_last_page());
        assert!(!last_page.has_more);
    }

    #[test]
    fn test_engine_metrics() {
        let metrics = EngineMetrics {
            accuracy_rate: 0.95,
            response_time_avg: 2000, // 2 seconds
            total_analyses: 500,
            false_positives: 10,
            false_negatives: 15,
            last_updated: Utc::now(),
        };

        assert!(metrics.meets_quality_standards());
        assert!(metrics.overall_score() > 0.75);

        let poor_metrics = EngineMetrics {
            accuracy_rate: 0.6,       // Below threshold
            response_time_avg: 70000, // Too slow
            total_analyses: 5,        // Too few analyses
            false_positives: 20,
            false_negatives: 25,
            last_updated: Utc::now(),
        };

        assert!(!poor_metrics.meets_quality_standards());
    }

    #[test]
    fn test_analysis_target_identifier() {
        let file_target = AnalysisTarget::File {
            filename: "test.exe".to_string(),
            file_hash: "abcd1234".to_string(),
            file_size: 1024,
            mime_type: "application/octet-stream".to_string(),
            content_url: "https://example.com/file".to_string(),
        };

        let url_target = AnalysisTarget::Url {
            url: "https://malicious.com".to_string(),
            domain: "malicious.com".to_string(),
        };

        let hash_target = AnalysisTarget::Hash {
            hash_type: HashType::Sha256,
            hash_value: "1234abcd".to_string(),
        };

        assert_eq!(file_target.get_identifier(), "abcd1234");
        assert_eq!(url_target.get_identifier(), "https://malicious.com");
        assert_eq!(hash_target.get_identifier(), "1234abcd");
    }

    #[test]
    fn test_api_response_creation() {
        let success_response = ApiResponse::success("test data");
        assert!(success_response.success);
        assert_eq!(success_response.data.unwrap(), "test data");
        assert!(success_response.error.is_none());

        let error_response: ApiResponse<String> = ApiResponse::error("ERR001", "Test error");
        assert!(!error_response.success);
        assert!(error_response.data.is_none());
        assert!(error_response.error.is_some());

        let error = error_response.error.unwrap();
        assert_eq!(error.code, "ERR001");
        assert_eq!(error.message, "Test error");
    }
}
