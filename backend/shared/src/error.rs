//! Structured error taxonomy for Verdyx services
//!
//! Provides consistent error types across all services with proper
//!
//! - HTTP status code mapping
//! - Error codes for client handling
//! - Structured error responses
//! - Logging context

use std::collections::HashMap;
use thiserror::Error;
use serde::{Serialize, Deserialize};

/// Standard error codes for API responses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // Generic errors
    InternalError,
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServiceUnavailable,
    Timeout,
    
    // Validation errors
    ValidationError,
    InvalidFormat,
    MissingField,
    InvalidFieldValue,
    
    // Authentication/Authorization
    InvalidToken,
    TokenExpired,
    TokenRevoked,
    InvalidCredentials,
    InsufficientPermissions,
    MfaRequired,
    
    // Resource errors
    ResourceNotFound,
    ResourceConflict,
    ResourceLocked,
    QuotaExceeded,
    
    // Business logic errors
    InsufficientFunds,
    InsufficientStake,
    InsufficientReputation,
    BountyExpired,
    BountyCancelled,
    ConsensusNotReached,
    AnalysisAlreadySubmitted,
    InvalidVerdict,
    StakeLocked,
    
    // Blockchain errors
    TransactionFailed,
    ContractError,
    InsufficientGas,
    NonceError,
    RevertError,
    
    // External service errors
    UpstreamError,
    UpstreamTimeout,
    UpstreamUnavailable,
    CircuitOpen,
    
    // Idempotency
    IdempotencyConflict,
    IdempotencyKeyExpired,
}

impl ErrorCode {
    /// HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            // 4xx Client Errors
            ErrorCode::InvalidRequest
            | ErrorCode::ValidationError
            | ErrorCode::InvalidFormat
            | ErrorCode::MissingField
            | ErrorCode::InvalidFieldValue
            | ErrorCode::InvalidCredentials
            | ErrorCode::MfaRequired => 400,
            
            ErrorCode::Unauthorized
            | ErrorCode::InvalidToken
            | ErrorCode::TokenExpired
            | ErrorCode::TokenRevoked => 401,
            
            ErrorCode::Forbidden
            | ErrorCode::InsufficientPermissions => 403,
            
            ErrorCode::NotFound
            | ErrorCode::ResourceNotFound => 404,
            
            ErrorCode::Conflict
            | ErrorCode::ResourceConflict
            | ErrorCode::ResourceLocked
            | ErrorCode::IdempotencyConflict => 409,
            
            ErrorCode::RateLimited => 429,
            
            ErrorCode::QuotaExceeded => 429,
            
            // 5xx Server Errors
            ErrorCode::InternalError
            | ErrorCode::ServiceUnavailable
            | ErrorCode::UpstreamError
            | ErrorCode::UpstreamUnavailable
            | ErrorCode::CircuitOpen => 503,
            
            ErrorCode::Timeout
            | ErrorCode::UpstreamTimeout => 504,
            
            // Business logic - use 400/422
            ErrorCode::InsufficientFunds
            | ErrorCode::InsufficientStake
            | ErrorCode::InsufficientReputation
            | ErrorCode::BountyExpired
            | ErrorCode::BountyCancelled
            | ErrorCode::ConsensusNotReached
            | ErrorCode::AnalysisAlreadySubmitted
            | ErrorCode::InvalidVerdict
            | ErrorCode::StakeLocked => 422,
            
            ErrorCode::TransactionFailed
            | ErrorCode::ContractError
            | ErrorCode::InsufficientGas
            | ErrorCode::NonceError
            | ErrorCode::RevertError => 502,
            
            ErrorCode::IdempotencyKeyExpired => 410,
        }
    }
    
    /// Human-readable message
    pub fn default_message(&self) -> &'static str {
        match self {
            ErrorCode::InternalError => "An internal server error occurred",
            ErrorCode::InvalidRequest => "The request is invalid",
            ErrorCode::Unauthorized => "Authentication required",
            ErrorCode::Forbidden => "Access denied",
            ErrorCode::NotFound => "Resource not found",
            ErrorCode::Conflict => "Resource conflict",
            ErrorCode::RateLimited => "Too many requests",
            ErrorCode::ServiceUnavailable => "Service temporarily unavailable",
            ErrorCode::Timeout => "Request timed out",
            ErrorCode::ValidationError => "Validation failed",
            ErrorCode::InvalidFormat => "Invalid format",
            ErrorCode::MissingField => "Required field missing",
            ErrorCode::InvalidFieldValue => "Invalid field value",
            ErrorCode::InvalidToken => "Invalid or malformed token",
            ErrorCode::TokenExpired => "Token has expired",
            ErrorCode::TokenRevoked => "Token has been revoked",
            ErrorCode::InvalidCredentials => "Invalid credentials",
            ErrorCode::InsufficientPermissions => "Insufficient permissions",
            ErrorCode::MfaRequired => "Multi-factor authentication required",
            ErrorCode::ResourceNotFound => "Resource not found",
            ErrorCode::ResourceConflict => "Resource already exists",
            ErrorCode::ResourceLocked => "Resource is locked",
            ErrorCode::QuotaExceeded => "Quota exceeded",
            ErrorCode::InsufficientFunds => "Insufficient funds",
            ErrorCode::InsufficientStake => "Insufficient stake amount",
            ErrorCode::InsufficientReputation => "Insufficient reputation",
            ErrorCode::BountyExpired => "Bounty has expired",
            ErrorCode::BountyCancelled => "Bounty was cancelled",
            ErrorCode::ConsensusNotReached => "Consensus not reached",
            ErrorCode::AnalysisAlreadySubmitted => "Analysis already submitted",
            ErrorCode::InvalidVerdict => "Invalid verdict",
            ErrorCode::StakeLocked => "Stake is still locked",
            ErrorCode::TransactionFailed => "Blockchain transaction failed",
            ErrorCode::ContractError => "Smart contract error",
            ErrorCode::InsufficientGas => "Insufficient gas for transaction",
            ErrorCode::NonceError => "Invalid transaction nonce",
            ErrorCode::RevertError => "Transaction reverted",
            ErrorCode::UpstreamError => "Upstream service error",
            ErrorCode::UpstreamTimeout => "Upstream service timeout",
            ErrorCode::UpstreamUnavailable => "Upstream service unavailable",
            ErrorCode::CircuitOpen => "Circuit breaker open",
            ErrorCode::IdempotencyConflict => "Idempotency key conflict",
            ErrorCode::IdempotencyKeyExpired => "Idempotency key expired",
        }
    }
}

/// Structured API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            request_id: None,
            trace_id: None,
        }
    }
    
    pub fn with_details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = Some(details);
        self
    }
    
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
    
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }
    
    pub fn status_code(&self) -> u16 {
        self.code.status_code()
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = axum::http::StatusCode::from_u16(self.status_code())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        
        let mut response = axum::Json(self).into_response();
        *response.status_mut() = status;
        response
    }
}

/// Main error type for Verdyx services
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Validation errors: {0:?}")]
    ValidationErrors(Vec<ValidationError>),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Rate limited: {0}")]
    RateLimited(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Blockchain error: {0}")]
    Blockchain(#[from] BlockchainError),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    
    #[error("External service error: {service} - {message}")]
    Upstream { service: String, message: String },
    
    #[error("Circuit breaker open for {service}")]
    CircuitOpen { service: String },
    
    #[error("Idempotency conflict: {key}")]
    IdempotencyConflict { key: String },
    
    #[error("Idempotency key expired: {key}")]
    IdempotencyKeyExpired { key: String },
    
    #[error("Business logic error: {code:?} - {message}")]
    Business { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum BlockchainError {
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    
    #[error("Contract error: {0}")]
    ContractError(String),
    
    #[error("Insufficient gas: {0}")]
    InsufficientGas(String),
    
    #[error("Nonce error: {0}")]
    NonceError(String),
    
    #[error("Revert: {0}")]
    Revert(String),
    
    #[error("Provider error: {0}")]
    ProviderError(String),
}

impl AppError {
    /// Convert to API error response
    pub fn to_api_error(&self, request_id: Option<String>) -> ApiError {
        match self {
            AppError::Internal(e) => ApiError::new(
                ErrorCode::InternalError,
                "An internal server error occurred"
            )
            .with_request_id(request_id.unwrap_or_default())
            .with_details(HashMap::from([("detail".into(), e.to_string().into())])),
            
            AppError::Validation(msg) => ApiError::new(
                ErrorCode::ValidationError,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::ValidationErrors(errors) => {
                let mut details = HashMap::new();
                details.insert("errors".into(), serde_json::to_value(errors).unwrap_or_default());
                ApiError::new(ErrorCode::ValidationError, "Validation failed")
                    .with_details(details)
                    .with_request_id(request_id.unwrap_or_default())
            }
            
            AppError::Unauthorized(msg) => ApiError::new(
                ErrorCode::Unauthorized,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::Forbidden(msg) => ApiError::new(
                ErrorCode::Forbidden,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::NotFound(msg) => ApiError::new(
                ErrorCode::NotFound,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::Conflict(msg) => ApiError::new(
                ErrorCode::Conflict,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::RateLimited(msg) => ApiError::new(
                ErrorCode::RateLimited,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::ServiceUnavailable(msg) => ApiError::new(
                ErrorCode::ServiceUnavailable,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::Timeout(msg) => ApiError::new(
                ErrorCode::Timeout,
                msg
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::Blockchain(e) => {
                let (code, msg) = match e {
                    BlockchainError::TransactionFailed(m) => (ErrorCode::TransactionFailed, m),
                    BlockchainError::ContractError(m) => (ErrorCode::ContractError, m),
                    BlockchainError::InsufficientGas(m) => (ErrorCode::InsufficientGas, m),
                    BlockchainError::NonceError(m) => (ErrorCode::NonceError, m),
                    BlockchainError::Revert(m) => (ErrorCode::RevertError, m),
                    BlockchainError::ProviderError(m) => (ErrorCode::UpstreamError, m),
                };
                ApiError::new(code, msg).with_request_id(request_id.unwrap_or_default())
            }
            
            AppError::Database(e) => ApiError::new(
                ErrorCode::InternalError,
                "Database error"
            ).with_request_id(request_id.unwrap_or_default())
            .with_details(HashMap::from([("detail".into(), e.to_string().into())])),
            
            AppError::Redis(e) => ApiError::new(
                ErrorCode::InternalError,
                "Cache error"
            ).with_request_id(request_id.unwrap_or_default())
            .with_details(HashMap::from([("detail".into(), e.to_string().into())])),
            
            AppError::Upstream { service, message } => ApiError::new(
                ErrorCode::UpstreamError,
                format!("{service}: {message}")
            ).with_request_id(request_id.unwrap_or_default())
            .with_details(HashMap::from([("service".into(), service.clone().into())])),
            
            AppError::CircuitOpen { service } => ApiError::new(
                ErrorCode::CircuitOpen,
                format!("Circuit breaker open for {service}")
            ).with_request_id(request_id.unwrap_or_default())
            .with_details(HashMap::from([("service".into(), service.clone().into())])),
            
            AppError::IdempotencyConflict { key } => ApiError::new(
                ErrorCode::IdempotencyConflict,
                format!("Idempotency key conflict: {key}")
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::IdempotencyKeyExpired { key } => ApiError::new(
                ErrorCode::IdempotencyKeyExpired,
                format!("Idempotency key expired: {key}")
            ).with_request_id(request_id.unwrap_or_default()),
            
            AppError::Business { code, message } => ApiError::new(
                *code,
                message
            ).with_request_id(request_id.unwrap_or_default()),
        }
    }
    
    /// Get the error code for this error
    pub fn error_code(&self) -> ErrorCode {
        match self {
            AppError::Internal(_) => ErrorCode::InternalError,
            AppError::Validation(_) => ErrorCode::ValidationError,
            AppError::ValidationErrors(_) => ErrorCode::ValidationError,
            AppError::Unauthorized(_) => ErrorCode::Unauthorized,
            AppError::Forbidden(_) => ErrorCode::Forbidden,
            AppError::NotFound(_) => ErrorCode::NotFound,
            AppError::Conflict(_) => ErrorCode::Conflict,
            AppError::RateLimited(_) => ErrorCode::RateLimited,
            AppError::ServiceUnavailable(_) => ErrorCode::ServiceUnavailable,
            AppError::Timeout(_) => ErrorCode::Timeout,
            AppError::Blockchain(e) => match e {
                BlockchainError::TransactionFailed(_) => ErrorCode::TransactionFailed,
                BlockchainError::ContractError(_) => ErrorCode::ContractError,
                BlockchainError::InsufficientGas(_) => ErrorCode::InsufficientGas,
                BlockchainError::NonceError(_) => ErrorCode::NonceError,
                BlockchainError::Revert(_) => ErrorCode::RevertError,
                BlockchainError::ProviderError(_) => ErrorCode::UpstreamError,
            },
            AppError::Database(_) => ErrorCode::InternalError,
            AppError::Redis(_) => ErrorCode::InternalError,
            AppError::Upstream { .. } => ErrorCode::UpstreamError,
            AppError::CircuitOpen { .. } => ErrorCode::CircuitOpen,
            AppError::IdempotencyConflict { .. } => ErrorCode::IdempotencyConflict,
            AppError::IdempotencyKeyExpired { .. } => ErrorCode::IdempotencyKeyExpired,
            AppError::Business { code, .. } => *code,
        }
    }
    
    /// Get HTTP status code
    pub fn status_code(&self) -> u16 {
        self.error_code().status_code()
    }
}

/// Result type alias
pub type AppResult<T> = Result<T, AppError>;

/// Extension trait for converting common errors
pub trait IntoAppError<T> {
    fn into_app_error(self, context: &str) -> AppResult<T>;
}

impl<T, E> IntoAppError<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn into_app_error(self, context: &str) -> AppResult<T> {
        self.map_err(|e| AppError::Internal(anyhow::Error::new(e).context(context.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_code_status() {
        assert_eq!(ErrorCode::NotFound.status_code(), 404);
        assert_eq!(ErrorCode::Unauthorized.status_code(), 401);
        assert_eq!(ErrorCode::InternalError.status_code(), 503);
        assert_eq!(ErrorCode::InsufficientFunds.status_code(), 422);
    }
    
    #[test]
    fn test_app_error_conversion() {
        let err = AppError::NotFound("user not found".to_string());
        let api_err = err.to_api_error(Some("req-123".into()));
        assert_eq!(api_err.status_code(), 404);
        assert_eq!(api_err.request_id, Some("req-123".into()));
    }
    
    #[test]
    fn test_business_error() {
        let err = AppError::Business {
            code: ErrorCode::InsufficientStake,
            message: "Need at least 100 tokens".to_string(),
        };
        assert_eq!(err.status_code(), 422);
        let api_err = err.to_api_error(None);
        assert_eq!(api_err.code, ErrorCode::InsufficientStake);
    }
}