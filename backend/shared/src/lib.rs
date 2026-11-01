// Pre-production scaffolding: some items are intentionally unused while
// features are wired up. This crate-level allow keeps `clippy -D warnings`
// green without deleting code we are about to use. Remove before GA.
#![allow(dead_code)]
// The legacy `VerdyxError`/`Result` stay available for callers while they migrate.
#![allow(deprecated)]

//! Shared utilities and types for Verdyx backend services

// Re-export common dependencies
pub use anyhow;
pub use chrono;
pub use serde;
pub use serde_json;
pub use thiserror;
pub use tracing;
pub use uuid;

// Export modules
#[cfg(feature = "crypto")]
pub mod crypto;
pub mod database;
pub mod env;
pub mod error;
#[cfg(feature = "evm")]
pub mod evm;
#[cfg(feature = "evm-testing")]
pub mod evm_testing;
pub mod messaging;
pub mod observability;
pub mod password_policy;
pub mod service_metrics;
pub mod types;

#[cfg(feature = "circuit-breaker")]
pub mod circuit_breaker;
#[cfg(feature = "idempotency")]
pub mod idempotency;
#[cfg(feature = "axum-mw")]
pub mod metrics_mw;
#[cfg(feature = "validation")]
pub mod validation;

pub use service_metrics::MetricsRegistry;

// Re-export key error types
pub use error::{
    ApiError, AppError, AppResult, BlockchainError, ErrorCode, IntoAppError, ValidationError,
};

// Legacy error type (deprecated - use AppError instead)
#[deprecated(since = "0.2.0", note = "Use AppError instead")]
#[allow(deprecated)]
#[derive(Debug, thiserror::Error)]
pub enum VerdyxError {
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("External service error: {0}")]
    ExternalService(String),
}

#[deprecated(since = "0.2.0", note = "Use AppResult instead")]
#[allow(deprecated)]
pub type Result<T> = std::result::Result<T, VerdyxError>;
