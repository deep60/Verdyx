//! Observability utilities for logging, tracing, and metrics
//!
//! Provides centralized observability setup for all services

pub mod logging;
pub mod metrics;
pub mod otel;
pub mod tracing;

pub use logging::*;
pub use metrics::*;
pub use otel::*;
pub use tracing::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObservabilityError {
    #[error("Logging setup error: {0}")]
    Logging(String),
    
    #[error("Tracing setup error: {0}")]
    Tracing(String),
    
    #[error("Metrics error: {0}")]
    Metrics(String),
    
    #[error("OpenTelemetry error: {0}")]
    Otel(String),
}

pub type ObservabilityResult<T> = Result<T, ObservabilityError>;
