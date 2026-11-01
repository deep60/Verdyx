//! Structured logging setup for all services

use super::{ObservabilityError, ObservabilityResult};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Log level configuration
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// Log format configuration
#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    /// Human-readable format
    Pretty,
    /// JSON format for log aggregation
    Json,
    /// Compact format
    Compact,
}

/// Logging configuration
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub service_name: String,
    pub include_line_numbers: bool,
    pub include_thread_ids: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            service_name: "verdyx-service".to_string(),
            include_line_numbers: true,
            include_thread_ids: false,
        }
    }
}

/// Initialize logging for the service
pub fn init_logging(config: LogConfig) -> ObservabilityResult<()> {
    // Create filter from environment or config
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(config.level.as_str()));

    match config.format {
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(config.include_thread_ids)
                        .with_line_number(config.include_line_numbers)
                        .pretty(),
                )
                .try_init()
                .map_err(|e| ObservabilityError::Logging(e.to_string()))?;
        }
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_current_span(true)
                        .with_thread_ids(config.include_thread_ids)
                        .with_line_number(config.include_line_numbers),
                )
                .try_init()
                .map_err(|e| ObservabilityError::Logging(e.to_string()))?;
        }
        LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .compact()
                        .with_target(true)
                        .with_thread_ids(config.include_thread_ids),
                )
                .try_init()
                .map_err(|e| ObservabilityError::Logging(e.to_string()))?;
        }
    }

    tracing::info!(
        service = %config.service_name,
        level = %config.level.as_str(),
        "Logging initialized"
    );

    Ok(())
}

/// Quick setup with sensible defaults
pub fn init_default_logging(service_name: &str) -> ObservabilityResult<()> {
    init_logging(LogConfig {
        service_name: service_name.to_string(),
        ..Default::default()
    })
}

/// Initialize JSON logging for production
pub fn init_production_logging(service_name: &str) -> ObservabilityResult<()> {
    init_logging(LogConfig {
        service_name: service_name.to_string(),
        format: LogFormat::Json,
        level: LogLevel::Info,
        include_line_numbers: false,
        include_thread_ids: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_conversion() {
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Error.as_str(), "error");
    }
}
