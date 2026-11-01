pub mod connection_pool;
pub mod migrations;
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;

pub use connection_pool::{
    close_connections, create_connection_pool, get_connection, health_check, migrate_database,
    test_connection, with_transaction, DatabaseManager, DatabaseStats, DbConnection, DbPool,
};

// Re-export common database types for convenience
pub use chrono::{DateTime, Utc};
pub use rust_decimal::Decimal;
pub use sqlx::{
    postgres::{PgConnection, PgPool, PgRow},
    types::Uuid,
    Error as SqlxError, Row,
};

// Database configuration structure
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database_name: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,
    pub idle_timeout: u64,
    pub ssl_mode: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            username: "verdyx_user".to_string(),
            password: "verdyx_password".to_string(),
            database_name: "verdyx".to_string(),
            max_connections: 20,
            min_connections: 1,
            connection_timeout: 30,
            idle_timeout: 600,
            ssl_mode: "prefer".to_string(),
        }
    }
}

impl DatabaseConfig {
    /// Create a new database configuration from environment variables
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            host: std::env::var("DATABASE_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port: std::env::var("DATABASE_PORT")
                .unwrap_or_else(|_| "5432".to_string())
                .parse()
                .unwrap_or(5432),
            username: std::env::var("DATABASE_USER")?,
            password: std::env::var("DATABASE_PASSWORD")?,
            database_name: std::env::var("DATABASE_NAME")?,
            max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "20".to_string())
                .parse()
                .unwrap_or(20),
            min_connections: std::env::var("DATABASE_MIN_CONNECTIONS")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .unwrap_or(1),
            connection_timeout: std::env::var("DATABASE_CONNECTION_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            idle_timeout: std::env::var("DATABASE_IDLE_TIMEOUT")
                .unwrap_or_else(|_| "600".to_string())
                .parse()
                .unwrap_or(600),
            ssl_mode: std::env::var("DATABASE_SSL_MODE").unwrap_or_else(|_| "prefer".to_string()),
        })
    }

    /// Build the database URL from configuration
    pub fn database_url(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}?sslmode={}",
            self.username, self.password, self.host, self.port, self.database_name, self.ssl_mode
        )
    }
}

// Error types for database operations
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    Connection(#[from] sqlx::Error),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Transaction error: {0}")]
    Transaction(String),
}

pub type DatabaseResult<T> = Result<T, DatabaseError>;
