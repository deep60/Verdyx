use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to load configuration file: {0}")]
    FileError(#[from] std::io::Error),
    #[error("Failed to parse configuration: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

pub type ConfigResult<T> = Result<T, ConfigError>;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub blockchain: BlockchainConfig,
    pub security: SecurityConfig,
    pub services: ServicesConfig,
    pub features: FeaturesConfig,
    pub monitoring: MonitoringConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
    pub max_connections: usize,
    pub keep_alive: u64,
    pub request_timeout_seconds: u64,
    pub graceful_shutdown_timeout_seconds: u64,
    pub environment: Environment,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
    pub enable_logging: bool,
    pub run_migrations: bool,
}

/// Redis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout_seconds: u64,
    pub pool_timeout_seconds: u64,
    pub enable_cluster: bool,
    pub key_prefix: String,
    pub default_ttl_seconds: u64,
}

/// Blockchain configuration. Read-only: the gateway holds no signing key, and
/// every marketplace transaction is signed in the person's own wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub contracts: ContractsConfig,
}

/// Smart contract addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractsConfig {
    pub bounty_manager: String,
    pub threat_token: String,
    pub reputation_system: String,
    pub governance: Option<String>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub jwt_expiry_hours: i64,
    pub refresh_token_expiry_days: i64,
    pub api_key_length: usize,
    pub password_min_length: usize,
    pub password_require_special_char: bool,
    pub password_require_number: bool,
    pub password_require_uppercase: bool,
    pub max_login_attempts: u32,
    pub lockout_duration_minutes: u64,
    pub session_timeout_minutes: u64,
    pub cors: CorsConfig,
    pub rate_limiting: RateLimitingConfig,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_seconds: u64,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub auth_requests_per_15min: u32,
    pub api_requests_per_hour: u32,
    pub whitelist_ips: Vec<String>,
}

/// External services configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesConfig {
    pub analysis_engine_url: String,
    pub bounty_manager_url: String,
    pub notification_service_url: String,
    pub storage_service_url: String,
    pub ml_service_url: Option<String>,
    pub max_file_size_mb: usize,
    pub supported_file_types: Vec<String>,
    pub analysis_timeout_seconds: u64,
    pub upload_path: String,
}

/// Feature flags configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesConfig {
    pub enable_file_uploads: bool,
    pub enable_url_analysis: bool,
    pub enable_blockchain_integration: bool,
    pub enable_webhooks: bool,
    pub enable_api_keys: bool,
    pub enable_mfa: bool,
    pub enable_oauth2: bool,
    pub enable_analytics: bool,
    pub enable_ml_insights: bool,
    pub enable_reputation_system: bool,
    pub enable_gamification: bool,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_metrics: bool,
    pub enable_tracing: bool,
    pub metrics_port: u16,
    pub log_level: String,
    pub log_format: LogFormat,
    pub sentry_dsn: Option<String>,
    pub prometheus_enabled: bool,
    pub jaeger_endpoint: Option<String>,
}

/// Environment type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Staging,
    Production,
    Testing,
}

impl Environment {
    pub fn is_production(&self) -> bool {
        matches!(self, Environment::Production)
    }

    pub fn is_development(&self) -> bool {
        matches!(self, Environment::Development)
    }

    pub fn is_testing(&self) -> bool {
        matches!(self, Environment::Testing)
    }
}

/// Log format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            workers: None,
            max_connections: 1000,
            keep_alive: 75,
            request_timeout_seconds: 30,
            graceful_shutdown_timeout_seconds: 30,
            environment: Environment::Development,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://postgres:postgres@localhost:5432/verdyx".to_string(),
            max_connections: 100,
            min_connections: 10,
            connection_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 1800,
            enable_logging: false,
            run_migrations: true,
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            max_connections: 50,
            connection_timeout_seconds: 5,
            pool_timeout_seconds: 10,
            enable_cluster: false,
            key_prefix: "verdyx:".to_string(),
            default_ttl_seconds: 3600,
        }
    }
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 1337, // Local development chain
            contracts: ContractsConfig::default(),
        }
    }
}

impl Default for ContractsConfig {
    fn default() -> Self {
        Self {
            bounty_manager: "0x0000000000000000000000000000000000000000".to_string(),
            threat_token: "0x0000000000000000000000000000000000000000".to_string(),
            reputation_system: "0x0000000000000000000000000000000000000000".to_string(),
            governance: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change-me-in-production".to_string(),
            jwt_expiry_hours: 24,
            refresh_token_expiry_days: 30,
            api_key_length: 32,
            password_min_length: 8,
            password_require_special_char: true,
            password_require_number: true,
            password_require_uppercase: true,
            max_login_attempts: 5,
            lockout_duration_minutes: 15,
            session_timeout_minutes: 60,
            cors: CorsConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["http://localhost:3000".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec!["*".to_string()],
            expose_headers: vec![],
            allow_credentials: true,
            max_age_seconds: 3600,
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 60,
            burst_size: 100,
            auth_requests_per_15min: 5,
            api_requests_per_hour: 1000,
            whitelist_ips: vec![],
        }
    }
}

impl Default for ServicesConfig {
    fn default() -> Self {
        Self {
            analysis_engine_url: "http://localhost:8082".to_string(),
            bounty_manager_url: "http://localhost:8083".to_string(),
            notification_service_url: "http://localhost:8088".to_string(),
            storage_service_url: "http://localhost:8084".to_string(),
            ml_service_url: None,
            max_file_size_mb: 100,
            supported_file_types: vec![
                "exe".to_string(),
                "dll".to_string(),
                "pdf".to_string(),
                "apk".to_string(),
                "zip".to_string(),
            ],
            analysis_timeout_seconds: 300,
            upload_path: "./uploads".to_string(),
        }
    }
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            enable_file_uploads: true,
            enable_url_analysis: true,
            enable_blockchain_integration: true,
            enable_webhooks: true,
            enable_api_keys: true,
            enable_mfa: false,
            enable_oauth2: false,
            enable_analytics: true,
            enable_ml_insights: false,
            enable_reputation_system: true,
            enable_gamification: true,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            enable_tracing: true,
            metrics_port: 9090,
            log_level: "info".to_string(),
            log_format: LogFormat::Pretty,
            sentry_dsn: None,
            prometheus_enabled: true,
            jaeger_endpoint: None,
        }
    }
}

impl AppConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> ConfigResult<Self> {
        let content = fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables
    pub fn from_env() -> ConfigResult<Self> {
        let mut config = AppConfig::default();

        // Server configuration
        if let Ok(host) = std::env::var("SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|_| ConfigError::InvalidValue("Invalid SERVER_PORT".to_string()))?;
        }
        if let Ok(env) = std::env::var("ENVIRONMENT") {
            config.server.environment = match env.to_lowercase().as_str() {
                "development" | "dev" => Environment::Development,
                "staging" => Environment::Staging,
                "production" | "prod" => Environment::Production,
                "testing" | "test" => Environment::Testing,
                _ => {
                    return Err(ConfigError::InvalidValue(format!(
                        "Invalid ENVIRONMENT: {env}"
                    )))
                }
            };
        }

        // Database configuration
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            config.database.url = db_url;
        }
        if let Ok(max_conn) = std::env::var("DATABASE_MAX_CONNECTIONS") {
            config.database.max_connections = max_conn.parse().map_err(|_| {
                ConfigError::InvalidValue("Invalid DATABASE_MAX_CONNECTIONS".to_string())
            })?;
        }

        // Redis configuration
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            config.redis.url = redis_url;
        }

        // Blockchain configuration
        if let Ok(rpc_url) =
            std::env::var("BLOCKCHAIN_RPC_URL").or_else(|_| std::env::var("ETHEREUM_RPC_URL"))
        {
            config.blockchain.rpc_url = rpc_url;
        }
        if let Ok(chain_id) = std::env::var("CHAIN_ID") {
            config.blockchain.chain_id = chain_id
                .parse()
                .map_err(|_| ConfigError::InvalidValue("Invalid CHAIN_ID".to_string()))?;
        }

        // Contract addresses (accept both naming conventions for compatibility)
        if let Ok(addr) = std::env::var("BOUNTY_MANAGER_ADDRESS")
            .or_else(|_| std::env::var("CONTRACT_BOUNTY_MANAGER"))
            .or_else(|_| std::env::var("CONTRACT_ADDRESS_BOUNTY"))
        {
            config.blockchain.contracts.bounty_manager = addr;
        }
        if let Ok(addr) = std::env::var("THREAT_TOKEN_ADDRESS")
            .or_else(|_| std::env::var("CONTRACT_THREAT_TOKEN"))
            .or_else(|_| std::env::var("CONTRACT_ADDRESS_TOKEN"))
        {
            config.blockchain.contracts.threat_token = addr;
        }
        if let Ok(addr) = std::env::var("REPUTATION_SYSTEM_ADDRESS")
            .or_else(|_| std::env::var("CONTRACT_REPUTATION_SYSTEM"))
        {
            config.blockchain.contracts.reputation_system = addr;
        }

        // Security configuration
        if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            config.security.jwt_secret = jwt_secret;
        } else if config.server.environment.is_production() {
            return Err(ConfigError::MissingField(
                "JWT_SECRET is required in production".to_string(),
            ));
        }

        // CORS origins
        if let Ok(origins) = std::env::var("CORS_ALLOWED_ORIGINS") {
            config.security.cors.allowed_origins =
                origins.split(',').map(|s| s.trim().to_string()).collect();
        }

        // Services configuration
        if let Ok(url) = std::env::var("ANALYSIS_ENGINE_URL") {
            config.services.analysis_engine_url = url;
        }
        if let Ok(url) = std::env::var("BOUNTY_MANAGER_URL") {
            config.services.bounty_manager_url = url;
        }
        if let Ok(path) = std::env::var("UPLOAD_PATH").or_else(|_| std::env::var("UPLOAD_DIR")) {
            config.services.upload_path = path;
        }

        // Feature flags
        if let Ok(val) = std::env::var("ENABLE_MFA") {
            config.features.enable_mfa = val.parse().unwrap_or(false);
        }
        if let Ok(val) = std::env::var("ENABLE_OAUTH2") {
            config.features.enable_oauth2 = val.parse().unwrap_or(false);
        }

        // Monitoring
        if let Ok(level) = std::env::var("LOG_LEVEL") {
            config.monitoring.log_level = level;
        }
        if let Ok(dsn) = std::env::var("SENTRY_DSN") {
            config.monitoring.sentry_dsn = Some(dsn);
        }

        config.validate()?;
        Ok(config)
    }

    /// Load configuration with priority: file -> env -> defaults
    pub fn load() -> ConfigResult<Self> {
        // Try to load from explicit config file
        if let Ok(config_path) = std::env::var("CONFIG_FILE") {
            if Path::new(&config_path).exists() {
                let mut config = Self::from_file(&config_path)?;
                config.apply_env_overrides();
                return Ok(config);
            }
        }

        // Try CONFIG_PATH as a directory containing .toml files
        if let Ok(config_dir) = std::env::var("CONFIG_PATH") {
            let dir = Path::new(&config_dir);
            if dir.is_dir() {
                // Look for app.toml or config.toml in the directory
                for name in &["app.toml", "config.toml"] {
                    let candidate = dir.join(name);
                    if candidate.exists() {
                        match Self::from_file(&candidate) {
                            Ok(mut config) => {
                                config.apply_env_overrides();
                                return Ok(config);
                            }
                            Err(e) => {
                                eprintln!(
                                    "Warning: Failed to load config from {}: {}",
                                    candidate.display(),
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }

        // Check default locations
        for path in &[
            "config.toml",
            "config/production.toml",
            "config/development.toml",
        ] {
            if Path::new(path).exists() {
                match Self::from_file(path) {
                    Ok(mut config) => {
                        // Override with environment variables
                        config.apply_env_overrides();
                        return Ok(config);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load config from {path}: {e}");
                    }
                }
            }
        }

        // Fall back to environment variables
        Self::from_env()
    }

    /// Apply environment variable overrides to existing config
    fn apply_env_overrides(&mut self) {
        if let Ok(host) = std::env::var("SERVER_HOST") {
            self.server.host = host;
        }
        if let Ok(port) = std::env::var("SERVER_PORT") {
            if let Ok(port_num) = port.parse() {
                self.server.port = port_num;
            }
        }
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            self.database.url = db_url;
        }
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            self.redis.url = redis_url;
        }
        if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            self.security.jwt_secret = jwt_secret;
        }
        if let Ok(origins) = std::env::var("CORS_ALLOWED_ORIGINS") {
            self.security.cors.allowed_origins =
                origins.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(path) = std::env::var("UPLOAD_PATH").or_else(|_| std::env::var("UPLOAD_DIR")) {
            self.services.upload_path = path;
        }
        if let Ok(url) = std::env::var("ANALYSIS_ENGINE_URL") {
            self.services.analysis_engine_url = url;
        }
        if let Ok(url) = std::env::var("BOUNTY_MANAGER_URL") {
            self.services.bounty_manager_url = url;
        }
        if let Ok(rpc_url) =
            std::env::var("BLOCKCHAIN_RPC_URL").or_else(|_| std::env::var("ETHEREUM_RPC_URL"))
        {
            self.blockchain.rpc_url = rpc_url;
        }
        if let Ok(env) = std::env::var("ENVIRONMENT") {
            self.server.environment = match env.to_lowercase().as_str() {
                "production" | "prod" => Environment::Production,
                "staging" => Environment::Staging,
                "development" | "dev" => Environment::Development,
                "testing" | "test" => Environment::Testing,
                _ => self.server.environment,
            };
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err(ConfigError::InvalidValue(
                "Server port cannot be 0".to_string(),
            ));
        }

        // Validate database URL
        if self.database.url.is_empty() {
            return Err(ConfigError::MissingField("database.url".to_string()));
        }

        // Validate Redis URL
        if self.redis.url.is_empty() {
            return Err(ConfigError::MissingField("redis.url".to_string()));
        }

        // Validate JWT secret in production
        if self.server.environment.is_production() {
            if self.security.jwt_secret == "change-me-in-production" {
                return Err(ConfigError::InvalidValue(
                    "JWT_SECRET must be changed in production".to_string(),
                ));
            }
            if self.security.jwt_secret.len() < 32 {
                return Err(ConfigError::InvalidValue(
                    "JWT_SECRET must be at least 32 characters in production".to_string(),
                ));
            }
        }

        // Validate blockchain configuration
        if self.features.enable_blockchain_integration && self.blockchain.rpc_url.is_empty() {
            return Err(ConfigError::MissingField("blockchain.rpc_url".to_string()));
        }

        // Validate rate limiting
        if self.security.rate_limiting.enabled
            && self.security.rate_limiting.requests_per_minute == 0
        {
            return Err(ConfigError::InvalidValue(
                "Rate limit requests_per_minute cannot be 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the server address as a string
    pub fn server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    /// Get max file size in bytes
    pub fn max_file_size_bytes(&self) -> usize {
        self.services.max_file_size_mb * 1024 * 1024
    }

    /// Check if a feature is enabled
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        match feature {
            "file_uploads" => self.features.enable_file_uploads,
            "url_analysis" => self.features.enable_url_analysis,
            "blockchain" => self.features.enable_blockchain_integration,
            "webhooks" => self.features.enable_webhooks,
            "api_keys" => self.features.enable_api_keys,
            "mfa" => self.features.enable_mfa,
            "oauth2" => self.features.enable_oauth2,
            "analytics" => self.features.enable_analytics,
            "ml_insights" => self.features.enable_ml_insights,
            "reputation" => self.features.enable_reputation_system,
            "gamification" => self.features.enable_gamification,
            _ => false,
        }
    }

    /// Print configuration summary (without sensitive data)
    pub fn print_summary(&self) {
        println!("=== Verdyx API Gateway Configuration ===");
        println!("Environment: {:?}", self.server.environment);
        println!("Server: {}:{}", self.server.host, self.server.port);
        println!(
            "Database: {} (max_conn: {})",
            self.mask_credentials(&self.database.url),
            self.database.max_connections
        );
        println!("Redis: {}", self.mask_credentials(&self.redis.url));
        println!("Blockchain RPC: {}", self.blockchain.rpc_url);
        println!("Max file size: {} MB", self.services.max_file_size_mb);
        println!(
            "Rate limiting: {}",
            if self.security.rate_limiting.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!("Features enabled:");
        println!("  - File uploads: {}", self.features.enable_file_uploads);
        println!(
            "  - Blockchain: {}",
            self.features.enable_blockchain_integration
        );
        println!("  - Webhooks: {}", self.features.enable_webhooks);
        println!("  - MFA: {}", self.features.enable_mfa);
        println!("  - Analytics: {}", self.features.enable_analytics);
        println!("===============================================");
    }

    /// Mask credentials in URLs
    fn mask_credentials(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            if parsed.username() != "" || parsed.password().is_some() {
                let mut masked = parsed.clone();
                masked.set_username("***").ok();
                masked.set_password(Some("***")).ok();
                return masked.to_string();
            }
        }
        url.to_string()
    }

    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> ConfigResult<()> {
        let toml_string = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::InvalidValue(format!("Failed to serialize config: {e}")))?;
        fs::write(path, toml_string)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.environment, Environment::Development);
    }

    #[test]
    fn test_config_validation() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_port() {
        let mut config = AppConfig::default();
        config.server.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_production_jwt_validation() {
        let mut config = AppConfig::default();
        config.server.environment = Environment::Production;
        assert!(config.validate().is_err()); // Should fail with default JWT secret
    }

    #[test]
    fn test_feature_flags() {
        let config = AppConfig::default();
        assert!(config.is_feature_enabled("file_uploads"));
        assert!(config.is_feature_enabled("blockchain"));
        assert!(!config.is_feature_enabled("mfa"));
    }

    #[test]
    fn test_max_file_size_bytes() {
        let config = AppConfig::default();
        assert_eq!(config.max_file_size_bytes(), 100 * 1024 * 1024);
    }

    #[test]
    fn test_server_address() {
        let config = AppConfig::default();
        assert_eq!(config.server_address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_environment_types() {
        assert!(Environment::Production.is_production());
        assert!(!Environment::Production.is_development());
        assert!(Environment::Development.is_development());
        assert!(Environment::Testing.is_testing());
    }
}
