use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub email: EmailConfig,
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
    pub session_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry_hours: u64,
    pub refresh_token_expiry_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_address: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let jwt_secret = std::env::var("JWT_SECRET")?;
        let is_production = std::env::var("ENVIRONMENT")
            .map(|e| e.eq_ignore_ascii_case("production"))
            .unwrap_or(false);
        if is_production {
            if jwt_secret == "change-me-in-production" {
                anyhow::bail!("JWT_SECRET must be changed in production");
            }
            if jwt_secret.len() < 32 {
                anyhow::bail!(
                    "JWT_SECRET must be at least 32 characters in production (got {})",
                    jwt_secret.len()
                );
            }
        }

        Ok(Self {
            server: ServerConfig {
                host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: std::env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
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
                session_ttl_seconds: std::env::var("SESSION_TTL_SECONDS")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()?,
            },
            jwt: JwtConfig {
                secret: jwt_secret,
                access_token_expiry_hours: std::env::var("ACCESS_TOKEN_EXPIRY_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse()?,
                refresh_token_expiry_days: std::env::var("REFRESH_TOKEN_EXPIRY_DAYS")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()?,
            },
            email: EmailConfig {
                smtp_host: std::env::var("SMTP_HOST")
                    .unwrap_or_else(|_| "smtp.gmail.com".to_string()),
                smtp_port: std::env::var("SMTP_PORT")
                    .unwrap_or_else(|_| "587".to_string())
                    .parse()?,
                // SMTP_USER is accepted too: the env template lists both, and
                // notification-service already reads either one.
                smtp_username: std::env::var("SMTP_USERNAME")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| std::env::var("SMTP_USER").ok())
                    .unwrap_or_default(),
                smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
                from_address: std::env::var("EMAIL_FROM")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| "noreply@verdyx.dev".to_string()),
            },
        })
    }
}
