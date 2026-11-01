use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::channels::{ApnsConfig, EmailConfig, FcmConfig, WebhookConfig};

fn env_non_empty(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub email: EmailConfig,
    pub push: PushConfig,
    pub webhook: WebhookConfig,
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
pub struct PushConfig {
    pub fcm: Option<FcmConfig>,
    pub apns: Option<ApnsConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            server: ServerConfig {
                host: env_non_empty("SERVER_HOST", "0.0.0.0"),
                port: env_non_empty("SERVER_PORT", "8080").parse().unwrap_or(8080),
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL")?,
                max_connections: env_non_empty("DATABASE_MAX_CONNECTIONS", "10")
                    .parse()
                    .unwrap_or(10),
            },
            redis: RedisConfig {
                url: env_non_empty("REDIS_URL", "redis://localhost:6379"),
            },
            email: EmailConfig {
                smtp_host: env_non_empty("SMTP_HOST", "smtp.gmail.com"),
                smtp_port: env_non_empty("SMTP_PORT", "587").parse().unwrap_or(587),
                smtp_username: std::env::var("SMTP_USERNAME")
                    .or_else(|_| std::env::var("SMTP_USER"))
                    .unwrap_or_default(),
                smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
                from_address: std::env::var("EMAIL_FROM_ADDRESS")
                    .or_else(|_| std::env::var("EMAIL_FROM"))
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "noreply@verdyx.io".to_string()),
                from_name: env_non_empty("EMAIL_FROM_NAME", "Verdyx"),
            },
            push: PushConfig {
                fcm: std::env::var("FCM_SERVER_KEY")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .map(|server_key| FcmConfig {
                        endpoint: env_non_empty(
                            "FCM_ENDPOINT",
                            "https://fcm.googleapis.com/fcm/send",
                        ),
                        server_key,
                    }),
                apns: std::env::var("APNS_AUTH_TOKEN")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .map(|auth_token| ApnsConfig {
                        endpoint: env_non_empty("APNS_ENDPOINT", "https://api.push.apple.com"),
                        auth_token,
                        bundle_id: env_non_empty("APNS_BUNDLE_ID", "io.verdyx.app"),
                    }),
            },
            webhook: WebhookConfig {
                signing_secret: std::env::var("WEBHOOK_SIGNING_SECRET")
                    .ok()
                    .filter(|s| !s.trim().is_empty()),
                max_retries: std::env::var("WEBHOOK_MAX_RETRIES")
                    .or_else(|_| std::env::var("MAX_RETRY_ATTEMPTS"))
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3),
                timeout_seconds: env_non_empty("WEBHOOK_TIMEOUT", "30").parse().unwrap_or(30),
            },
        })
    }
}
