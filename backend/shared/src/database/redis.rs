/// Redis utilities and helpers for caching and session management
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use serde::{Deserialize, Serialize};

/// Redis connection wrapper with common operations
pub struct RedisClient {
    connection: ConnectionManager,
}

impl RedisClient {
    /// Create a new Redis client
    pub fn new(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    /// Set a value with expiration
    pub async fn set_with_expiry<T: Serialize>(
        &mut self,
        key: &str,
        value: &T,
        expiry_seconds: u64,
    ) -> Result<(), RedisError> {
        let serialized = serde_json::to_string(value).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Serialization failed",
                e.to_string(),
            ))
        })?;

        self.connection
            .set_ex(key, serialized, expiry_seconds)
            .await
    }

    /// Get and deserialize a value
    pub async fn get<T: for<'de> Deserialize<'de>>(
        &mut self,
        key: &str,
    ) -> Result<Option<T>, RedisError> {
        let value: Option<String> = self.connection.get(key).await?;

        match value {
            Some(v) => {
                let deserialized = serde_json::from_str(&v).map_err(|e| {
                    RedisError::from((
                        redis::ErrorKind::TypeError,
                        "Deserialization failed",
                        e.to_string(),
                    ))
                })?;
                Ok(Some(deserialized))
            }
            None => Ok(None),
        }
    }

    /// Delete a key
    pub async fn delete(&mut self, key: &str) -> Result<bool, RedisError> {
        let result: i32 = self.connection.del(key).await?;
        Ok(result > 0)
    }

    /// Check if a key exists
    pub async fn exists(&mut self, key: &str) -> Result<bool, RedisError> {
        let result: bool = self.connection.exists(key).await?;
        Ok(result)
    }

    /// Set expiration on a key
    pub async fn expire(&mut self, key: &str, seconds: u64) -> Result<bool, RedisError> {
        let result: bool = self.connection.expire(key, seconds as i64).await?;
        Ok(result)
    }

    /// Increment a counter
    pub async fn increment(&mut self, key: &str) -> Result<i64, RedisError> {
        self.connection.incr(key, 1).await
    }

    /// Decrement a counter
    pub async fn decrement(&mut self, key: &str) -> Result<i64, RedisError> {
        self.connection.decr(key, 1).await
    }

    /// Add item to a set
    pub async fn sadd(&mut self, key: &str, member: &str) -> Result<i64, RedisError> {
        self.connection.sadd(key, member).await
    }

    /// Remove item from a set
    pub async fn srem(&mut self, key: &str, member: &str) -> Result<i64, RedisError> {
        self.connection.srem(key, member).await
    }

    /// Check if item is in a set
    pub async fn sismember(&mut self, key: &str, member: &str) -> Result<bool, RedisError> {
        self.connection.sismember(key, member).await
    }

    /// Get all members of a set
    pub async fn smembers(&mut self, key: &str) -> Result<Vec<String>, RedisError> {
        self.connection.smembers(key).await
    }
}

/// Cache key builder for consistent key naming
pub struct CacheKeyBuilder;

impl CacheKeyBuilder {
    pub fn user_session(user_id: &str) -> String {
        format!("session:{}", user_id)
    }

    pub fn user_profile(user_id: &str) -> String {
        format!("profile:{}", user_id)
    }

    pub fn bounty(bounty_id: &str) -> String {
        format!("bounty:{}", bounty_id)
    }

    pub fn analysis_result(artifact_hash: &str) -> String {
        format!("analysis:{}", artifact_hash)
    }

    pub fn rate_limit(user_id: &str, endpoint: &str) -> String {
        format!("ratelimit:{}:{}", user_id, endpoint)
    }

    pub fn verification_token(user_id: &str) -> String {
        format!("verify:{}", user_id)
    }

    pub fn password_reset_token(user_id: &str) -> String {
        format!("reset:{}", user_id)
    }
}

/// Common TTL values in seconds
pub mod ttl {
    pub const MINUTE: u64 = 60;
    pub const HOUR: u64 = 3600;
    pub const DAY: u64 = 86400;
    pub const WEEK: u64 = 604800;

    pub const SESSION: u64 = HOUR; // 1 hour
    pub const VERIFICATION: u64 = DAY; // 24 hours
    pub const RATE_LIMIT: u64 = MINUTE; // 1 minute
    pub const CACHE_SHORT: u64 = 5 * MINUTE; // 5 minutes
    pub const CACHE_MEDIUM: u64 = HOUR; // 1 hour
    pub const CACHE_LONG: u64 = DAY; // 1 day
}
