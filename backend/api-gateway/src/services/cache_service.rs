use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::redis::RedisService;

/// High-level cache service that provides application-level caching abstractions
/// Built on top of RedisService with additional features like cache warming,
/// invalidation strategies, and typed caching
#[derive(Clone)]
pub struct CacheService {
    redis: Arc<RwLock<RedisService>>,
    cache_stats: Arc<RwLock<CacheStats>>,
    config: CacheConfig,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub default_ttl_seconds: u64,
    pub max_cache_size_mb: usize,
    pub enable_compression: bool,
    pub enable_stats: bool,
    pub cache_warming_enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 3600, // 1 hour
            max_cache_size_mb: 512,
            enable_compression: true,
            enable_stats: true,
            cache_warming_enabled: false,
        }
    }
}

/// Cache statistics tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub sets: u64,
    pub deletes: u64,
    pub errors: u64,
    pub total_bytes_cached: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    pub fn miss_rate(&self) -> f64 {
        100.0 - self.hit_rate()
    }
}

/// Cache key prefixes for different data types
#[derive(Clone)]
pub enum CacheKeyPrefix {
    User,
    Analysis,
    Bounty,
    Engine,
    Reputation,
    Webhook,
    Session,
    ApiKey,
}

impl CacheKeyPrefix {
    fn as_str(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Analysis => "analysis",
            Self::Bounty => "bounty",
            Self::Engine => "engine",
            Self::Reputation => "reputation",
            Self::Webhook => "webhook",
            Self::Session => "session",
            Self::ApiKey => "api_key",
        }
    }

    pub fn key(&self, identifier: &str) -> String {
        format!("{}:{}", self.as_str(), identifier)
    }
}

/// Cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub data: T,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub version: u32,
}

impl<T> CacheEntry<T> {
    pub fn new(data: T, ttl_seconds: u64) -> Self {
        let now = chrono::Utc::now();
        Self {
            data,
            cached_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds as i64),
            version: 1,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    pub fn time_until_expiry(&self) -> Option<chrono::Duration> {
        let now = chrono::Utc::now();
        if now < self.expires_at {
            Some(self.expires_at - now)
        } else {
            None
        }
    }
}

impl CacheService {
    /// Create a new cache service
    pub async fn new(redis: RedisService, config: CacheConfig) -> Result<Self> {
        info!("Initializing cache service with config: {:?}", config);

        Ok(Self {
            redis: Arc::new(RwLock::new(redis)),
            cache_stats: Arc::new(RwLock::new(CacheStats::default())),
            config,
        })
    }

    /// Get a value from cache with automatic deserialization
    pub async fn get<T>(&self, prefix: CacheKeyPrefix, key: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let cache_key = prefix.key(key);
        debug!("Cache GET: {}", cache_key);

        let mut redis = self.redis.write().await;
        let cached: Option<String> = redis
            .connection_pool
            .get::<_, Option<String>>(&cache_key)
            .await
            .context("Failed to get value from cache")?;

        if let Some(data) = cached {
            // Update stats
            if self.config.enable_stats {
                let mut stats = self.cache_stats.write().await;
                stats.hits += 1;
            }

            let entry: CacheEntry<T> =
                serde_json::from_str(&data).context("Failed to deserialize cache entry")?;

            // Check if expired
            if entry.is_expired() {
                debug!("Cache entry expired: {}", cache_key);
                drop(redis); // Release lock before delete
                self.delete(prefix, key).await?;

                if self.config.enable_stats {
                    let mut stats = self.cache_stats.write().await;
                    stats.misses += 1;
                }

                return Ok(None);
            }

            debug!("Cache HIT: {}", cache_key);
            Ok(Some(entry.data))
        } else {
            debug!("Cache MISS: {}", cache_key);

            // Update stats
            if self.config.enable_stats {
                let mut stats = self.cache_stats.write().await;
                stats.misses += 1;
            }

            Ok(None)
        }
    }

    /// Set a value in cache with automatic serialization
    pub async fn set<T>(
        &self,
        prefix: CacheKeyPrefix,
        key: &str,
        value: T,
        ttl_seconds: Option<u64>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let cache_key = prefix.key(key);
        let ttl = ttl_seconds.unwrap_or(self.config.default_ttl_seconds);

        debug!("Cache SET: {} (TTL: {}s)", cache_key, ttl);

        let entry = CacheEntry::new(value, ttl);
        let serialized =
            serde_json::to_string(&entry).context("Failed to serialize cache entry")?;

        let mut redis = self.redis.write().await;
        let _: () = redis
            .connection_pool
            .set_ex(&cache_key, serialized.clone(), ttl)
            .await
            .context("Failed to set value in cache")?;

        // Update stats
        if self.config.enable_stats {
            let mut stats = self.cache_stats.write().await;
            stats.sets += 1;
            stats.total_bytes_cached += serialized.len() as u64;
        }

        info!("Cached {} ({}s TTL)", cache_key, ttl);
        Ok(())
    }

    /// Delete a value from cache
    pub async fn delete(&self, prefix: CacheKeyPrefix, key: &str) -> Result<()> {
        let cache_key = prefix.key(key);
        debug!("Cache DELETE: {}", cache_key);

        let mut redis = self.redis.write().await;
        let _: () = redis
            .connection_pool
            .del(&cache_key)
            .await
            .context("Failed to delete from cache")?;

        // Update stats
        if self.config.enable_stats {
            let mut stats = self.cache_stats.write().await;
            stats.deletes += 1;
        }

        info!("Deleted cache key: {}", cache_key);
        Ok(())
    }

    /// Delete all keys matching a pattern
    pub async fn delete_pattern(&self, pattern: &str) -> Result<u64> {
        debug!("Cache DELETE PATTERN: {}", pattern);

        let mut redis = self.redis.write().await;

        // Get all keys matching pattern
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut redis.connection_pool)
            .await
            .context("Failed to find keys matching pattern")?;

        if keys.is_empty() {
            return Ok(0);
        }

        let count = keys.len() as u64;

        // Delete all matching keys
        let _: () = redis
            .connection_pool
            .del(keys)
            .await
            .context("Failed to delete keys")?;

        // Update stats
        if self.config.enable_stats {
            let mut stats = self.cache_stats.write().await;
            stats.deletes += count;
        }

        info!("Deleted {} keys matching pattern: {}", count, pattern);
        Ok(count)
    }

    /// Get or set a value in cache (cache-aside pattern)
    pub async fn get_or_set<T, F, Fut>(
        &self,
        prefix: CacheKeyPrefix,
        key: &str,
        ttl_seconds: Option<u64>,
        fetch_fn: F,
    ) -> Result<T>
    where
        T: Serialize + for<'de> Deserialize<'de>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        // Try to get from cache first
        if let Some(cached) = self.get(prefix.clone(), key).await? {
            return Ok(cached);
        }

        // Cache miss - fetch data
        let data = fetch_fn().await?;

        // Store in cache
        self.set(prefix, key, &data, ttl_seconds).await?;

        Ok(data)
    }

    /// Invalidate multiple related cache entries
    pub async fn invalidate_group(
        &self,
        prefix: CacheKeyPrefix,
        identifiers: Vec<&str>,
    ) -> Result<()> {
        debug!(
            "Invalidating cache group: {:?} ({} entries)",
            prefix.as_str(),
            identifiers.len()
        );

        for identifier in &identifiers {
            self.delete(prefix.clone(), identifier).await?;
        }

        info!("Invalidated {} cache entries", identifiers.len());
        Ok(())
    }

    /// Warm up cache with frequently accessed data
    pub async fn warm_cache<T, F, Fut>(
        &self,
        prefix: CacheKeyPrefix,
        entries: Vec<(String, F)>,
        ttl_seconds: Option<u64>,
    ) -> Result<usize>
    where
        T: Serialize,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        if !self.config.cache_warming_enabled {
            warn!("Cache warming is disabled");
            return Ok(0);
        }

        let total_entries = entries.len();
        info!("Warming cache with {} entries", total_entries);
        let mut warmed = 0;

        for (key, fetch_fn) in entries {
            match fetch_fn().await {
                Ok(data) => {
                    self.set(prefix.clone(), &key, data, ttl_seconds).await?;
                    warmed += 1;
                }
                Err(e) => {
                    warn!("Failed to warm cache for key {}: {}", key, e);
                }
            }
        }

        info!(
            "Cache warming complete: {}/{} entries warmed",
            warmed, total_entries
        );
        Ok(warmed)
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        self.cache_stats.read().await.clone()
    }

    /// Reset cache statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.cache_stats.write().await;
        *stats = CacheStats::default();
        info!("Cache statistics reset");
    }

    /// Check if a key exists in cache
    pub async fn exists(&self, prefix: CacheKeyPrefix, key: &str) -> Result<bool> {
        let cache_key = prefix.key(key);
        let mut redis = self.redis.write().await;

        let exists: bool = redis
            .connection_pool
            .exists(&cache_key)
            .await
            .context("Failed to check key existence")?;

        Ok(exists)
    }

    /// Set expiration time for an existing cache entry
    pub async fn expire(&self, prefix: CacheKeyPrefix, key: &str, ttl_seconds: u64) -> Result<()> {
        let cache_key = prefix.key(key);
        let mut redis = self.redis.write().await;

        let _: () = redis
            .connection_pool
            .expire(&cache_key, ttl_seconds as i64)
            .await
            .context("Failed to set expiration")?;

        debug!("Set expiration for {}: {}s", cache_key, ttl_seconds);
        Ok(())
    }

    /// Get time-to-live for a cache entry
    pub async fn ttl(&self, prefix: CacheKeyPrefix, key: &str) -> Result<Option<i64>> {
        let cache_key = prefix.key(key);
        let mut redis = self.redis.write().await;

        let ttl: i64 = redis
            .connection_pool
            .ttl(&cache_key)
            .await
            .context("Failed to get TTL")?;

        if ttl < 0 {
            Ok(None)
        } else {
            Ok(Some(ttl))
        }
    }

    /// Flush all cache entries (use with caution)
    pub async fn flush_all(&self) -> Result<()> {
        warn!("Flushing entire cache - this will delete all data!");

        let mut redis = self.redis.write().await;
        let _: () = redis::cmd("FLUSHDB")
            .query_async(&mut redis.connection_pool)
            .await
            .context("Failed to flush cache")?;

        // Reset stats
        drop(redis);
        self.reset_stats().await;

        info!("Cache flushed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_prefix() {
        assert_eq!(CacheKeyPrefix::User.key("123"), "user:123");
        assert_eq!(CacheKeyPrefix::Analysis.key("abc"), "analysis:abc");
        assert_eq!(CacheKeyPrefix::Bounty.key("bounty-1"), "bounty:bounty-1");
    }

    #[test]
    fn test_cache_entry_expiry() {
        let entry = CacheEntry::new("test data", 3600);
        assert!(!entry.is_expired());
        assert!(entry.time_until_expiry().is_some());
    }

    #[test]
    fn test_cache_stats() {
        let stats = CacheStats {
            hits: 80,
            misses: 20,
            ..Default::default()
        };

        assert_eq!(stats.hit_rate(), 80.0);
        assert_eq!(stats.miss_rate(), 20.0);
    }

    #[test]
    fn test_cache_stats_no_requests() {
        let stats = CacheStats::default();
        assert_eq!(stats.hit_rate(), 0.0);
        assert_eq!(stats.miss_rate(), 100.0);
    }
}
