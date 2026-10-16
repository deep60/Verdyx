use anyhow::{Context, Result};
use redis::{AsyncCommands, Client, RedisResult};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct RedisService {
    client: Client,
    pub(crate) connection_pool: redis::aio::MultiplexedConnection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisCache {
    pub file_hash: String,
    pub analysis_result: String,
    pub confidence_score: f64,
    pub threat_level: String,
    pub engines_analyzed: Vec<String>,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BountyCache {
    pub bounty_id: Uuid,
    pub status: String,
    pub current_reward: String, // Store as string to avoid precision issues with crypto amounts
    pub submissions_count: u32,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: Uuid,
    pub wallet_address: String,
    pub reputation_score: i32,
    pub session_token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl RedisService {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = Client::open(redis_url).context("Failed to create Redis client")?;

        let connection_pool = client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to establish Redis connection pool")?;

        info!("Redis service initialized successfully");

        Ok(RedisService {
            client,
            connection_pool,
        })
    }

    // Analysis result caching
    pub async fn cache_analysis(
        &self,
        file_hash: &str,
        analysis: &AnalysisCache,
        ttl_seconds: u64,
    ) -> Result<()> {
        let key = format!("analysis:{file_hash}");
        let serialized =
            serde_json::to_string(analysis).context("Failed to serialize analysis cache")?;

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .set_ex(&key, serialized, ttl_seconds)
            .await
            .context("Failed to cache analysis result")?;

        info!("Cached analysis result for file hash: {}", file_hash);
        Ok(())
    }

    pub async fn get_cached_analysis(&self, file_hash: &str) -> Result<Option<AnalysisCache>> {
        let key = format!("analysis:{file_hash}");

        let mut conn = self.connection_pool.clone();
        let cached: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to retrieve cached analysis")?;

        match cached {
            Some(data) => {
                let analysis: AnalysisCache =
                    serde_json::from_str(&data).context("Failed to deserialize cached analysis")?;
                Ok(Some(analysis))
            }
            None => Ok(None),
        }
    }

    // Bounty caching
    pub async fn cache_bounty(&self, bounty: &BountyCache, ttl_seconds: u64) -> Result<()> {
        let key = format!("bounty:{}", bounty.bounty_id);
        let serialized =
            serde_json::to_string(bounty).context("Failed to serialize bounty cache")?;

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .set_ex(&key, serialized, ttl_seconds)
            .await
            .context("Failed to cache bounty")?;

        info!("Cached bounty: {}", bounty.bounty_id);
        Ok(())
    }

    pub async fn get_cached_bounty(&self, bounty_id: &Uuid) -> Result<Option<BountyCache>> {
        let key = format!("bounty:{bounty_id}");

        let mut conn = self.connection_pool.clone();
        let cached: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to retrieve cached bounty")?;

        match cached {
            Some(data) => {
                let bounty: BountyCache =
                    serde_json::from_str(&data).context("Failed to deserialize cached bounty")?;
                Ok(Some(bounty))
            }
            None => Ok(None),
        }
    }

    pub async fn invalidate_bounty_cache(&self, bounty_id: &Uuid) -> Result<()> {
        let key = format!("bounty:{bounty_id}");

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .del(&key)
            .await
            .context("Failed to invalidate bounty cache")?;

        info!("Invalidated cache for bounty: {}", bounty_id);
        Ok(())
    }

    // User session management
    pub async fn create_session(&self, session: &UserSession, ttl_seconds: u64) -> Result<()> {
        let key = format!("session:{}", session.session_token);
        let user_key = format!("user_session:{}", session.user_id);

        let serialized =
            serde_json::to_string(session).context("Failed to serialize user session")?;

        let mut conn = self.connection_pool.clone();
        // Store session data with expiration
        let _: () = conn
            .set_ex(&key, &serialized, ttl_seconds)
            .await
            .context("Failed to create session")?;

        // Store user -> session mapping
        let _: () = conn
            .set_ex(&user_key, &session.session_token, ttl_seconds)
            .await
            .context("Failed to create user session mapping")?;

        info!("Created session for user: {}", session.user_id);
        Ok(())
    }

    pub async fn get_session(&self, session_token: &str) -> Result<Option<UserSession>> {
        let key = format!("session:{session_token}");

        let mut conn = self.connection_pool.clone();
        let cached: Option<String> = conn.get(&key).await.context("Failed to retrieve session")?;

        match cached {
            Some(data) => {
                let session: UserSession =
                    serde_json::from_str(&data).context("Failed to deserialize session")?;

                // Check if session is expired
                if session.expires_at < chrono::Utc::now() {
                    // Delete expired session directly without recursion
                    let _: () = conn.del(&key).await.context("Failed to delete session")?;
                    let user_key = format!("user_session:{}", session.user_id);
                    let _: () = conn
                        .del(&user_key)
                        .await
                        .context("Failed to remove user session")?;
                    Ok(None)
                } else {
                    Ok(Some(session))
                }
            }
            None => Ok(None),
        }
    }

    pub async fn invalidate_session(&self, session_token: &str) -> Result<()> {
        // Get session data directly without calling get_session to avoid recursion
        let key = format!("session:{session_token}");
        let mut conn = self.connection_pool.clone();
        let cached: Option<String> = conn.get(&key).await.context("Failed to retrieve session")?;

        if let Some(data) = cached {
            if let Ok(session) = serde_json::from_str::<UserSession>(&data) {
                let user_key = format!("user_session:{}", session.user_id);
                let _: () = conn
                    .del(&user_key)
                    .await
                    .context("Failed to remove user session mapping")?;
            }
        }

        let key = format!("session:{session_token}");
        let _: () = conn
            .del(&key)
            .await
            .context("Failed to invalidate session")?;

        info!("Invalidated session: {}", session_token);
        Ok(())
    }

    // Rate limiting
    pub async fn check_rate_limit(
        &self,
        identifier: &str,
        max_requests: u32,
        window_seconds: u64,
    ) -> Result<bool> {
        let key = format!("rate_limit:{identifier}");

        let mut conn = self.connection_pool.clone();
        // Use Redis sliding window rate limiting
        let current_count: u32 = conn
            .incr(&key, 1)
            .await
            .context("Failed to increment rate limit counter")?;

        if current_count == 1 {
            // Set expiration for new key
            let _: () = conn
                .expire(&key, window_seconds as i64)
                .await
                .context("Failed to set rate limit expiration")?;
        }

        let allowed = current_count <= max_requests;

        if !allowed {
            warn!(
                "Rate limit exceeded for identifier: {} ({}/{})",
                identifier, current_count, max_requests
            );
        }

        Ok(allowed)
    }

    // Real-time notifications and pub/sub
    pub async fn publish_analysis_complete(
        &self,
        file_hash: &str,
        analysis_id: &Uuid,
    ) -> Result<()> {
        let channel = "analysis_complete";
        let message = serde_json::json!({
            "file_hash": file_hash,
            "analysis_id": analysis_id,
            "timestamp": chrono::Utc::now()
        });

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .publish(channel, message.to_string())
            .await
            .context("Failed to publish analysis complete notification")?;

        info!(
            "Published analysis complete notification for file: {}",
            file_hash
        );
        Ok(())
    }

    pub async fn publish_bounty_update(
        &self,
        bounty_id: &Uuid,
        update_type: &str,
        data: serde_json::Value,
    ) -> Result<()> {
        let channel = format!("bounty_updates:{bounty_id}");
        let message = serde_json::json!({
            "bounty_id": bounty_id,
            "update_type": update_type,
            "data": data,
            "timestamp": chrono::Utc::now()
        });

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .publish(&channel, message.to_string())
            .await
            .context("Failed to publish bounty update")?;

        info!(
            "Published bounty update for bounty: {} ({})",
            bounty_id, update_type
        );
        Ok(())
    }

    // Engine reputation caching
    pub async fn cache_engine_reputation(
        &self,
        engine_id: &str,
        reputation_score: f64,
        ttl_seconds: u64,
    ) -> Result<()> {
        let key = format!("engine_reputation:{engine_id}");

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .set_ex(&key, reputation_score, ttl_seconds)
            .await
            .context("Failed to cache engine reputation")?;

        info!(
            "Cached reputation for engine: {} (score: {})",
            engine_id, reputation_score
        );
        Ok(())
    }

    pub async fn get_engine_reputation(&self, engine_id: &str) -> Result<Option<f64>> {
        let key = format!("engine_reputation:{engine_id}");

        let mut conn = self.connection_pool.clone();
        let reputation: Option<f64> = conn
            .get(&key)
            .await
            .context("Failed to retrieve engine reputation")?;

        Ok(reputation)
    }

    // Leaderboard functionality
    pub async fn update_leaderboard(
        &self,
        leaderboard_name: &str,
        member: &str,
        score: f64,
    ) -> Result<()> {
        let key = format!("leaderboard:{leaderboard_name}");

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .zadd(&key, member, score)
            .await
            .context("Failed to update leaderboard")?;

        Ok(())
    }

    pub async fn get_leaderboard(
        &self,
        leaderboard_name: &str,
        limit: isize,
    ) -> Result<Vec<(String, f64)>> {
        let key = format!("leaderboard:{leaderboard_name}");

        let mut conn = self.connection_pool.clone();
        let results: Vec<(String, f64)> = conn
            .zrevrange_withscores(&key, 0, limit - 1)
            .await
            .context("Failed to retrieve leaderboard")?;

        Ok(results)
    }

    // Health check
    pub async fn health_check(&self) -> Result<bool> {
        let mut conn = self.connection_pool.clone();
        let result: RedisResult<String> = redis::cmd("PING").query_async(&mut conn).await;

        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                error!("Redis health check failed: {}", e);
                Ok(false)
            }
        }
    }

    // Cache statistics
    pub async fn get_cache_stats(&self) -> Result<serde_json::Value> {
        let mut conn = self.connection_pool.clone();
        let info: String = redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut conn)
            .await
            .context("Failed to get Redis memory info")?;

        // Parse basic stats from Redis INFO command
        let mut stats = serde_json::Map::new();

        for line in info.lines() {
            if line.contains(':') {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 {
                    match parts[0] {
                        "used_memory"
                        | "used_memory_human"
                        | "used_memory_peak"
                        | "used_memory_peak_human"
                        | "maxmemory"
                        | "maxmemory_human" => {
                            stats.insert(
                                parts[0].to_string(),
                                serde_json::Value::String(parts[1].to_string()),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(serde_json::Value::Object(stats))
    }

    // === Submission-related caching methods ===

    /// Push item to queue (FIFO using RPUSH/LPOP)
    /// Uses Redis list as a queue
    pub async fn push_to_queue(&self, queue_name: &str, item: &str) -> Result<()> {
        let key = format!("queue:{queue_name}");

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .rpush(&key, item)
            .await
            .context("Failed to push item to queue")?;

        info!("Pushed item to queue: {}", queue_name);
        Ok(())
    }

    /// Pop item from queue (FIFO using LPOP)
    pub async fn pop_from_queue(&self, queue_name: &str) -> Result<Option<String>> {
        let key = format!("queue:{queue_name}");

        let mut conn = self.connection_pool.clone();
        let item: Option<String> = conn
            .lpop(&key, None)
            .await
            .context("Failed to pop item from queue")?;

        if item.is_some() {
            info!("Popped item from queue: {}", queue_name);
        }

        Ok(item)
    }

    /// Queue a submission for the analysis-engine worker.
    ///
    /// The worker blocks on the Redis list `analysis_queue` (`BRPOPLPUSH`).
    /// Do not write `queue:analysis` (a sorted set) or `queue:analysis_queue`.
    /// The value must be the `submissions.id`, not a separate file id.
    /// `priority` is recorded in logs only; the worker is FIFO.
    pub async fn queue_for_analysis(&self, submission_id: uuid::Uuid, priority: i32) -> Result<()> {
        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .lpush("analysis_queue", submission_id.to_string())
            .await
            .context("Failed to queue analysis")?;

        info!(
            "Queued submission {} on analysis_queue (priority hint {})",
            submission_id, priority
        );
        Ok(())
    }

    // Dequeue highest priority analysis
    // Pops item with highest score from sorted set
    // pub async fn dequeue_analysis(&self) -> Result<Option<uuid::Uuid>> {
    //     let key = "queue:analysis";

    //     let mut conn = self.connection_pool.clone();
    //     // ZPOPMAX removes and returns highest score member
    //     let result: Option<(String, f64)> = conn
    //         .zpopmax(key, None)
    //         .await
    //         .context("Failed to dequeue analysis")?;

    //     match result {
    //         Some((member, priority)) => {
    //             let analysis_id = uuid::Uuid::parse_str(&member)
    //                 .context("Failed to parse analysis ID")?;
    //             info!("Dequeued analysis: {} (priority: {})", analysis_id, priority);
    //             Ok(Some(analysis_id))
    //         }
    //         None => Ok(None),
    //     }
    // }

    /// Cache file info with TTL (default: 1 hour)
    pub async fn cache_file_info(
        &self,
        file_hash: &str,
        file_info: &crate::handlers::submission::FileInfo,
    ) -> Result<()> {
        let key = format!("file_info:{file_hash}");
        let serialized =
            serde_json::to_string(file_info).context("Failed to serialize file info")?;

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .set_ex(&key, serialized, 3600) // 1 hour TTL
            .await
            .context("Failed to cache file info")?;

        info!("Cached file info for hash: {}", file_hash);
        Ok(())
    }

    /// Get cached file info
    pub async fn get_cached_file_info(
        &self,
        file_hash: &str,
    ) -> Result<Option<crate::handlers::submission::FileInfo>> {
        let key = format!("file_info:{file_hash}");

        let mut conn = self.connection_pool.clone();
        let cached: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to retrieve cached file info")?;

        match cached {
            Some(data) => {
                let file_info: crate::handlers::submission::FileInfo =
                    serde_json::from_str(&data).context("Failed to deserialize file info")?;
                Ok(Some(file_info))
            }
            None => Ok(None),
        }
    }

    /// Cache submission response with TTL (default: 5 minutes)
    pub async fn cache_submission(
        &self,
        submission_id: uuid::Uuid,
        submission: &crate::handlers::submission::SubmissionResponse,
    ) -> Result<()> {
        let key = format!("submission:{submission_id}");
        let serialized =
            serde_json::to_string(submission).context("Failed to serialize submission")?;

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .set_ex(&key, serialized, 300) // 5 minutes TTL
            .await
            .context("Failed to cache submission")?;

        info!("Cached submission: {}", submission_id);
        Ok(())
    }

    /// Cache detailed submission response with TTL (default: 10 minutes)
    pub async fn cache_detailed_submission(
        &self,
        submission_id: uuid::Uuid,
        submission: &crate::handlers::submission::DetailedSubmissionResponse,
    ) -> Result<()> {
        let key = format!("submission:detailed:{submission_id}");
        let serialized =
            serde_json::to_string(submission).context("Failed to serialize detailed submission")?;

        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .set_ex(&key, serialized, 600) // 10 minutes TTL
            .await
            .context("Failed to cache detailed submission")?;

        info!("Cached detailed submission: {}", submission_id);
        Ok(())
    }

    /// Get cached submission response
    pub async fn get_cached_submission(
        &self,
        submission_id: uuid::Uuid,
    ) -> Result<Option<crate::handlers::submission::SubmissionResponse>> {
        let key = format!("submission:{submission_id}");

        let mut conn = self.connection_pool.clone();
        let cached: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to retrieve cached submission")?;

        match cached {
            Some(data) => {
                let submission: crate::handlers::submission::SubmissionResponse =
                    serde_json::from_str(&data).context("Failed to deserialize submission")?;
                Ok(Some(submission))
            }
            None => Ok(None),
        }
    }

    /// Get cached detailed submission response
    pub async fn get_cached_detailed_submission(
        &self,
        submission_id: uuid::Uuid,
    ) -> Result<Option<crate::handlers::submission::DetailedSubmissionResponse>> {
        let key = format!("submission:detailed:{submission_id}");

        let mut conn = self.connection_pool.clone();
        let cached: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to retrieve cached detailed submission")?;

        match cached {
            Some(data) => {
                let submission: crate::handlers::submission::DetailedSubmissionResponse =
                    serde_json::from_str(&data)
                        .context("Failed to deserialize detailed submission")?;
                Ok(Some(submission))
            }
            None => Ok(None),
        }
    }

    /// Invalidate all caches for a submission
    pub async fn invalidate_submission_cache(&self, submission_id: uuid::Uuid) -> Result<()> {
        let keys = vec![
            format!("submission:{}", submission_id),
            format!("submission:detailed:{}", submission_id),
        ];

        let mut conn = self.connection_pool.clone();
        for key in &keys {
            let _: () = conn
                .del(key)
                .await
                .context("Failed to delete submission cache")?;
        }

        info!("Invalidated caches for submission: {}", submission_id);
        Ok(())
    }
    /// Get a raw string value by key
    pub async fn get_raw(&self, key: String) -> Result<Option<String>> {
        let mut conn = self.connection_pool.clone();
        let value: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to get raw value from Redis")?;
        Ok(value)
    }

    /// Set a raw string value with TTL (in seconds)
    pub async fn set_raw_with_ttl(
        &self,
        key: String,
        value: String,
        ttl_seconds: u64,
    ) -> Result<()> {
        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .set_ex(&key, value, ttl_seconds)
            .await
            .context("Failed to set raw value in Redis")?;
        Ok(())
    }

    /// Delete a key
    pub async fn delete_raw(&self, key: String) -> Result<()> {
        let mut conn = self.connection_pool.clone();
        let _: () = conn
            .del(&key)
            .await
            .context("Failed to delete key from Redis")?;
        Ok(())
    }
}
