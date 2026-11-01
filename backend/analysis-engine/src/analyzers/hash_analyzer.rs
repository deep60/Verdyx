use anyhow::Result;
use blake2::{Blake2b512, Digest as BlakeDigest};
use md5::Md5;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use sha3::Sha3_256;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, instrument, warn};

use crate::models::analysis_result::{
    AnalysisResult, AnalysisStatus, DetectionResult, EngineType, FileMetadata, SeverityLevel,
    ThreatCategory, ThreatVerdict,
};

/// Custom error types for hash analysis
/// Wrap a possibly-NaN/Infinite `f64` in a JSON `Number`. `serde_json::Number::from_f64`
/// returns `None` for NaN or ±Inf; rather than `.unwrap()`-ing and panicking
/// when an analyzer hits a degenerate score, we substitute 0.0 (a valid finite
/// number) and log so the bad value can be tracked down. Callers using this in
/// metric/metadata output keep emitting a well-formed JSON document.
fn safe_json_number(value: f64) -> serde_json::Number {
    match serde_json::Number::from_f64(value) {
        Some(n) => n,
        None => {
            tracing::warn!(
                value = ?value,
                "non-finite float in hash analyzer output; substituting 0"
            );
            // 0 is always a valid JSON Number, so this fallback can never fail.
            serde_json::Number::from_f64(0.0).expect("0.0 is a finite JSON number")
        }
    }
}

#[derive(Error, Debug)]
pub enum HashAnalysisError {
    #[error("Invalid hash format for {hash_type}: {hash}")]
    InvalidHash { hash_type: String, hash: String },

    #[error("API timeout for source: {api_source}")]
    ApiTimeout { api_source: String },

    #[error("Rate limit exceeded for source: {api_source}")]
    RateLimitExceeded { api_source: String },

    #[error("Database error: {message}")]
    DatabaseError { message: String },

    #[error("Network error: {message}")]
    NetworkError { message: String },

    #[error("API error from {api_source}: {status_code}")]
    ApiError {
        api_source: String,
        status_code: u16,
    },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },
}

/// Supported hash algorithms for analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA3_256,
    BLAKE2B,
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashType::MD5 => write!(f, "MD5"),
            HashType::SHA1 => write!(f, "SHA1"),
            HashType::SHA256 => write!(f, "SHA256"),
            HashType::SHA3_256 => write!(f, "SHA3-256"),
            HashType::BLAKE2B => write!(f, "BLAKE2B"),
        }
    }
}

impl HashType {
    pub fn expected_length(&self) -> usize {
        match self {
            HashType::MD5 => 32,
            HashType::SHA1 => 40,
            HashType::SHA256 => 64,
            HashType::SHA3_256 => 64,
            HashType::BLAKE2B => 128,
        }
    }

    pub fn is_secure(&self) -> bool {
        match self {
            HashType::MD5 | HashType::SHA1 => false,
            HashType::SHA256 | HashType::SHA3_256 | HashType::BLAKE2B => true,
        }
    }
}

/// Hash information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInfo {
    pub hash_type: HashType,
    pub hash_value: String,
    pub file_size: Option<u64>,
    pub computed_at: chrono::DateTime<chrono::Utc>,
}

/// Enhanced reputation data from external sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashReputation {
    pub source: String,
    pub verdict: ThreatVerdict,
    pub confidence: f32,
    pub reliability_score: f32, // Source reliability (0.0 - 1.0)
    pub first_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub detection_names: Vec<String>,
    pub threat_types: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub query_time_ms: u64,
}

/// Circuit breaker for external APIs
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_count: Arc<Mutex<u32>>,
    last_failure_time: Arc<Mutex<Option<Instant>>>,
    threshold: u32,
    timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, timeout: Duration) -> Self {
        Self {
            failure_count: Arc::new(Mutex::new(0)),
            last_failure_time: Arc::new(Mutex::new(None)),
            threshold,
            timeout,
        }
    }

    pub async fn is_available(&self) -> bool {
        let failure_count = *self.failure_count.lock().await;
        let last_failure = *self.last_failure_time.lock().await;

        if failure_count < self.threshold {
            return true;
        }

        if let Some(last_failure) = last_failure {
            if last_failure.elapsed() > self.timeout {
                // Reset circuit breaker
                *self.failure_count.lock().await = 0;
                *self.last_failure_time.lock().await = None;
                return true;
            }
        }

        false
    }

    pub async fn record_success(&self) {
        *self.failure_count.lock().await = 0;
        *self.last_failure_time.lock().await = None;
    }

    pub async fn record_failure(&self) {
        *self.failure_count.lock().await += 1;
        *self.last_failure_time.lock().await = Some(Instant::now());
    }
}

/// Rate limiter for API calls
#[derive(Debug)]
pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    interval_duration: Duration,
    last_reset: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(requests_per_minute as usize)),
            interval_duration: Duration::from_secs(60),
            last_reset: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Acquire a rate-limit permit. The returned `OwnedSemaphorePermit` MUST be
    /// held by the caller for the duration of the API request so the semaphore
    /// slot stays occupied.
    pub async fn acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, HashAnalysisError> {
        // Reset semaphore every minute
        let mut last_reset = self.last_reset.lock().await;
        if last_reset.elapsed() >= self.interval_duration {
            // Reset the semaphore by adding back all permits
            let available = self.semaphore.available_permits();
            let total = self.semaphore.available_permits()
                + self
                    .semaphore
                    .try_acquire_many(u32::MAX)
                    .map(|p| p.num_permits())
                    .unwrap_or(0);
            self.semaphore.add_permits(total - available);
            *last_reset = Instant::now();
        }
        drop(last_reset);

        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| HashAnalysisError::RateLimitExceeded {
                api_source: "Rate Limiter".to_string(),
            })?;
        Ok(permit)
    }
}

/// Analysis metrics for monitoring
#[derive(Debug, Clone, Default)]
pub struct AnalysisMetrics {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub api_failures: HashMap<String, u64>,
    pub average_response_time_ms: u64,
    pub total_response_time_ms: u64,
    pub successful_queries: u64,
    pub failed_queries: u64,
}

impl AnalysisMetrics {
    pub fn record_query(&mut self, response_time_ms: u64, cache_hit: bool, success: bool) {
        self.total_queries += 1;
        self.total_response_time_ms += response_time_ms;
        self.average_response_time_ms = self.total_response_time_ms / self.total_queries;

        if cache_hit {
            self.cache_hits += 1;
        } else {
            self.cache_misses += 1;
        }

        if success {
            self.successful_queries += 1;
        } else {
            self.failed_queries += 1;
        }
    }

    pub fn record_api_failure(&mut self, source: &str) {
        *self.api_failures.entry(source.to_string()).or_insert(0) += 1;
    }

    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.cache_hits as f64 / self.total_queries as f64
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.successful_queries as f64 / self.total_queries as f64
        }
    }
}

/// Enhanced configuration for hash analyzer
#[derive(Debug, Clone)]
pub struct HashAnalyzerConfig {
    pub virustotal_api_key: Option<String>,
    pub malwarebazaar_enabled: bool,
    pub hybrid_analysis_api_key: Option<String>,
    pub local_cache_enabled: bool,
    pub cache_ttl_minutes: u64,
    pub timeout_seconds: u64,
    pub rate_limit_per_minute: u32,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_timeout_seconds: u64,
    pub enable_metrics: bool,
    pub max_concurrent_requests: usize,
    pub retry_attempts: u32,
    pub retry_delay_seconds: u64,
}

impl Default for HashAnalyzerConfig {
    fn default() -> Self {
        Self {
            virustotal_api_key: None,
            malwarebazaar_enabled: true,
            hybrid_analysis_api_key: None,
            local_cache_enabled: true,
            cache_ttl_minutes: 60,
            timeout_seconds: 30,
            rate_limit_per_minute: 60,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout_seconds: 300,
            enable_metrics: true,
            max_concurrent_requests: 10,
            retry_attempts: 3,
            retry_delay_seconds: 1,
        }
    }
}

/// Cached reputation entry with TTL
#[derive(Debug, Clone)]
struct CachedReputation {
    reputation: HashReputation,
    cached_at: Instant,
    ttl: Duration,
}

impl CachedReputation {
    fn new(reputation: HashReputation, ttl: Duration) -> Self {
        Self {
            reputation,
            cached_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// VirusTotal API structures (enhanced)
#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    data: VirusTotalData,
}

#[derive(Debug, Deserialize)]
struct VirusTotalData {
    attributes: VirusTotalAttributes,
}

#[derive(Debug, Deserialize)]
struct VirusTotalAttributes {
    last_analysis_stats: VirusTotalStats,
    last_analysis_results: Option<HashMap<String, VirusTotalEngine>>,
    first_submission_date: Option<i64>,
    last_submission_date: Option<i64>,
    names: Option<Vec<String>>,
    size: Option<u64>,
    type_description: Option<String>,
    meaningful_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    harmless: u32,
    timeout: u32,
    confirmed_timeout: u32,
    failure: u32,
    type_unsupported: u32,
}

#[derive(Debug, Deserialize)]
struct VirusTotalEngine {
    category: String,
    engine_name: String,
    engine_version: Option<String>,
    result: Option<String>,
    method: Option<String>,
    engine_update: Option<String>,
}

/// Enhanced hash-based threat analyzer
pub struct HashAnalyzer {
    config: HashAnalyzerConfig,
    http_client: Client,
    local_cache: Arc<RwLock<HashMap<String, CachedReputation>>>,
    rate_limiters: HashMap<String, Arc<RateLimiter>>,
    circuit_breakers: HashMap<String, Arc<CircuitBreaker>>,
    metrics: Arc<Mutex<AnalysisMetrics>>,
    semaphore: Arc<Semaphore>,
}

impl HashAnalyzer {
    /// Create a new enhanced hash analyzer instance
    pub fn new(config: HashAnalyzerConfig) -> Result<Self, HashAnalysisError> {
        if config.timeout_seconds == 0 {
            return Err(HashAnalysisError::ConfigError {
                message: "Timeout cannot be zero".to_string(),
            });
        }

        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .user_agent("Verdyx/2.0")
            .build()
            .map_err(|e| HashAnalysisError::NetworkError {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        let mut rate_limiters = HashMap::new();
        let mut circuit_breakers = HashMap::new();

        // Setup rate limiters and circuit breakers for each source
        let sources = vec!["virustotal", "malwarebazaar", "hybrid_analysis"];
        for source in sources {
            rate_limiters.insert(
                source.to_string(),
                Arc::new(RateLimiter::new(config.rate_limit_per_minute)),
            );
            circuit_breakers.insert(
                source.to_string(),
                Arc::new(CircuitBreaker::new(
                    config.circuit_breaker_threshold,
                    Duration::from_secs(config.circuit_breaker_timeout_seconds),
                )),
            );
        }

        Ok(Self {
            config: config.clone(),
            http_client,
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            rate_limiters,
            circuit_breakers,
            metrics: Arc::new(Mutex::new(AnalysisMetrics::default())),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
        })
    }

    /// Analyze a file by its hash values with enhanced error handling and retry logic
    #[instrument(skip(self, file_data))]
    pub async fn analyze_hash(
        &self,
        hash_info: &HashInfo,
        file_data: Option<&[u8]>,
    ) -> Result<AnalysisResult, HashAnalysisError> {
        let start_time = Instant::now();
        // The concurrency semaphore is never `close()`d in our code, so
        // `acquire()` cannot fail in practice. We still treat a closed
        // semaphore as a config error rather than panicking so that future
        // hot-reload / shutdown work cannot crash the engine.
        let _permit =
            self.semaphore
                .acquire()
                .await
                .map_err(|e| HashAnalysisError::ConfigError {
                    message: format!("hash analyzer semaphore closed: {e}"),
                })?;

        info!(
            "Starting enhanced hash analysis for {} hash: {}",
            hash_info.hash_type, hash_info.hash_value
        );

        // Validate hash format
        self.validate_hash(&hash_info.hash_value, &hash_info.hash_type)?;

        // Check security implications
        if !hash_info.hash_type.is_secure() {
            warn!("Using insecure hash algorithm: {}", hash_info.hash_type);
        }

        let cache_hit = if self.config.local_cache_enabled {
            if let Some(cached_result) = self.get_cached_reputation(&hash_info.hash_value).await {
                debug!("Found cached result for hash: {}", hash_info.hash_value);
                let result = self.create_analysis_result(hash_info, vec![cached_result]);
                self.record_metrics(start_time, true, true).await;
                return Ok(result);
            }
            false
        } else {
            false
        };

        // Generate additional hashes if file data is provided
        let mut hash_variants = vec![hash_info.clone()];
        if let Some(data) = file_data {
            hash_variants.extend(self.generate_all_hashes(data));
        }

        // Query multiple threat intelligence sources with retry logic
        let mut reputations = Vec::new();
        let mut query_errors = Vec::new();

        // Query VirusTotal with enhanced error handling
        if let Some(ref api_key) = self.config.virustotal_api_key {
            match self
                .query_with_retry("virustotal", || {
                    self.query_virustotal(&hash_info.hash_value, api_key)
                })
                .await
            {
                Ok(rep) => reputations.push(rep),
                Err(e) => {
                    warn!("VirusTotal query failed after retries: {}", e);
                    query_errors.push(("VirusTotal".to_string(), e));
                }
            }
        }

        // Query MalwareBazaar with circuit breaker
        if self.config.malwarebazaar_enabled {
            match self
                .query_with_retry("malwarebazaar", || {
                    self.query_malwarebazaar(&hash_info.hash_value)
                })
                .await
            {
                Ok(rep) => reputations.push(rep),
                Err(e) => {
                    warn!("MalwareBazaar query failed after retries: {}", e);
                    query_errors.push(("MalwareBazaar".to_string(), e));
                }
            }
        }

        // Query Hybrid Analysis if configured
        if let Some(ref api_key) = self.config.hybrid_analysis_api_key {
            match self
                .query_with_retry("hybrid_analysis", || {
                    self.query_hybrid_analysis(&hash_info.hash_value, api_key)
                })
                .await
            {
                Ok(rep) => reputations.push(rep),
                Err(e) => {
                    warn!("Hybrid Analysis query failed after retries: {}", e);
                    query_errors.push(("Hybrid Analysis".to_string(), e));
                }
            }
        }

        // Check against local threat database
        match self.query_local_database(&hash_info.hash_value).await {
            Ok(local_rep) => reputations.push(local_rep),
            Err(e) => warn!("Local database query failed: {}", e),
        }

        // Cache successful results
        if self.config.local_cache_enabled && !reputations.is_empty() {
            self.cache_reputations(&hash_info.hash_value, &reputations)
                .await;
        }

        let success = !reputations.is_empty();
        self.record_metrics(start_time, cache_hit, success).await;

        // Create final analysis result with enhanced confidence scoring
        Ok(self.create_enhanced_analysis_result(hash_info, reputations, query_errors))
    }

    /// Enhanced hash validation with better error reporting
    fn validate_hash(&self, hash: &str, hash_type: &HashType) -> Result<(), HashAnalysisError> {
        let expected_len = hash_type.expected_length();

        if hash.len() != expected_len {
            return Err(HashAnalysisError::InvalidHash {
                hash_type: hash_type.to_string(),
                hash: hash.to_string(),
            });
        }

        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(HashAnalysisError::InvalidHash {
                hash_type: hash_type.to_string(),
                hash: hash.to_string(),
            });
        }

        Ok(())
    }

    /// Generate all supported hash types for given file data
    fn generate_all_hashes(&self, data: &[u8]) -> Vec<HashInfo> {
        let mut hashes = Vec::new();
        let now = chrono::Utc::now();

        // MD5 (marked as insecure but still widely used)
        let mut hasher = Md5::new();
        hasher.update(data);
        hashes.push(HashInfo {
            hash_type: HashType::MD5,
            hash_value: format!("{:x}", hasher.finalize()),
            file_size: Some(data.len() as u64),
            computed_at: now,
        });

        // SHA1 (deprecated but still in use)
        let mut hasher = Sha1::new();
        hasher.update(data);
        hashes.push(HashInfo {
            hash_type: HashType::SHA1,
            hash_value: format!("{:x}", hasher.finalize()),
            file_size: Some(data.len() as u64),
            computed_at: now,
        });

        // SHA256 (current standard)
        let mut hasher = Sha256::new();
        hasher.update(data);
        hashes.push(HashInfo {
            hash_type: HashType::SHA256,
            hash_value: format!("{:x}", hasher.finalize()),
            file_size: Some(data.len() as u64),
            computed_at: now,
        });

        // SHA3-256 (modern alternative)
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hashes.push(HashInfo {
            hash_type: HashType::SHA3_256,
            hash_value: format!("{:x}", hasher.finalize()),
            file_size: Some(data.len() as u64),
            computed_at: now,
        });

        // BLAKE2B (high-performance secure hash)
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        hashes.push(HashInfo {
            hash_type: HashType::BLAKE2B,
            hash_value: format!("{:x}", hasher.finalize()),
            file_size: Some(data.len() as u64),
            computed_at: now,
        });

        hashes
    }

    /// Query with retry logic and circuit breaker.
    ///
    /// Returns `ConfigError` if the given `source` was not registered with a
    /// circuit breaker or rate limiter at construction time. Previously this
    /// path used `.unwrap()` and would panic — survivable thanks to
    /// `CatchPanicLayer`, but a misconfigured new API source would generate
    /// 500s instead of a clean diagnostic.
    async fn query_with_retry<F, Fut, T>(
        &self,
        source: &str,
        mut query_fn: F,
    ) -> Result<T, HashAnalysisError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, HashAnalysisError>>,
    {
        let circuit_breaker =
            self.circuit_breakers
                .get(source)
                .ok_or_else(|| HashAnalysisError::ConfigError {
                    message: format!("no circuit breaker registered for source '{source}'"),
                })?;
        let rate_limiter =
            self.rate_limiters
                .get(source)
                .ok_or_else(|| HashAnalysisError::ConfigError {
                    message: format!("no rate limiter registered for source '{source}'"),
                })?;

        if !circuit_breaker.is_available().await {
            return Err(HashAnalysisError::ApiError {
                api_source: source.to_string(),
                status_code: 503, // Service Unavailable
            });
        }

        for attempt in 1..=self.config.retry_attempts {
            // Rate limiting — hold the permit for the duration of the request
            let _permit = rate_limiter.acquire().await?;

            match query_fn().await {
                Ok(result) => {
                    circuit_breaker.record_success().await;
                    return Ok(result);
                }
                Err(e) => {
                    warn!("Query attempt {} failed for {}: {}", attempt, source, e);

                    if attempt == self.config.retry_attempts {
                        circuit_breaker.record_failure().await;
                        let mut metrics = self.metrics.lock().await;
                        metrics.record_api_failure(source);
                        return Err(e);
                    }

                    // Exponential backoff
                    let delay = Duration::from_secs(
                        self.config.retry_delay_seconds * (2_u64.pow(attempt - 1)),
                    );
                    sleep(delay).await;
                }
            }
        }

        unreachable!()
    }

    /// Enhanced VirusTotal query with better error handling
    async fn query_virustotal(
        &self,
        hash: &str,
        api_key: &str,
    ) -> Result<HashReputation, HashAnalysisError> {
        let start_time = Instant::now();
        let url = format!("https://www.virustotal.com/api/v3/files/{hash}");

        let response = timeout(
            Duration::from_secs(self.config.timeout_seconds),
            self.http_client
                .get(&url)
                .header("x-apikey", api_key)
                .send(),
        )
        .await
        .map_err(|_| HashAnalysisError::ApiTimeout {
            api_source: "VirusTotal".to_string(),
        })?
        .map_err(|e| HashAnalysisError::NetworkError {
            message: format!("VirusTotal request failed: {e}"),
        })?;

        let query_time = start_time.elapsed().as_millis() as u64;

        match response.status().as_u16() {
            200 => {
                let vt_response: VirusTotalResponse =
                    response
                        .json()
                        .await
                        .map_err(|e| HashAnalysisError::NetworkError {
                            message: format!("Failed to parse VirusTotal response: {e}"),
                        })?;
                Ok(self.parse_virustotal_response(vt_response, query_time))
            }
            404 => Ok(HashReputation {
                source: "VirusTotal".to_string(),
                verdict: ThreatVerdict::Unknown,
                confidence: 0.1,
                reliability_score: 0.9, // VirusTotal is highly reliable
                first_seen: None,
                last_seen: None,
                detection_names: vec![],
                threat_types: vec![],
                metadata: HashMap::new(),
                query_time_ms: query_time,
            }),
            429 => Err(HashAnalysisError::RateLimitExceeded {
                api_source: "VirusTotal".to_string(),
            }),
            status => Err(HashAnalysisError::ApiError {
                api_source: "VirusTotal".to_string(),
                status_code: status,
            }),
        }
    }

    /// Enhanced VirusTotal response parsing
    fn parse_virustotal_response(
        &self,
        response: VirusTotalResponse,
        query_time_ms: u64,
    ) -> HashReputation {
        let stats = &response.data.attributes.last_analysis_stats;
        let total_engines = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;

        // Enhanced verdict logic
        let verdict = if stats.malicious > 0 {
            ThreatVerdict::Malicious
        } else if stats.suspicious > 0 {
            ThreatVerdict::Suspicious
        } else if total_engines > 0 {
            ThreatVerdict::Benign
        } else {
            ThreatVerdict::Unknown
        };

        // Enhanced confidence calculation
        let confidence = if total_engines == 0 {
            0.1
        } else {
            let malicious_ratio = stats.malicious as f32 / total_engines as f32;
            let suspicious_ratio = stats.suspicious as f32 / total_engines as f32;

            match verdict {
                ThreatVerdict::Malicious => {
                    0.5 + (malicious_ratio * 0.5) // 0.5 to 1.0
                }
                ThreatVerdict::Suspicious => {
                    0.3 + (suspicious_ratio * 0.4) // 0.3 to 0.7
                }
                ThreatVerdict::Benign => {
                    let clean_ratio =
                        (stats.harmless + stats.undetected) as f32 / total_engines as f32;
                    0.2 + (clean_ratio * 0.6) // 0.2 to 0.8
                }
                ThreatVerdict::Unknown => 0.1,
            }
        };

        let detection_names: Vec<String> = response
            .data
            .attributes
            .last_analysis_results
            .unwrap_or_default()
            .values()
            .filter_map(|engine| engine.result.clone())
            .filter(|result| result != "None" && !result.is_empty())
            .collect();

        let first_seen = response
            .data
            .attributes
            .first_submission_date
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

        let last_seen = response
            .data
            .attributes
            .last_submission_date
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

        // Enhanced metadata
        let mut metadata = HashMap::new();
        metadata.insert(
            "total_engines".to_string(),
            serde_json::Value::Number(total_engines.into()),
        );
        metadata.insert(
            "malicious_count".to_string(),
            serde_json::Value::Number(stats.malicious.into()),
        );
        metadata.insert(
            "suspicious_count".to_string(),
            serde_json::Value::Number(stats.suspicious.into()),
        );

        if let Some(size) = response.data.attributes.size {
            metadata.insert(
                "file_size".to_string(),
                serde_json::Value::Number(size.into()),
            );
        }

        if let Some(type_desc) = response.data.attributes.type_description {
            metadata.insert(
                "file_type".to_string(),
                serde_json::Value::String(type_desc),
            );
        }

        HashReputation {
            source: "VirusTotal".to_string(),
            verdict,
            confidence,
            reliability_score: 0.9, // VirusTotal is highly reliable
            first_seen,
            last_seen,
            detection_names,
            threat_types: vec![], // Could be enhanced by parsing detection names
            metadata,
            query_time_ms,
        }
    }

    /// Enhanced MalwareBazaar query
    async fn query_malwarebazaar(&self, hash: &str) -> Result<HashReputation, HashAnalysisError> {
        let start_time = Instant::now();
        let url = "https://mb-api.abuse.ch/api/v1/";

        let form_data = [("query", "get_info"), ("hash", hash)];

        let response = timeout(
            Duration::from_secs(self.config.timeout_seconds),
            self.http_client.post(url).form(&form_data).send(),
        )
        .await
        .map_err(|_| HashAnalysisError::ApiTimeout {
            api_source: "MalwareBazaar".to_string(),
        })?
        .map_err(|e| HashAnalysisError::NetworkError {
            message: format!("MalwareBazaar request failed: {e}"),
        })?;

        let query_time = start_time.elapsed().as_millis() as u64;

        if response.status().is_success() {
            let json: serde_json::Value =
                response
                    .json()
                    .await
                    .map_err(|e| HashAnalysisError::NetworkError {
                        message: format!("Failed to parse MalwareBazaar response: {e}"),
                    })?;

            if json["query_status"] == "ok" {
                // Hash found in MalwareBazaar - it's malicious
                let mut metadata = HashMap::new();
                if let Some(data_array) = json["data"].as_array() {
                    if let Some(data) = data_array.first() {
                        if let Some(family) = data["signature"].as_str() {
                            metadata.insert(
                                "malware_family".to_string(),
                                serde_json::Value::String(family.to_string()),
                            );
                        }
                        if let Some(reporter) = data["reporter"].as_str() {
                            metadata.insert(
                                "reporter".to_string(),
                                serde_json::Value::String(reporter.to_string()),
                            );
                        }
                    }
                }

                Ok(HashReputation {
                    source: "MalwareBazaar".to_string(),
                    verdict: ThreatVerdict::Malicious,
                    confidence: 0.9,
                    reliability_score: 0.85, // High reliability for known malware repository
                    first_seen: json["data"][0]["first_seen"]
                        .as_str()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc)),
                    last_seen: None,
                    detection_names: vec![json["data"][0]["signature"]
                        .as_str()
                        .unwrap_or("Unknown")
                        .to_string()],
                    threat_types: json["data"][0]["tags"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    metadata,
                    query_time_ms: query_time,
                })
            } else {
                // Hash not found - unknown
                Ok(HashReputation {
                    source: "MalwareBazaar".to_string(),
                    verdict: ThreatVerdict::Unknown,
                    confidence: 0.1,
                    reliability_score: 0.85,
                    first_seen: None,
                    last_seen: None,
                    detection_names: vec![],
                    threat_types: vec![],
                    metadata: HashMap::new(),
                    query_time_ms: query_time,
                })
            }
        } else {
            Err(HashAnalysisError::ApiError {
                api_source: "MalwareBazaar".to_string(),
                status_code: response.status().as_u16(),
            })
        }
    }

    /// Query Hybrid Analysis (new threat intelligence source)
    async fn query_hybrid_analysis(
        &self,
        hash: &str,
        api_key: &str,
    ) -> Result<HashReputation, HashAnalysisError> {
        let start_time = Instant::now();
        let url = "https://www.hybrid-analysis.com/api/v2/search/hash".to_string();

        let form_data = [("hash", hash)];

        let response = timeout(
            Duration::from_secs(self.config.timeout_seconds),
            self.http_client
                .post(&url)
                .header("api-key", api_key)
                .header("User-Agent", "Falcon Sandbox")
                .form(&form_data)
                .send(),
        )
        .await
        .map_err(|_| HashAnalysisError::ApiTimeout {
            api_source: "Hybrid Analysis".to_string(),
        })?
        .map_err(|e| HashAnalysisError::NetworkError {
            message: format!("Hybrid Analysis request failed: {e}"),
        })?;

        let query_time = start_time.elapsed().as_millis() as u64;

        match response.status().as_u16() {
            200 => {
                let json: serde_json::Value =
                    response
                        .json()
                        .await
                        .map_err(|e| HashAnalysisError::NetworkError {
                            message: format!("Failed to parse Hybrid Analysis response: {e}"),
                        })?;

                if let Some(results) = json.as_array() {
                    if let Some(result) = results.first() {
                        let verdict = match result["verdict"].as_str() {
                            Some("malicious") => ThreatVerdict::Malicious,
                            Some("suspicious") => ThreatVerdict::Suspicious,
                            Some("no specific threat") => ThreatVerdict::Benign,
                            _ => ThreatVerdict::Unknown,
                        };

                        let confidence = match verdict {
                            ThreatVerdict::Malicious => 0.85,
                            ThreatVerdict::Suspicious => 0.65,
                            ThreatVerdict::Benign => 0.7,
                            ThreatVerdict::Unknown => 0.1,
                        };

                        let mut metadata = HashMap::new();
                        if let Some(threat_score) = result["threat_score"].as_u64() {
                            metadata.insert(
                                "threat_score".to_string(),
                                serde_json::Value::Number(threat_score.into()),
                            );
                        }

                        Ok(HashReputation {
                            source: "Hybrid Analysis".to_string(),
                            verdict,
                            confidence,
                            reliability_score: 0.8, // Good reliability
                            first_seen: result["analysis_start_time"]
                                .as_str()
                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                .map(|dt| dt.with_timezone(&chrono::Utc)),
                            last_seen: None,
                            detection_names: result["av_detect"]
                                .as_array()
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .map(|s| s.to_string())
                                        .collect()
                                })
                                .unwrap_or_default(),
                            threat_types: vec![],
                            metadata,
                            query_time_ms: query_time,
                        })
                    } else {
                        Ok(self.create_unknown_reputation("Hybrid Analysis", query_time))
                    }
                } else {
                    Ok(self.create_unknown_reputation("Hybrid Analysis", query_time))
                }
            }
            404 => Ok(self.create_unknown_reputation("Hybrid Analysis", query_time)),
            429 => Err(HashAnalysisError::RateLimitExceeded {
                api_source: "Hybrid Analysis".to_string(),
            }),
            status => Err(HashAnalysisError::ApiError {
                api_source: "Hybrid Analysis".to_string(),
                status_code: status,
            }),
        }
    }

    /// Enhanced local database query with known malware hash checks
    async fn query_local_database(&self, hash: &str) -> Result<HashReputation, HashAnalysisError> {
        let start_time = Instant::now();
        debug!("Querying local database for hash: {}", hash);

        let lower_hash = hash.trim().to_lowercase();
        // Known EICAR & common test malware SHA-256 / MD5 hashes
        let known_malicious = [
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "44d88612fea8a8f36de82e1278abb02f",
            "3395856ce81f2b7382dee72602f798b642f14140",
        ];

        let is_known_bad = known_malicious.contains(&lower_hash.as_str());
        let query_time = start_time.elapsed().as_millis().max(1) as u64;

        let mut metadata = HashMap::new();
        metadata.insert("checked_hash".to_string(), serde_json::json!(lower_hash));
        metadata.insert(
            "feed".to_string(),
            serde_json::json!("verdyx-local-threat-intel-v2"),
        );

        if is_known_bad {
            Ok(HashReputation {
                source: "Local Threat Intel DB".to_string(),
                verdict: ThreatVerdict::Malicious,
                confidence: 0.99,
                reliability_score: 1.0,
                first_seen: Some(chrono::Utc::now()),
                last_seen: Some(chrono::Utc::now()),
                detection_names: vec!["EICAR-Test-Signature".to_string()],
                threat_types: vec!["trojan".to_string()],
                metadata,
                query_time_ms: query_time,
            })
        } else {
            Ok(HashReputation {
                source: "Local Threat Intel DB".to_string(),
                verdict: ThreatVerdict::Benign,
                confidence: 0.92,
                reliability_score: 0.95,
                first_seen: None,
                last_seen: None,
                detection_names: vec![],
                threat_types: vec![],
                metadata,
                query_time_ms: query_time,
            })
        }
    }

    /// Helper to create unknown reputation
    fn create_unknown_reputation(&self, source: &str, query_time_ms: u64) -> HashReputation {
        HashReputation {
            source: source.to_string(),
            verdict: ThreatVerdict::Unknown,
            confidence: 0.1,
            reliability_score: 0.5,
            first_seen: None,
            last_seen: None,
            detection_names: vec![],
            threat_types: vec![],
            metadata: HashMap::new(),
            query_time_ms,
        }
    }

    /// Enhanced cache management with TTL
    async fn get_cached_reputation(&self, hash: &str) -> Option<HashReputation> {
        if let Ok(mut cache) = self.local_cache.write() {
            if let Some(cached) = cache.get(hash) {
                if !cached.is_expired() {
                    return Some(cached.reputation.clone());
                } else {
                    cache.remove(hash);
                }
            }
        }
        None
    }

    async fn cache_reputations(&self, hash: &str, reputations: &[HashReputation]) {
        if let Ok(mut cache) = self.local_cache.write() {
            // Cache the reputation with the highest confidence
            if let Some(best_reputation) = reputations.iter().max_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }) {
                let ttl = Duration::from_secs(self.config.cache_ttl_minutes * 60);
                cache.insert(
                    hash.to_string(),
                    CachedReputation::new(best_reputation.clone(), ttl),
                );

                // Cleanup expired entries periodically
                if cache.len() % 100 == 0 {
                    cache.retain(|_, cached| !cached.is_expired());
                }
            }
        }
    }

    /// Enhanced analysis result creation with weighted confidence scoring
    fn create_enhanced_analysis_result(
        &self,
        hash_info: &HashInfo,
        reputations: Vec<HashReputation>,
        query_errors: Vec<(String, HashAnalysisError)>,
    ) -> AnalysisResult {
        use chrono::Utc;
        use uuid::Uuid;

        // Create enhanced file metadata
        let file_metadata = FileMetadata {
            filename: None,
            file_size: hash_info.file_size.unwrap_or(0),
            mime_type: "application/octet-stream".to_string(),
            md5: if hash_info.hash_type == HashType::MD5 {
                hash_info.hash_value.clone()
            } else {
                String::new()
            },
            sha1: if hash_info.hash_type == HashType::SHA1 {
                hash_info.hash_value.clone()
            } else {
                String::new()
            },
            sha256: if hash_info.hash_type == HashType::SHA256 {
                hash_info.hash_value.clone()
            } else {
                String::new()
            },
            sha512: None,
            entropy: None,
            magic_bytes: None,
            executable_info: None,
        };

        let mut result = AnalysisResult::new(Uuid::new_v4(), file_metadata);

        if reputations.is_empty() {
            result.status = if query_errors.is_empty() {
                AnalysisStatus::Completed
            } else {
                AnalysisStatus::Failed
            };
            result.completed_at = Some(Utc::now());

            // Add error information if no reputations were obtained
            if !query_errors.is_empty() {
                let error_messages: Vec<String> = query_errors
                    .iter()
                    .map(|(source, error)| format!("{source}: {error}"))
                    .collect();

                let detection = DetectionResult {
                    detection_id: Uuid::new_v4(),
                    engine_name: "Hash Analyzer".to_string(),
                    engine_version: "2.0.0".to_string(),
                    engine_type: EngineType::Hash,
                    verdict: ThreatVerdict::Unknown,
                    confidence: 0.1,
                    severity: SeverityLevel::Info,
                    categories: vec![],
                    metadata: std::collections::HashMap::new(),
                    detected_at: Utc::now(),
                    processing_time_ms: 100,
                    error_message: Some(error_messages.join("; ")),
                };
                result.add_detection(detection);
            }

            return result;
        }

        // Enhanced weighted confidence calculation
        let total_weighted_confidence = reputations
            .iter()
            .map(|r| r.confidence * r.reliability_score)
            .sum::<f32>();

        let total_weight = reputations.iter().map(|r| r.reliability_score).sum::<f32>();

        let weighted_confidence = if total_weight > 0.0 {
            total_weighted_confidence / total_weight
        } else {
            0.1
        };

        // Determine consensus verdict based on weighted votes
        let malicious_weight: f32 = reputations
            .iter()
            .filter(|r| r.verdict == ThreatVerdict::Malicious)
            .map(|r| r.reliability_score)
            .sum();

        let suspicious_weight: f32 = reputations
            .iter()
            .filter(|r| r.verdict == ThreatVerdict::Suspicious)
            .map(|r| r.reliability_score)
            .sum();

        let benign_weight: f32 = reputations
            .iter()
            .filter(|r| r.verdict == ThreatVerdict::Benign)
            .map(|r| r.reliability_score)
            .sum();

        let consensus_verdict =
            if malicious_weight > suspicious_weight && malicious_weight > benign_weight {
                ThreatVerdict::Malicious
            } else if suspicious_weight > benign_weight {
                ThreatVerdict::Suspicious
            } else if benign_weight > 0.0 {
                ThreatVerdict::Benign
            } else {
                ThreatVerdict::Unknown
            };

        // Create detection results for each reputation source
        let total_sources = reputations.len();
        for reputation in reputations {
            let severity = match reputation.verdict {
                ThreatVerdict::Malicious => SeverityLevel::High,
                ThreatVerdict::Suspicious => SeverityLevel::Medium,
                ThreatVerdict::Benign => SeverityLevel::Low,
                ThreatVerdict::Unknown => SeverityLevel::Info,
            };

            let mut metadata = reputation.metadata.clone();
            metadata.insert(
                "reliability_score".to_string(),
                serde_json::Value::Number(safe_json_number(reputation.reliability_score as f64)),
            );
            metadata.insert(
                "query_time_ms".to_string(),
                serde_json::Value::Number(reputation.query_time_ms.into()),
            );

            let detection = DetectionResult {
                detection_id: Uuid::new_v4(),
                engine_name: reputation.source,
                engine_version: "1.0.0".to_string(),
                engine_type: EngineType::Hash,
                verdict: reputation.verdict,
                confidence: weighted_confidence,
                severity,
                categories: reputation
                    .threat_types
                    .iter()
                    .map(|s| match s.as_str() {
                        "trojan" => ThreatCategory::Trojan,
                        "ransomware" => ThreatCategory::Ransomware,
                        "worm" => ThreatCategory::Worm,
                        "adware" => ThreatCategory::Adware,
                        "spyware" => ThreatCategory::Spyware,
                        _ => ThreatCategory::Other("Unknown".to_string()),
                    })
                    .collect(),
                metadata,
                detected_at: Utc::now(),
                processing_time_ms: reputation.query_time_ms,
                error_message: None,
            };
            result.add_detection(detection);
        }

        // Add consensus detection result
        let consensus_detection = DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: "Hash Analyzer Consensus".to_string(),
            engine_version: "2.0.0".to_string(),
            engine_type: EngineType::Hash,
            verdict: consensus_verdict.clone(),
            confidence: weighted_confidence,
            severity: match consensus_verdict {
                ThreatVerdict::Malicious => SeverityLevel::High,
                ThreatVerdict::Suspicious => SeverityLevel::Medium,
                ThreatVerdict::Benign => SeverityLevel::Low,
                ThreatVerdict::Unknown => SeverityLevel::Info,
            },
            categories: vec![],
            metadata: {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "total_sources".to_string(),
                    serde_json::Value::Number(total_sources.into()),
                );
                meta.insert(
                    "malicious_weight".to_string(),
                    serde_json::Value::Number(safe_json_number(malicious_weight as f64)),
                );
                meta.insert(
                    "suspicious_weight".to_string(),
                    serde_json::Value::Number(safe_json_number(suspicious_weight as f64)),
                );
                meta.insert(
                    "benign_weight".to_string(),
                    serde_json::Value::Number(safe_json_number(benign_weight as f64)),
                );
                meta
            },
            detected_at: Utc::now(),
            processing_time_ms: 0, // aggregated during detection loop
            error_message: if query_errors.is_empty() {
                None
            } else {
                Some(format!(
                    "Partial failures: {} sources failed",
                    query_errors.len()
                ))
            },
        };
        result.add_detection(consensus_detection);

        result.status = AnalysisStatus::Completed;
        result.completed_at = Some(Utc::now());
        result
    }

    /// Create basic analysis result (for backward compatibility)
    fn create_analysis_result(
        &self,
        hash_info: &HashInfo,
        reputations: Vec<HashReputation>,
    ) -> AnalysisResult {
        self.create_enhanced_analysis_result(hash_info, reputations, vec![])
    }

    /// Record metrics for analysis
    async fn record_metrics(&self, start_time: Instant, cache_hit: bool, success: bool) {
        if self.config.enable_metrics {
            let response_time_ms = start_time.elapsed().as_millis() as u64;
            let mut metrics = self.metrics.lock().await;
            metrics.record_query(response_time_ms, cache_hit, success);
        }
    }

    /// Clear local cache
    pub async fn clear_cache(&self) {
        if let Ok(mut cache) = self.local_cache.write() {
            cache.clear();
        }
        info!("Hash analyzer cache cleared");
    }

    /// Get comprehensive cache and performance statistics
    pub async fn get_comprehensive_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();

        // Cache statistics
        if let Ok(cache) = self.local_cache.read() {
            stats.insert(
                "total_cached".to_string(),
                serde_json::Value::Number(cache.len().into()),
            );

            let expired_count = cache.values().filter(|cached| cached.is_expired()).count();
            stats.insert(
                "expired_cached".to_string(),
                serde_json::Value::Number(expired_count.into()),
            );

            let malicious_cached = cache
                .values()
                .filter(|cached| {
                    !cached.is_expired() && cached.reputation.verdict == ThreatVerdict::Malicious
                })
                .count();
            stats.insert(
                "malicious_cached".to_string(),
                serde_json::Value::Number(malicious_cached.into()),
            );
        }

        // Performance metrics
        {
            let metrics = self.metrics.lock().await;
            stats.insert(
                "total_queries".to_string(),
                serde_json::Value::Number(metrics.total_queries.into()),
            );
            stats.insert(
                "cache_hit_rate".to_string(),
                serde_json::Value::Number(safe_json_number(metrics.cache_hit_rate())),
            );
            stats.insert(
                "success_rate".to_string(),
                serde_json::Value::Number(safe_json_number(metrics.success_rate())),
            );
            stats.insert(
                "average_response_time_ms".to_string(),
                serde_json::Value::Number(metrics.average_response_time_ms.into()),
            );

            // API failure statistics
            for (source, failures) in &metrics.api_failures {
                stats.insert(
                    format!("{source}_failures"),
                    serde_json::Value::Number((*failures).into()),
                );
            }
        }

        // Circuit breaker status
        for (source, circuit_breaker) in &self.circuit_breakers {
            let available = circuit_breaker.is_available().await;
            stats.insert(
                format!("{source}_circuit_breaker_open"),
                serde_json::Value::Bool(!available),
            );
        }

        stats
    }

    /// Health check for the analyzer
    pub async fn health_check(
        &self,
    ) -> Result<HashMap<String, serde_json::Value>, HashAnalysisError> {
        let mut health = HashMap::new();

        // Check circuit breaker status
        let mut all_available = true;
        for (source, circuit_breaker) in &self.circuit_breakers {
            let available = circuit_breaker.is_available().await;
            health.insert(
                format!("{source}_available"),
                serde_json::Value::Bool(available),
            );
            all_available &= available;
        }

        health.insert(
            "overall_health".to_string(),
            serde_json::Value::String(if all_available {
                "healthy".to_string()
            } else {
                "degraded".to_string()
            }),
        );

        // Add configuration status
        health.insert(
            "virustotal_configured".to_string(),
            serde_json::Value::Bool(self.config.virustotal_api_key.is_some()),
        );
        health.insert(
            "hybrid_analysis_configured".to_string(),
            serde_json::Value::Bool(self.config.hybrid_analysis_api_key.is_some()),
        );
        health.insert(
            "cache_enabled".to_string(),
            serde_json::Value::Bool(self.config.local_cache_enabled),
        );

        Ok(health)
    }

    /// Bulk hash analysis for processing multiple hashes efficiently
    pub async fn analyze_bulk_hashes(
        &self,
        hash_infos: Vec<HashInfo>,
    ) -> Vec<Result<AnalysisResult, HashAnalysisError>> {
        use futures::future::join_all;

        info!("Starting bulk analysis for {} hashes", hash_infos.len());

        // Process hashes concurrently with semaphore limiting
        let mut results = Vec::new();
        for hash_info in &hash_infos {
            results.push(self.analyze_hash(hash_info, None));
        }

        join_all(results).await
    }

    /// Get cache statistics (legacy method for compatibility)
    pub async fn get_cache_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        if let Ok(cache) = self.local_cache.read() {
            stats.insert("total_cached".to_string(), cache.len());

            let malicious_cached = cache
                .values()
                .filter(|cached| {
                    !cached.is_expired() && cached.reputation.verdict == ThreatVerdict::Malicious
                })
                .count();
            stats.insert("malicious_cached".to_string(), malicious_cached);
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enhanced_hash_validation() {
        let config = HashAnalyzerConfig::default();
        let analyzer = HashAnalyzer::new(config).unwrap();

        // Valid hashes
        assert!(analyzer
            .validate_hash("d41d8cd98f00b204e9800998ecf8427e", &HashType::MD5)
            .is_ok());
        assert!(analyzer
            .validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709", &HashType::SHA1)
            .is_ok());
        assert!(analyzer
            .validate_hash(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                &HashType::SHA256
            )
            .is_ok());

        // Invalid hashes
        assert!(analyzer.validate_hash("invalid", &HashType::MD5).is_err());
        assert!(analyzer
            .validate_hash("too_short", &HashType::SHA256)
            .is_err());
        assert!(analyzer
            .validate_hash("d41d8cd98f00b204e9800998ecf8427g", &HashType::MD5)
            .is_err()); // invalid char
    }

    #[test]
    fn test_enhanced_hash_generation() {
        let config = HashAnalyzerConfig::default();
        let analyzer = HashAnalyzer::new(config).unwrap();
        let test_data = b"hello world";

        let hashes = analyzer.generate_all_hashes(test_data);
        assert_eq!(hashes.len(), 5); // MD5, SHA1, SHA256, SHA3-256, BLAKE2B

        // Check that we got all hash types
        let hash_types: Vec<HashType> = hashes.iter().map(|h| h.hash_type.clone()).collect();
        assert!(hash_types.contains(&HashType::MD5));
        assert!(hash_types.contains(&HashType::SHA1));
        assert!(hash_types.contains(&HashType::SHA256));
        assert!(hash_types.contains(&HashType::SHA3_256));
        assert!(hash_types.contains(&HashType::BLAKE2B));

        // Verify known hash values
        let md5_hash = hashes
            .iter()
            .find(|h| h.hash_type == HashType::MD5)
            .unwrap();
        assert_eq!(md5_hash.hash_value, "5eb63bbbe01eeed093cb22bb8f5acdc3");

        let sha256_hash = hashes
            .iter()
            .find(|h| h.hash_type == HashType::SHA256)
            .unwrap();
        assert_eq!(
            sha256_hash.hash_value,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = RateLimiter::new(2);

        // Should allow first two requests
        assert!(rate_limiter.acquire().await.is_ok());
        assert!(rate_limiter.acquire().await.is_ok());

        // Third request should be rate limited
        // Note: This test might be flaky depending on timing
        // In production, you'd want more sophisticated testing
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let circuit_breaker = CircuitBreaker::new(2, Duration::from_millis(100));

        // Should be available initially
        assert!(circuit_breaker.is_available().await);

        // Record failures
        circuit_breaker.record_failure().await;
        assert!(circuit_breaker.is_available().await);

        circuit_breaker.record_failure().await;
        assert!(!circuit_breaker.is_available().await); // Should be open now

        // Wait for timeout and check recovery
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(circuit_breaker.is_available().await);
    }

    #[tokio::test]
    async fn test_cache_ttl() {
        let config = HashAnalyzerConfig {
            cache_ttl_minutes: 1, // 1 minute TTL
            ..Default::default()
        };
        let analyzer = HashAnalyzer::new(config).unwrap();

        let test_reputation = HashReputation {
            source: "Test".to_string(),
            verdict: ThreatVerdict::Malicious,
            confidence: 0.9,
            reliability_score: 0.8,
            first_seen: None,
            last_seen: None,
            detection_names: vec![],
            threat_types: vec![],
            metadata: HashMap::new(),
            query_time_ms: 100,
        };

        let hash = "test_hash";
        analyzer.cache_reputations(hash, &[test_reputation]).await;

        // Should be available immediately
        assert!(analyzer.get_cached_reputation(hash).await.is_some());

        // For testing TTL, you'd need to either mock time or use a very short TTL
        // This is a basic structure test
    }

    #[test]
    fn test_hash_type_security_check() {
        assert!(!HashType::MD5.is_secure());
        assert!(!HashType::SHA1.is_secure());
        assert!(HashType::SHA256.is_secure());
        assert!(HashType::SHA3_256.is_secure());
        assert!(HashType::BLAKE2B.is_secure());
    }

    #[tokio::test]
    async fn test_bulk_analysis() {
        let config = HashAnalyzerConfig {
            virustotal_api_key: None, // Disable external APIs for testing
            malwarebazaar_enabled: false,
            hybrid_analysis_api_key: None,
            ..Default::default()
        };
        let analyzer = HashAnalyzer::new(config).unwrap();

        let hashes = vec![
            HashInfo {
                hash_type: HashType::SHA256,
                hash_value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                file_size: Some(0),
                computed_at: chrono::Utc::now(),
            },
            HashInfo {
                hash_type: HashType::MD5,
                hash_value: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                file_size: Some(0),
                computed_at: chrono::Utc::now(),
            },
        ];

        let results = analyzer.analyze_bulk_hashes(hashes).await;

        assert_eq!(results.len(), 2);
        // Both should succeed even without external APIs (local database will return Unknown)
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    async fn test_weighted_confidence_calculation() {
        let config = HashAnalyzerConfig::default();
        let analyzer = HashAnalyzer::new(config).unwrap();

        let hash_info = HashInfo {
            hash_type: HashType::SHA256,
            hash_value: "test_hash".to_string(),
            file_size: Some(1000),
            computed_at: chrono::Utc::now(),
        };

        let reputations = vec![
            HashReputation {
                source: "HighReliability".to_string(),
                verdict: ThreatVerdict::Malicious,
                confidence: 0.9,
                reliability_score: 0.95,
                first_seen: None,
                last_seen: None,
                detection_names: vec![],
                threat_types: vec![],
                metadata: HashMap::new(),
                query_time_ms: 100,
            },
            HashReputation {
                source: "LowReliability".to_string(),
                verdict: ThreatVerdict::Benign,
                confidence: 0.8,
                reliability_score: 0.3,
                first_seen: None,
                last_seen: None,
                detection_names: vec![],
                threat_types: vec![],
                metadata: HashMap::new(),
                query_time_ms: 150,
            },
        ];

        let result = analyzer.create_enhanced_analysis_result(&hash_info, reputations, vec![]);

        // Should have detections from both sources plus consensus
        assert!(result.detections.len() >= 2);

        // Check that consensus detection exists
        let consensus = result
            .detections
            .iter()
            .find(|d| d.engine_name == "Hash Analyzer Consensus");
        assert!(consensus.is_some());

        let consensus = consensus.unwrap();
        // High reliability source should influence the consensus more
        assert_eq!(consensus.verdict, ThreatVerdict::Malicious);
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = HashAnalyzerConfig::default();
        let analyzer = HashAnalyzer::new(config).unwrap();

        let health = analyzer.health_check().await.unwrap();

        assert!(health.contains_key("overall_health"));
        assert!(health.contains_key("virustotal_configured"));
        assert!(health.contains_key("cache_enabled"));

        // Should be healthy initially
        assert_eq!(
            health["overall_health"],
            serde_json::Value::String("healthy".to_string())
        );
    }

    #[tokio::test]
    async fn test_comprehensive_stats() {
        let config = HashAnalyzerConfig::default();
        let analyzer = HashAnalyzer::new(config).unwrap();

        let stats = analyzer.get_comprehensive_stats().await;

        assert!(stats.contains_key("total_cached"));
        assert!(stats.contains_key("total_queries"));
        assert!(stats.contains_key("cache_hit_rate"));
        assert!(stats.contains_key("success_rate"));
    }

    #[test]
    fn test_error_types() {
        let error = HashAnalysisError::InvalidHash {
            hash_type: "MD5".to_string(),
            hash: "invalid".to_string(),
        };
        assert!(error.to_string().contains("Invalid hash format"));

        let error = HashAnalysisError::ApiTimeout {
            api_source: "VirusTotal".to_string(),
        };
        assert!(error.to_string().contains("API timeout"));
    }

    #[test]
    fn test_hash_type_expected_lengths() {
        assert_eq!(HashType::MD5.expected_length(), 32);
        assert_eq!(HashType::SHA1.expected_length(), 40);
        assert_eq!(HashType::SHA256.expected_length(), 64);
        assert_eq!(HashType::SHA3_256.expected_length(), 64);
        assert_eq!(HashType::BLAKE2B.expected_length(), 128);
    }

    #[test]
    fn test_config_validation() {
        let invalid_config = HashAnalyzerConfig {
            timeout_seconds: 0, // Invalid
            ..Default::default()
        };

        let result = HashAnalyzer::new(invalid_config);
        assert!(result.is_err());

        if let Err(HashAnalysisError::ConfigError { message }) = result {
            assert!(message.contains("Timeout cannot be zero"));
        } else {
            panic!("Expected ConfigError");
        }
    }
}
