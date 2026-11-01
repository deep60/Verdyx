// Axum middleware returns `Response` as its error type, which is large by design.
#![allow(clippy::result_large_err)]

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_duration: Duration,
    pub burst_size: Option<u32>,
}

impl RateLimitConfig {
    /// Default: 100 requests per minute
    pub fn default() -> Self {
        Self {
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            burst_size: Some(20),
        }
    }

    /// Strict: 10 requests per minute
    pub fn strict() -> Self {
        Self {
            requests_per_window: 10,
            window_duration: Duration::from_secs(60),
            burst_size: Some(5),
        }
    }

    /// Relaxed: 1000 requests per minute
    pub fn relaxed() -> Self {
        Self {
            requests_per_window: 1000,
            window_duration: Duration::from_secs(60),
            burst_size: Some(200),
        }
    }

    /// Authentication endpoints: 5 requests per 15 minutes
    pub fn auth() -> Self {
        Self {
            requests_per_window: 5,
            window_duration: Duration::from_secs(900), // 15 minutes
            burst_size: None,
        }
    }

    /// API endpoints: 1000 requests per hour
    pub fn api() -> Self {
        Self {
            requests_per_window: 1000,
            window_duration: Duration::from_secs(3600), // 1 hour
            burst_size: Some(100),
        }
    }
}

/// Rate limiter state
#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
    last_request: Instant,
}

impl RateLimitEntry {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            count: 0,
            window_start: now,
            last_request: now,
        }
    }

    fn should_reset(&self, window_duration: Duration) -> bool {
        self.window_start.elapsed() >= window_duration
    }

    fn reset(&mut self) {
        let now = Instant::now();
        self.count = 0;
        self.window_start = now;
        self.last_request = now;
    }
}

/// Rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiter {
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if request is allowed
    pub async fn check_rate_limit(&self, identifier: &str) -> RateLimitResult {
        let mut entries = self.entries.write().await;
        let entry = entries
            .entry(identifier.to_string())
            .or_insert_with(RateLimitEntry::new);

        // Reset window if expired
        if entry.should_reset(self.config.window_duration) {
            entry.reset();
        }

        // Check if limit exceeded
        if entry.count >= self.config.requests_per_window {
            let retry_after = self
                .config
                .window_duration
                .checked_sub(entry.window_start.elapsed())
                .unwrap_or(Duration::from_secs(0));

            return RateLimitResult::Limited {
                retry_after_secs: retry_after.as_secs(),
                limit: self.config.requests_per_window,
                remaining: 0,
                reset_at: entry.window_start + self.config.window_duration,
            };
        }

        // Increment counter
        entry.count += 1;
        entry.last_request = Instant::now();

        let remaining = self.config.requests_per_window.saturating_sub(entry.count);

        RateLimitResult::Allowed {
            limit: self.config.requests_per_window,
            remaining,
            reset_at: entry.window_start + self.config.window_duration,
        }
    }

    /// Clean up old entries (call periodically)
    pub async fn cleanup_old_entries(&self) {
        let mut entries = self.entries.write().await;
        let threshold = self.config.window_duration * 2;

        entries.retain(|_, entry| entry.last_request.elapsed() < threshold);
    }
}

/// Rate limit check result
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed {
        limit: u32,
        remaining: u32,
        reset_at: Instant,
    },
    Limited {
        retry_after_secs: u64,
        limit: u32,
        remaining: u32,
        reset_at: Instant,
    },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }

    pub fn headers(&self) -> Vec<(String, String)> {
        match self {
            RateLimitResult::Allowed {
                limit,
                remaining,
                reset_at,
            } => {
                vec![
                    ("X-RateLimit-Limit".to_string(), limit.to_string()),
                    ("X-RateLimit-Remaining".to_string(), remaining.to_string()),
                    (
                        "X-RateLimit-Reset".to_string(),
                        format!("{}", reset_at.elapsed().as_secs()),
                    ),
                ]
            }
            RateLimitResult::Limited {
                retry_after_secs,
                limit,
                remaining,
                ..
            } => {
                vec![
                    ("X-RateLimit-Limit".to_string(), limit.to_string()),
                    ("X-RateLimit-Remaining".to_string(), remaining.to_string()),
                    ("Retry-After".to_string(), retry_after_secs.to_string()),
                ]
            }
        }
    }
}

/// Rate limit error response
#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitError {
    pub error: String,
    pub message: String,
    pub retry_after_seconds: u64,
    pub limit: u32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

const EDGE_SECRET_HEADER: &str = "x-verdyx-edge-secret";
const EDGE_CLIENT_IP_HEADER: &str = "x-verdyx-client-ip";

/// Limit for unauthenticated auth endpoints, shared across `/api` and `/api/v1`.
#[derive(Debug)]
pub struct AuthRateLimit {
    limiter: RateLimiter,
    /// Shared with the Cloudflare Pages proxy, which is the only caller allowed
    /// to state the browser's IP.
    edge_secret: Option<String>,
    /// True only where Caddy is the sole route to the gateway, so it alone can
    /// set `X-Real-IP`. Otherwise a client could send a new value per request.
    trust_real_ip: bool,
}

impl AuthRateLimit {
    pub fn new(requests_per_15_min: u32, edge_secret: Option<String>, trust_real_ip: bool) -> Self {
        Self {
            limiter: RateLimiter::new(RateLimitConfig {
                requests_per_window: requests_per_15_min,
                window_duration: Duration::from_secs(15 * 60),
                burst_size: None,
            }),
            edge_secret: edge_secret.filter(|s| !s.is_empty()),
            trust_real_ip,
        }
    }

    pub fn from_env() -> Self {
        let limit = std::env::var("AUTH_RATE_LIMIT_PER_15_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let trust_real_ip = std::env::var("TRUST_PROXY_HEADERS").as_deref() == Ok("true");
        Self::new(
            limit,
            std::env::var("EDGE_PROXY_SECRET").ok(),
            trust_real_ip,
        )
    }

    pub async fn cleanup(&self) {
        self.limiter.cleanup_old_entries().await;
    }

    fn client_ip(&self, headers: &HeaderMap, peer: Option<IpAddr>) -> String {
        let parsed_header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
        };

        if let (Some(secret), Some(sent)) = (
            self.edge_secret.as_deref(),
            headers
                .get(EDGE_SECRET_HEADER)
                .and_then(|v| v.to_str().ok()),
        ) {
            if constant_time_eq(secret.as_bytes(), sent.as_bytes()) {
                if let Some(ip) = parsed_header(EDGE_CLIENT_IP_HEADER) {
                    return ip.to_string();
                }
            }
        }

        if self.trust_real_ip {
            if let Some(ip) = parsed_header("x-real-ip") {
                return ip.to_string();
            }
        }

        peer.map_or_else(|| "unknown".to_string(), |ip| ip.to_string())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Per-client limit on login, registration and password reset requests.
pub async fn auth_rate_limit_middleware(
    State(state): State<crate::AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let ip = state.auth_rate_limit.client_ip(request.headers(), peer);

    match state.auth_rate_limit.limiter.check_rate_limit(&ip).await {
        RateLimitResult::Allowed { .. } => Ok(next.run(request).await),
        RateLimitResult::Limited {
            retry_after_secs,
            limit,
            ..
        } => {
            let body = RateLimitError {
                error: "RATE_LIMIT_EXCEEDED".to_string(),
                message: "Too many attempts. Please wait a few minutes and try again.".to_string(),
                retry_after_seconds: retry_after_secs,
                limit,
                timestamp: Utc::now(),
            };
            let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            if let Ok(value) = retry_after_secs.to_string().parse() {
                response.headers_mut().insert("Retry-After", value);
            }
            Err(response)
        }
    }
}

/// IP-based rate limiting middleware
pub async fn ip_rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let ip = addr.ip().to_string();

    match limiter.check_rate_limit(&ip).await {
        RateLimitResult::Allowed {
            limit, remaining, ..
        } => {
            let mut response = next.run(request).await;

            // Add rate limit headers to successful responses
            if let Ok(limit_value) = limit.to_string().parse() {
                response
                    .headers_mut()
                    .insert("X-RateLimit-Limit", limit_value);
            }
            if let Ok(remaining_value) = remaining.to_string().parse() {
                response
                    .headers_mut()
                    .insert("X-RateLimit-Remaining", remaining_value);
            }

            Ok(response)
        }
        RateLimitResult::Limited {
            retry_after_secs,
            limit,
            ..
        } => {
            let error_response = RateLimitError {
                error: "RATE_LIMIT_EXCEEDED".to_string(),
                message: format!("Rate limit of {limit} requests exceeded"),
                retry_after_seconds: retry_after_secs,
                limit,
                timestamp: Utc::now(),
            };

            let mut response =
                (StatusCode::TOO_MANY_REQUESTS, Json(error_response)).into_response();

            // Add retry-after header
            if let Ok(value) = retry_after_secs.to_string().parse() {
                response.headers_mut().insert("Retry-After", value);
            }

            Err(response)
        }
    }
}

/// User-based rate limiting middleware (requires authentication)
pub async fn user_rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract user ID from request extensions (set by auth middleware)
    let user_id = request
        .extensions()
        .get::<crate::middleware::auth::Claims>()
        .map(|claims| claims.sub.to_string())
        .unwrap_or_else(|| "anonymous".to_string());

    match limiter.check_rate_limit(&user_id).await {
        RateLimitResult::Allowed {
            limit, remaining, ..
        } => {
            let mut response = next.run(request).await;

            // Add rate limit headers
            if let Ok(limit_value) = limit.to_string().parse() {
                response
                    .headers_mut()
                    .insert("X-RateLimit-Limit", limit_value);
            }
            if let Ok(remaining_value) = remaining.to_string().parse() {
                response
                    .headers_mut()
                    .insert("X-RateLimit-Remaining", remaining_value);
            }

            Ok(response)
        }
        RateLimitResult::Limited {
            retry_after_secs,
            limit,
            ..
        } => {
            let error_response = RateLimitError {
                error: "RATE_LIMIT_EXCEEDED".to_string(),
                message: format!("User rate limit of {limit} requests exceeded"),
                retry_after_seconds: retry_after_secs,
                limit,
                timestamp: Utc::now(),
            };

            let mut response =
                (StatusCode::TOO_MANY_REQUESTS, Json(error_response)).into_response();

            if let Ok(value) = retry_after_secs.to_string().parse() {
                response.headers_mut().insert("Retry-After", value);
            }

            Err(response)
        }
    }
}

/// API key-based rate limiting
pub async fn api_key_rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract API key from header
    let api_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous");

    match limiter.check_rate_limit(api_key).await {
        RateLimitResult::Allowed { .. } => Ok(next.run(request).await),
        RateLimitResult::Limited {
            retry_after_secs,
            limit,
            ..
        } => {
            let error_response = RateLimitError {
                error: "RATE_LIMIT_EXCEEDED".to_string(),
                message: format!("API key rate limit of {limit} requests exceeded"),
                retry_after_seconds: retry_after_secs,
                limit,
                timestamp: Utc::now(),
            };

            Err((StatusCode::TOO_MANY_REQUESTS, Json(error_response)).into_response())
        }
    }
}

/// Adaptive rate limiter that adjusts based on server load
#[derive(Debug, Clone)]
pub struct AdaptiveRateLimiter {
    base_limiter: RateLimiter,
    current_multiplier: Arc<RwLock<f64>>,
}

impl AdaptiveRateLimiter {
    pub fn new(base_config: RateLimitConfig) -> Self {
        Self {
            base_limiter: RateLimiter::new(base_config),
            current_multiplier: Arc::new(RwLock::new(1.0)),
        }
    }

    /// Adjust rate limit based on server load (0.5 = stricter, 2.0 = more lenient)
    pub async fn adjust_for_load(&self, load_percentage: f64) {
        let mut multiplier = self.current_multiplier.write().await;

        *multiplier = if load_percentage > 90.0 {
            0.5 // Reduce to 50% capacity under high load
        } else if load_percentage > 75.0 {
            0.75 // Reduce to 75% capacity
        } else if load_percentage < 25.0 {
            1.5 // Increase to 150% capacity under low load
        } else {
            1.0 // Normal capacity
        };
    }

    pub async fn check_rate_limit(&self, identifier: &str) -> RateLimitResult {
        // Use base limiter with adjusted multiplier
        self.base_limiter.check_rate_limit(identifier).await
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    fn peer() -> Option<IpAddr> {
        Some("10.0.0.9".parse().unwrap())
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn spoofed_ip_headers_are_ignored_by_default() {
        let limit = AuthRateLimit::new(5, None, false);
        let sent = headers(&[
            ("x-real-ip", "1.1.1.1"),
            ("x-verdyx-client-ip", "2.2.2.2"),
            ("x-verdyx-edge-secret", "guess"),
        ]);
        assert_eq!(limit.client_ip(&sent, peer()), "10.0.0.9");
    }

    #[test]
    fn edge_ip_requires_the_exact_secret() {
        let limit = AuthRateLimit::new(5, Some("correct".to_string()), false);
        let wrong = headers(&[
            ("x-verdyx-client-ip", "2.2.2.2"),
            ("x-verdyx-edge-secret", "wrong"),
        ]);
        assert_eq!(limit.client_ip(&wrong, peer()), "10.0.0.9");

        let right = headers(&[
            ("x-verdyx-client-ip", "2.2.2.2"),
            ("x-verdyx-edge-secret", "correct"),
        ]);
        assert_eq!(limit.client_ip(&right, peer()), "2.2.2.2");
    }

    #[test]
    fn empty_edge_secret_is_treated_as_unset() {
        let limit = AuthRateLimit::new(5, Some(String::new()), false);
        let sent = headers(&[
            ("x-verdyx-client-ip", "2.2.2.2"),
            ("x-verdyx-edge-secret", ""),
        ]);
        assert_eq!(limit.client_ip(&sent, peer()), "10.0.0.9");
    }

    #[test]
    fn real_ip_is_used_only_behind_a_trusted_proxy() {
        let limit = AuthRateLimit::new(5, None, true);
        assert_eq!(
            limit.client_ip(&headers(&[("x-real-ip", "3.3.3.3")]), peer()),
            "3.3.3.3"
        );
        assert_eq!(
            limit.client_ip(&headers(&[("x-real-ip", "not-an-ip")]), peer()),
            "10.0.0.9"
        );
    }

    #[tokio::test]
    async fn limit_blocks_after_the_configured_attempts() {
        let limit = AuthRateLimit::new(2, None, false);
        assert!(limit.limiter.check_rate_limit("ip").await.is_allowed());
        assert!(limit.limiter.check_rate_limit("ip").await.is_allowed());
        assert!(!limit.limiter.check_rate_limit("ip").await.is_allowed());
        assert!(limit.limiter.check_rate_limit("other").await.is_allowed());
    }

    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_window: 5,
            window_duration: Duration::from_secs(60),
            burst_size: None,
        });

        for _ in 0..5 {
            let result = limiter.check_rate_limit("test_user").await;
            assert!(result.is_allowed());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_window: 3,
            window_duration: Duration::from_secs(60),
            burst_size: None,
        });

        for _ in 0..3 {
            limiter.check_rate_limit("test_user").await;
        }

        let result = limiter.check_rate_limit("test_user").await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_rate_limiter_resets_after_window() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_window: 2,
            window_duration: Duration::from_millis(100),
            burst_size: None,
        });

        limiter.check_rate_limit("test_user").await;
        limiter.check_rate_limit("test_user").await;

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        let result = limiter.check_rate_limit("test_user").await;
        assert!(result.is_allowed());
    }
}
