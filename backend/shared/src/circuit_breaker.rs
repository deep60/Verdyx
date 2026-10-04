//! Circuit breaker middleware for downstream service calls
//!
//! Implements the circuit breaker pattern to prevent cascading failures
//! when downstream services are unhealthy.

#[cfg(feature = "circuit-breaker")]
use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
#[cfg(feature = "circuit-breaker")]
use std::sync::Arc;
#[cfg(feature = "circuit-breaker")]
use std::time::{Duration, Instant};
#[cfg(feature = "circuit-breaker")]
use tokio::sync::{RwLock, Semaphore};

use crate::{AppError, AppResult};

/// Circuit breaker states
#[cfg(feature = "circuit-breaker")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum CircuitState {
    #[default]
    Closed,   // Normal operation, requests pass through
    Open,     // Failing, requests blocked
    HalfOpen, // Testing recovery, limited requests allowed
}

/// Circuit breaker configuration
#[cfg(feature = "circuit-breaker")]
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Number of successes in half-open before closing
    pub success_threshold: u32,
    /// Time to wait before transitioning to half-open
    pub timeout: Duration,
    /// Maximum concurrent requests in half-open state
    pub half_open_max_requests: u32,
    /// Minimum requests before evaluating failure rate
    pub minimum_requests: u32,
    /// Failure rate threshold (0.0 to 1.0)
    pub failure_rate_threshold: f64,
}

#[cfg(feature = "circuit-breaker")]
impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(30),
            half_open_max_requests: 3,
            minimum_requests: 10,
            failure_rate_threshold: 0.5,
        }
    }
}

/// Circuit breaker statistics
#[cfg(feature = "circuit-breaker")]
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct CircuitStats {
    pub state: CircuitState,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub rejected_requests: u64,
    pub last_failure: Option<String>,
    pub last_state_change: Option<String>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

/// Circuit breaker for a single downstream service
#[cfg(feature = "circuit-breaker")]
#[derive(Debug)]
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    stats: RwLock<CircuitStats>,
    last_state_change: RwLock<Instant>,
    half_open_semaphore: Arc<Semaphore>,
}

#[cfg(feature = "circuit-breaker")]
impl CircuitBreaker {
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            state: RwLock::new(CircuitState::Closed),
            stats: RwLock::new(CircuitStats {
                state: CircuitState::Closed,
                ..Default::default()
            }),
            last_state_change: RwLock::new(Instant::now()),
            half_open_semaphore: Arc::new(Semaphore::new(1)), // Updated dynamically
        }
    }
    
    /// Get current state
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }
    
    /// Get current stats
    pub async fn stats(&self) -> CircuitStats {
        let mut stats = self.stats.read().await.clone();
        stats.state = *self.state.read().await;
        stats
    }
    
    /// Record a successful call
    pub async fn record_success(&self) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.successful_requests += 1;
        stats.consecutive_failures = 0;
        stats.consecutive_successes += 1;
        
        let state = *self.state.read().await;
        if state == CircuitState::HalfOpen && stats.consecutive_successes >= self.config.success_threshold {
            self.transition_to_closed(stats).await;
        }
    }
    
    /// Record a failed call
    pub async fn record_failure(&self, error: Option<String>) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.failed_requests += 1;
        stats.consecutive_successes = 0;
        stats.consecutive_failures += 1;
        
        if let Some(err) = error {
            stats.last_failure = Some(err);
        }
        
        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => {
                // Check if we should open
                if stats.total_requests >= self.config.minimum_requests as u64 {
                    let failure_rate = stats.failed_requests as f64 / stats.total_requests as f64;
                    if failure_rate >= self.config.failure_rate_threshold
                        || stats.consecutive_failures >= self.config.failure_threshold {
                        self.transition_to_open(stats).await;
                    }
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                self.transition_to_open(stats).await;
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }
    
    /// Check if request should be allowed
    pub async fn allow_request(&self) -> bool {
        let state = *self.state.read().await;
        
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has passed to transition to half-open
                let last_change = *self.last_state_change.read().await;
                if last_change.elapsed() >= self.config.timeout {
                    // Transition to half-open
                    self.transition_to_half_open().await;
                    true
                } else {
                    // Reject request
                    let mut stats = self.stats.write().await;
                    stats.rejected_requests += 1;
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests
                let permit = self.half_open_semaphore.clone().try_acquire_owned();
                permit.is_ok()
            }
        }
    }
    
    /// Execute a call with circuit breaker protection
    pub async fn call<F, Fut, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = AppResult<T>>,
    {
        if !self.allow_request().await {
            return Err(AppError::CircuitOpen {
                service: self.name.clone(),
            });
        }
        
        let result = f().await;
        
        match &result {
            Ok(_) => self.record_success().await,
            Err(e) => {
                let is_retriable = matches!(
                    e,
                    AppError::Timeout(_) |
                    AppError::ServiceUnavailable(_) |
                    AppError::Upstream { .. } |
                    AppError::UpstreamTimeout
                );
                if is_retriable {
                    self.record_failure(Some(e.to_string())).await;
                }
            }
        }
        
        result
    }
    
    async fn transition_to_open(&self, mut stats: tokio::sync::RwLockWriteGuard<'_, CircuitStats>) {
        *self.state.write().await = CircuitState::Open;
        *self.last_state_change.write().await = Instant::now();
        stats.state = CircuitState::Open;
        stats.last_state_change = Some(chrono::Utc::now().to_rfc3339());
        tracing::warn!(service = %self.name, "Circuit breaker OPENED");
    }
    
    async fn transition_to_half_open(&self) {
        *self.state.write().await = CircuitState::HalfOpen;
        *self.last_state_change.write().await = Instant::now();
        
        // Update semaphore for half-open max requests
        let new_semaphore = Arc::new(Semaphore::new(self.config.half_open_max_requests as usize));
        self.half_open_semaphore = new_semaphore;
        
        let mut stats = self.stats.write().await;
        stats.state = CircuitState::HalfOpen;
        stats.last_state_change = Some(chrono::Utc::now().to_rfc3339());
        stats.consecutive_successes = 0;
        
        tracing::info!(service = %self.name, "Circuit breaker HALF-OPEN");
    }
    
    async fn transition_to_closed(&self, mut stats: tokio::sync::RwLockWriteGuard<'_, CircuitStats>) {
        *self.state.write().await = CircuitState::Closed;
        *self.last_state_change.write().await = Instant::now();
        stats.state = CircuitState::Closed;
        stats.last_state_change = Some(chrono::Utc::now().to_rfc3339());
        stats.consecutive_failures = 0;
        stats.consecutive_successes = 0;
        
        tracing::info!(service = %self.name, "Circuit breaker CLOSED");
    }
    
    /// Force reset the circuit breaker (admin operation)
    pub async fn reset(&self) {
        *self.state.write().await = CircuitState::Closed;
        *self.last_state_change.write().await = Instant::now();
        let mut stats = self.stats.write().await;
        *stats = CircuitStats::default();
        tracing::info!(service = %self.name, "Circuit breaker RESET");
    }
}

/// Registry for multiple circuit breakers
#[cfg(feature = "circuit-breaker")]
#[derive(Debug, Default)]
pub struct CircuitBreakerRegistry {
    breakers: Arc<DashMap<String, Arc<CircuitBreaker>>>,
}

#[cfg(feature = "circuit-breaker")]
impl CircuitBreakerRegistry {
    pub fn new() -> Self {
        Self {
            breakers: Arc::new(DashMap::new()),
        }
    }
    
    pub fn get_or_create(&self, name: &str, config: CircuitBreakerConfig) -> Arc<CircuitBreaker> {
        self.breakers
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(CircuitBreaker::new(name, config)))
            .clone()
    }
    
    pub fn get(&self, name: &str) -> Option<Arc<CircuitBreaker>> {
        self.breakers.get(name).map(|v| v.clone())
    }
    
    pub fn remove(&self, name: &str) -> bool {
        self.breakers.remove(name).is_some()
    }
    
    pub async fn all_stats(&self) -> Vec<(String, CircuitStats)> {
        let mut result = Vec::new();
        for entry in self.breakers.iter() {
            let stats = entry.value().stats().await;
            result.push((entry.key().clone(), stats));
        }
        result
    }
    
    pub async fn reset_all(&self) {
        for entry in self.breakers.iter() {
            entry.value().reset().await;
        }
    }
}

/// Middleware for circuit breaker on outbound requests
#[cfg(feature = "circuit-breaker")]
pub struct CircuitBreakerMiddleware {
    registry: Arc<CircuitBreakerRegistry>,
    service_name: String,
}

/// Simple circuit breaker middleware for axum
/// 
/// Usage:
/// ```rust
/// let breaker = registry.get_or_create("service-name", CircuitBreakerConfig::default());
/// let middleware = circuit_breaker_middleware(breaker);
/// router.layer(axum::middleware::from_fn(middleware));
/// ```
#[cfg(feature = "circuit-breaker")]
pub fn circuit_breaker_middleware(
    breaker: Arc<CircuitBreaker>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> + Clone + Send + 'static {
    move |request: Request, next: Next| {
        let breaker = breaker.clone();
        Box::pin(async move {
            // Check circuit breaker
            if !breaker.allow_request().await {
                let err = AppError::CircuitOpen {
                    service: breaker.name.clone(),
                };
                return err.to_api_error(None).into_response();
            }
            
            // Call downstream
            let response = next.run(request).await;
            
            let status = response.status().as_u16();
            if status >= 500 {
                breaker.record_failure(Some(format!("HTTP {}", status))).await;
            } else {
                breaker.record_success().await;
            }
            
            response
        })
    }
}

#[cfg(test)]
#[cfg(feature = "circuit-breaker")]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            minimum_requests: 3,
            failure_rate_threshold: 0.5,
            ..Default::default()
        };
        
        let breaker = CircuitBreaker::new("test-service", config);
        
        // Record failures
        breaker.record_failure(Some("error 1".into())).await;
        breaker.record_failure(Some("error 2".into())).await;
        breaker.record_failure(Some("error 3".into())).await;
        
        // Should be open now
        assert_eq!(breaker.state().await, CircuitState::Open);
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_half_open_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            minimum_requests: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            half_open_max_requests: 3,
            ..Default::default()
        };
        
        let breaker = CircuitBreaker::new("test-service", config);
        
        // Trigger open
        breaker.record_failure(None).await;
        breaker.record_failure(None).await;
        assert_eq!(breaker.state().await, CircuitState::Open);
        
        // Wait for timeout
        sleep(Duration::from_millis(150)).await;
        
        // Should be half-open now
        assert!(breaker.allow_request().await);
        assert_eq!(breaker.state().await, CircuitState::HalfOpen);
        
        // Record successes
        breaker.record_success().await;
        breaker.record_success().await;
        
        // Should be closed now
        assert_eq!(breaker.state().await, CircuitState::Closed);
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_registry() {
        let registry = CircuitBreakerRegistry::new();
        let config = CircuitBreakerConfig::default();
        
        let breaker1 = registry.get_or_create("service-a", config.clone());
        let breaker2 = registry.get_or_create("service-b", config.clone());
        let breaker1_again = registry.get("service-a").unwrap();
        
        assert!(Arc::ptr_eq(&breaker1, &breaker1_again));
        assert!(!Arc::ptr_eq(&breaker1, &breaker2));
    }
}