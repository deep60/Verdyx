//! Idempotency key support for safe retries
//!
//! Provides middleware and storage for idempotency keys to prevent
//! duplicate operations from retries.

#[cfg(feature = "idempotency")]
use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
#[cfg(feature = "idempotency")]
use dashmap::DashMap;
#[cfg(feature = "idempotency")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "idempotency")]
use std::sync::Arc;
#[cfg(feature = "idempotency")]
use std::time::{Duration, Instant};
#[cfg(feature = "idempotency")]
use uuid::Uuid;

use crate::{AppError, AppResult};

/// Idempotency key header name
#[cfg(feature = "idempotency")]
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// Default TTL for idempotency keys (24 hours)
#[cfg(feature = "idempotency")]
pub const DEFAULT_IDEMPOTENCY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum size of idempotency key value (1MB)
#[cfg(feature = "idempotency")]
pub const MAX_IDEMPOTENCY_VALUE_SIZE: usize = 1_048_576;

/// Stored idempotency record
/// Uses Vec<(String, String)> instead of HeaderMap for serialization
/// Uses u64 timestamps instead of Instant for serialization
#[cfg(feature = "idempotency")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub key: String,
    pub request_hash: String,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub created_at: u64, // Unix timestamp in milliseconds
    pub expires_at: u64, // Unix timestamp in milliseconds
}

#[cfg(feature = "idempotency")]
impl IdempotencyRecord {
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now >= self.expires_at
    }
    
    pub fn matches_request(&self, request_hash: &str) -> bool {
        self.request_hash == request_hash
    }
}

/// In-memory idempotency store (use Redis-backed for production clusters)
#[cfg(feature = "idempotency")]
#[derive(Debug, Clone)]
pub struct IdempotencyStore {
    inner: Arc<DashMap<String, IdempotencyRecord>>,
    ttl: Duration,
    max_size: usize,
}

#[cfg(feature = "idempotency")]
impl IdempotencyStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            ttl,
            max_size: 100_000,
        }
    }
    
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }
    
    /// Generate a hash of the request for comparison
    fn hash_request(method: &str, path: &str, body: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(b":");
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(body);
        format!("{:x}", hasher.finalize())
    }
    
    /// Check if key exists and matches request
    pub fn check(&self, key: &str, method: &str, path: &str, body: &[u8]) -> Option<IdempotencyRecord> {
        let request_hash = Self::hash_request(method, path, body);
        
        self.inner.get(key).and_then(|record| {
            if record.is_expired() {
                self.inner.remove(key);
                None
            } else if record.matches_request(&request_hash) {
                Some(record.clone())
            } else {
                // Key exists but different request - conflict
                None
            }
        })
    }
    
    /// Store a new idempotency record
    pub fn store(&self, key: String, record: IdempotencyRecord) -> Result<(), AppError> {
        if self.inner.len() >= self.max_size {
            // Clean up expired entries
            self.cleanup_expired();
            
            if self.inner.len() >= self.max_size {
                return Err(AppError::Internal(anyhow::anyhow!("Idempotency store full")));
            }
        }
        
        self.inner.insert(key, record);
        Ok(())
    }
    
    /// Remove expired entries
    fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.inner.retain(|_, v| v.expires_at > now);
    }
    
    /// Get store stats
    pub fn stats(&self) -> IdempotencyStats {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut expired = 0;
        let mut valid = 0;
        
        for entry in self.inner.iter() {
            if entry.value().expires_at <= now {
                expired += 1;
            } else {
                valid += 1;
            }
        }
        
        IdempotencyStats {
            total: self.inner.len(),
            valid,
            expired,
        }
    }
}

/// Idempotency store statistics
#[cfg(feature = "idempotency")]
#[derive(Debug, Serialize)]
pub struct IdempotencyStats {
    pub total: usize,
    pub valid: usize,
    pub expired: usize,
}

/// Idempotency middleware
#[cfg(feature = "idempotency")]
pub async fn idempotency_middleware(
    store: Arc<IdempotencyStore>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Only apply to mutating methods
    let method = request.method().clone();
    if !matches!(method, axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::PATCH | axum::http::Method::DELETE) {
        return Ok(next.run(request).await);
    }
    
    // Extract idempotency key
    let key = match request.headers().get(IDEMPOTENCY_KEY_HEADER) {
        Some(v) => match v.to_str() {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(next.run(request).await), // No key, skip
        },
        None => return Ok(next.run(request).await), // No key, skip
    };
    
    // Validate key format (UUID v4)
    if Uuid::parse_str(&key).is_err() {
        let err = AppError::Validation("Invalid Idempotency-Key format (must be UUID v4)".to_string());
        return Err(err.to_api_error(None).into_response());
    }
    
    // Read body for hashing
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_IDEMPOTENCY_VALUE_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            let err = AppError::Validation(format!("Failed to read request body: {}", e));
            return Err(err.to_api_error(None).into_response());
        }
    };
    
    let path = parts.uri.path().to_string();
    
    // Check existing record
    if let Some(record) = store.check(&key, method.as_str(), &path, &body_bytes) {
        // Return cached response
        let mut response = Response::builder()
            .status(StatusCode::from_u16(record.response_status).unwrap_or(StatusCode::OK))
            .body(Body::from(record.response_body))
            .unwrap();
        
        // Copy response headers (excluding hop-by-hop headers)
        for (name, value) in &record.response_headers {
            if !is_hop_by_hop_header(name) {
                if let (Ok(header_name), Ok(header_value)) = (
                    name.parse::<axum::http::HeaderName>(),
                    value.parse::<axum::http::HeaderValue>(),
                ) {
                    response.headers_mut().insert(header_name, header_value);
                }
            }
        }
        
        // Add idempotency replay header
        response.headers_mut().insert(
            "Idempotency-Replay",
            HeaderValue::from_static("true"),
        );
        
        return Ok(response);
    }
    
    // No existing record - proceed with request
    let request = Request::from_parts(parts, Body::from(body_bytes));
    let response = next.run(request).await;
    
    // Store response for future replays (only for successful responses)
    let status = response.status().as_u16();
    if status < 500 {
        let response_headers = response.headers().clone();
        let response_body = match axum::body::to_bytes(response.into_body(), MAX_IDEMPOTENCY_VALUE_SIZE).await {
            Ok(b) => b.to_vec(),
            Err(_) => Vec::new(),
        };
        
        // Convert HeaderMap to Vec<(String, String)> for serialization
        let headers_vec: Vec<(String, String)> = response_headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        let record = IdempotencyRecord {
            key: key.clone(),
            request_hash: IdempotencyStore::hash_request(method.as_str(), &path, &body_bytes),
            response_status: status,
            response_headers: headers_vec,
            response_body,
            created_at: now_ms,
            expires_at: now_ms + store.ttl.as_millis() as u64,
        };
        
        // Store asynchronously (don't block response)
        let store_clone = store.clone();
        let key_clone = key.clone();
        tokio::spawn(async move {
            let _ = store_clone.store(key_clone, record);
        });
        
        // Reconstruct response
        let mut new_response = Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
            .body(Body::from(response_body))
            .unwrap();
        
        for (name, value) in response_headers {
            if !is_hop_by_hop_header(&name) {
                new_response.headers_mut().insert(name, value);
            }
        }
        
        Ok(new_response)
    } else {
        Ok(response)
    }
}

/// Headers that should not be cached/replayed
#[cfg(feature = "idempotency")]
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailers" | "transfer-encoding" | "upgrade"
    )
}

/// Layer for adding idempotency middleware
#[cfg(feature = "idempotency")]
pub fn idempotency_layer(store: Arc<IdempotencyStore>) -> tower::LayerFn<fn(Request, Next) -> _> {
    tower::ServiceBuilder::new()
        .layer(axum::middleware::from_fn_with_state(store, idempotency_middleware))
        .into_inner()
}

/// Redis-backed idempotency store (for production clusters)
#[cfg(all(feature = "idempotency", feature = "redis-store"))]
pub mod redis_store {
    use redis::AsyncCommands;
    use super::*;
    use std::time::SystemTime;
    
    /// Redis-backed idempotency store
    pub struct RedisIdempotencyStore {
        client: redis::Client,
        prefix: String,
        ttl: Duration,
    }
    
    impl RedisIdempotencyStore {
        pub fn new(client: redis::Client, prefix: String, ttl: Duration) -> Self {
            Self { client, prefix, ttl }
        }
        
        fn key(&self, key: &str) -> String {
            format!("{}:idempotency:{}", self.prefix, key)
        }
        
        pub async fn check(&self, key: &str, method: &str, path: &str, body: &[u8]) -> Option<IdempotencyRecord> {
            let mut conn = self.client.get_async_connection().await.ok()?;
            let request_hash = IdempotencyStore::hash_request(method, path, body);
            let redis_key = self.key(key);
            
            let data: Option<Vec<u8>> = conn.get(&redis_key).await.ok()?;
            let record: IdempotencyRecord = serde_json::from_slice(&data?).ok()?;
            
            if record.is_expired() || !record.matches_request(&request_hash) {
                let _: () = conn.del(&redis_key).await.ok();
                None
            } else {
                Some(record)
            }
        }
        
        pub async fn store(&self, key: String, record: IdempotencyRecord) -> Result<(), AppError> {
            let mut conn = self.client.get_async_connection().await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Redis connection failed: {}", e)))?;
            
            let redis_key = self.key(&key);
            let data = serde_json::to_vec(&record)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Serialization failed: {}", e)))?;
            
            conn.set_ex(&redis_key, data, self.ttl.as_secs())
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Redis store failed: {}", e)))?;
            
            Ok(())
        }
    }
}

#[cfg(test)]
#[cfg(feature = "idempotency")]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_idempotency_store() {
        let store = IdempotencyStore::new(Duration::from_secs(60));
        let key = Uuid::new_v4().to_string();
        let method = "POST";
        let path = "/api/test";
        let body = b"test body";
        
        // First check - should be None
        assert!(store.check(&key, method, path, body).is_none());
        
        // Store a record
        let record = IdempotencyRecord {
            key: key.clone(),
            request_hash: IdempotencyStore::hash_request(method, path, body),
            response_status: 200,
            response_headers: HeaderMap::new(),
            response_body: b"success".to_vec(),
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        
        store.store(key.clone(), record).unwrap();
        
        // Second check - should return record
        let cached = store.check(&key, method, path, body);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().response_body, b"success");
        
        // Different body - should be None (conflict)
        let different_body = b"different";
        assert!(store.check(&key, method, path, different_body).is_none());
    }
    
    #[test]
    fn test_request_hash() {
        let hash1 = IdempotencyStore::hash_request("POST", "/api/test", b"body");
        let hash2 = IdempotencyStore::hash_request("POST", "/api/test", b"body");
        let hash3 = IdempotencyStore::hash_request("POST", "/api/test", b"different");
        let hash4 = IdempotencyStore::hash_request("GET", "/api/test", b"body");
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash1, hash4);
    }
}