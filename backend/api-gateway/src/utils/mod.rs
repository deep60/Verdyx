pub mod circuit_breaker;
pub mod crypto;
pub mod errors;
pub mod outbound;
pub mod serialization;
pub mod validation;

// Re-export commonly used types. `ApiResponse` is only referenced by tests in
// this module, so allow it to appear unused in non-test (lib) builds.
#[allow(unused_imports)]
pub use errors::ApiResponse;
pub use errors::{ApiError, ApiResult};

// Re-export commonly used items for convenience
pub use crypto::{CryptoUtils, HashUtils};

pub use validation::{ApiValidator, ValidationResult};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ApiResponse is now defined in errors.rs and re-exported above

/// Pagination parameters for list endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    pub page: u32,
    pub page_size: u32,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>, // "asc" or "desc"
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
            sort_by: None,
            sort_order: Some("desc".to_string()),
        }
    }
}

impl PaginationParams {
    /// Validate pagination parameters
    pub fn validate(&self) -> ValidationResult<()> {
        ApiValidator::validate_pagination(self.page, self.page_size)?;

        if let (Some(sort_by), Some(sort_order)) = (&self.sort_by, &self.sort_order) {
            // Default allowed sort fields - can be overridden per endpoint
            let default_fields = ["created_at", "updated_at", "name", "id"];
            ApiValidator::validate_sort_params(sort_by, sort_order, &default_fields)?;
        }

        Ok(())
    }

    /// Calculate offset for database queries
    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.page_size
    }

    /// Get limit for database queries
    pub fn limit(&self) -> u32 {
        self.page_size
    }
}

/// Paginated response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total_count: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_previous: bool,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total_count: u64, page: u32, page_size: u32) -> Self {
        let total_pages = ((total_count as f64) / (page_size as f64)).ceil() as u32;
        let has_next = page < total_pages;
        let has_previous = page > 1;

        Self {
            items,
            total_count,
            page,
            page_size,
            total_pages,
            has_next,
            has_previous,
        }
    }
}

/// HTTP status codes commonly used in the API
#[derive(Debug, Clone, Copy)]
pub enum HttpStatus {
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    Conflict = 409,
    UnprocessableEntity = 422,
    TooManyRequests = 429,
    InternalServerError = 500,
    BadGateway = 502,
    ServiceUnavailable = 503,
}

impl HttpStatus {
    pub fn code(&self) -> u16 {
        *self as u16
    }

    pub fn is_success(&self) -> bool {
        self.code() >= 200 && self.code() < 300
    }

    pub fn is_client_error(&self) -> bool {
        self.code() >= 400 && self.code() < 500
    }

    pub fn is_server_error(&self) -> bool {
        self.code() >= 500 && self.code() < 600
    }
}

// ApiError and related types are now defined in errors.rs and re-exported above

/// Request metadata for logging and tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub request_id: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub query_params: Option<HashMap<String, String>>,
}

impl RequestMetadata {
    pub fn new(method: String, path: String) -> Self {
        Self {
            request_id: CryptoUtils::generate_uuid(),
            user_agent: None,
            ip_address: None,
            timestamp: Utc::now(),
            method,
            path,
            query_params: None,
        }
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_query_params(mut self, params: HashMap<String, String>) -> Self {
        self.query_params = Some(params);
        self
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub uptime_seconds: u64,
    pub checks: HashMap<String, ServiceHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub status: String,
    pub response_time_ms: Option<u64>,
    pub last_check: DateTime<Utc>,
    pub error: Option<String>,
}

impl ServiceHealth {
    pub fn healthy(response_time_ms: u64) -> Self {
        Self {
            status: "healthy".to_string(),
            response_time_ms: Some(response_time_ms),
            last_check: Utc::now(),
            error: None,
        }
    }

    pub fn unhealthy(error: String) -> Self {
        Self {
            status: "unhealthy".to_string(),
            response_time_ms: None,
            last_check: Utc::now(),
            error: Some(error),
        }
    }
}

/// Rate limiting information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub limit: u32,
    pub remaining: u32,
    pub reset_at: DateTime<Utc>,
    pub retry_after: Option<u32>,
}

impl RateLimitInfo {
    pub fn new(limit: u32, remaining: u32, reset_at: DateTime<Utc>) -> Self {
        let retry_after = if remaining == 0 {
            Some((reset_at - Utc::now()).num_seconds() as u32)
        } else {
            None
        };

        Self {
            limit,
            remaining,
            reset_at,
            retry_after,
        }
    }
}

/// File upload metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUploadInfo {
    pub filename: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub hash_sha256: String,
    pub upload_id: String,
    pub uploaded_at: DateTime<Utc>,
    pub uploader_address: String,
}

impl FileUploadInfo {
    pub fn new(
        filename: String,
        size_bytes: u64,
        mime_type: String,
        file_data: &[u8],
        uploader_address: String,
    ) -> Self {
        Self {
            filename,
            size_bytes,
            mime_type,
            hash_sha256: HashUtils::sha256(file_data),
            upload_id: CryptoUtils::generate_uuid(),
            uploaded_at: Utc::now(),
            uploader_address,
        }
    }

    pub fn human_readable_size(&self) -> String {
        CryptoUtils::bytes_to_human_readable(self.size_bytes)
    }
}

/// Authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: String,
    pub ethereum_address: String,
    pub api_key_id: Option<String>,
    pub permissions: Vec<String>,
    pub rate_limit_tier: String,
    pub authenticated_at: DateTime<Utc>,
}

impl AuthContext {
    pub fn new(user_id: String, ethereum_address: String) -> Self {
        Self {
            user_id,
            ethereum_address,
            api_key_id: None,
            permissions: vec!["basic".to_string()],
            rate_limit_tier: "standard".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    pub fn with_api_key(mut self, api_key_id: String) -> Self {
        self.api_key_id = Some(api_key_id);
        self
    }

    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions;
        self
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
            || self.permissions.contains(&"admin".to_string())
    }
}

/// Utility functions
pub mod helpers {
    use super::*;

    /// Generate a new request ID
    pub fn generate_request_id() -> String {
        CryptoUtils::generate_uuid()
    }

    /// Get current Unix timestamp
    pub fn current_timestamp() -> i64 {
        Utc::now().timestamp()
    }

    /// Convert Unix timestamp to DateTime
    pub fn timestamp_to_datetime(timestamp: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now)
    }

    /// Sanitize string for logging (remove sensitive data)
    pub fn sanitize_for_log(input: &str) -> String {
        // Remove potential sensitive patterns
        let patterns = [
            (
                r#"(?i)password["':\s]*["']?([^"'\s,}]+)"#,
                "password: [REDACTED]",
            ),
            (r#"(?i)token["':\s]*["']?([^"'\s,}]+)"#, "token: [REDACTED]"),
            (r#"(?i)key["':\s]*["']?([^"'\s,}]+)"#, "key: [REDACTED]"),
            (
                r#"(?i)secret["':\s]*["']?([^"'\s,}]+)"#,
                "secret: [REDACTED]",
            ),
        ];

        let mut result = input.to_string();
        for (pattern, replacement) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                result = re.replace_all(&result, replacement).to_string();
            }
        }
        result
    }

    /// Truncate string to specified length with ellipsis
    pub fn truncate_string(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }

    /// Parse query string into HashMap
    pub fn parse_query_string(query: &str) -> HashMap<String, String> {
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect()
    }

    /// Build query string from HashMap
    pub fn build_query_string(params: &HashMap<String, String>) -> String {
        if params.is_empty() {
            return String::new();
        }

        let pairs: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect();

        format!("?{}", pairs.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_creation() {
        let success_response = ApiResponse::success("test data");
        assert!(success_response.success);
        assert_eq!(success_response.data, Some("test data"));
        assert!(success_response.error.is_none());

        let error_response: ApiResponse<()> = ApiResponse::error("test error".to_string());
        assert!(!error_response.success);
        assert!(error_response.data.is_none());
        assert_eq!(error_response.error, Some("test error".to_string()));
    }

    #[test]
    fn test_pagination_params() {
        let params = PaginationParams {
            page: 2,
            page_size: 10,
            ..Default::default()
        };

        assert_eq!(params.offset(), 10);
        assert_eq!(params.limit(), 10);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_paginated_response() {
        let items = vec![1, 2, 3];
        let response = PaginatedResponse::new(items, 100, 1, 10);

        assert_eq!(response.total_count, 100);
        assert_eq!(response.total_pages, 10);
        assert!(response.has_next);
        assert!(!response.has_previous);
    }

    #[test]
    fn test_http_status() {
        assert_eq!(HttpStatus::Ok.code(), 200);
        assert!(HttpStatus::Ok.is_success());
        assert!(!HttpStatus::BadRequest.is_success());
        assert!(HttpStatus::BadRequest.is_client_error());
        assert!(HttpStatus::InternalServerError.is_server_error());
    }

    #[test]
    fn test_auth_context() {
        let auth = AuthContext::new("user123".to_string(), "0x123...".to_string())
            .with_permissions(vec!["read".to_string(), "write".to_string()]);

        assert!(auth.has_permission("read"));
        assert!(auth.has_permission("write"));
        assert!(!auth.has_permission("admin"));
    }

    #[test]
    fn test_helpers() {
        let request_id = helpers::generate_request_id();
        assert!(!request_id.is_empty());

        let timestamp = helpers::current_timestamp();
        assert!(timestamp > 0);

        let sanitized = helpers::sanitize_for_log("password: secret123");
        assert!(sanitized.contains("[REDACTED]"));

        let truncated = helpers::truncate_string("very long string", 8);
        assert_eq!(truncated, "very ...");
    }
}
