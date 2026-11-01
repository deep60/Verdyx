//! Distributed tracing utilities for request tracking

use std::time::Instant;
use tracing::{info, warn, Span};
use uuid::Uuid;

/// Request tracing context
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub user_id: Option<Uuid>,
    pub start_time: Instant,
    pub path: String,
    pub method: String,
}

impl RequestContext {
    pub fn new(path: String, method: String) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            user_id: None,
            start_time: Instant::now(),
            path,
            method,
        }
    }

    pub fn with_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.start_time.elapsed().as_millis()
    }

    pub fn log_completion(&self, status_code: u16) {
        let elapsed = self.elapsed_ms();

        if status_code >= 500 {
            warn!(
                request_id = %self.request_id,
                method = %self.method,
                path = %self.path,
                status = status_code,
                duration_ms = elapsed,
                user_id = ?self.user_id,
                "Request completed with error"
            );
        } else {
            info!(
                request_id = %self.request_id,
                method = %self.method,
                path = %self.path,
                status = status_code,
                duration_ms = elapsed,
                user_id = ?self.user_id,
                "Request completed"
            );
        }
    }
}

/// Create a new span for a database query
pub fn db_query_span(query: &str) -> Span {
    tracing::info_span!(
        "db_query",
        query = %query,
        db.system = "postgresql"
    )
}

/// Create a new span for an external API call
pub fn api_call_span(service: &str, endpoint: &str) -> Span {
    tracing::info_span!(
        "external_api",
        service = %service,
        endpoint = %endpoint
    )
}

/// Create a new span for blockchain operations
pub fn blockchain_span(operation: &str, chain_id: u64) -> Span {
    tracing::info_span!(
        "blockchain_op",
        operation = %operation,
        chain_id = chain_id
    )
}

/// Macro to time a code block and log duration
#[macro_export]
macro_rules! timed_operation {
    ($name:expr, $block:expr) => {{
        let start = std::time::Instant::now();
        let result = $block;
        let duration = start.elapsed();
        tracing::debug!(
            operation = $name,
            duration_ms = duration.as_millis(),
            "Operation completed"
        );
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context() {
        let ctx = RequestContext::new("/api/test".to_string(), "GET".to_string());
        assert!(!ctx.request_id.is_empty());
        assert!(ctx.user_id.is_none());

        let user_id = Uuid::new_v4();
        let ctx_with_user = ctx.with_user(user_id);
        assert_eq!(ctx_with_user.user_id, Some(user_id));
    }

    #[test]
    fn test_elapsed_time() {
        let ctx = RequestContext::new("/test".to_string(), "POST".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(ctx.elapsed_ms() >= 10);
    }
}
