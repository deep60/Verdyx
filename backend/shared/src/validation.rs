//! Request validation middleware
//!
//! Provides unified validation for HTTP requests using the `validator` crate.
//! Extracts validation logic from handlers into reusable middleware.

#[cfg(feature = "validation")]
use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
#[cfg(feature = "validation")]
use validator::{Validate, ValidationErrors};
#[cfg(feature = "validation")]
use serde::de::DeserializeOwned;
#[cfg(feature = "validation")]
use std::marker::PhantomData;

use crate::{AppError, AppResult};

/// Validation error detail for API responses
#[cfg(feature = "validation")]
#[derive(Debug, serde::Serialize)]
pub struct ValidationErrorDetail {
    pub field: String,
    pub code: String,
    pub message: String,
}

/// Convert validator::ValidationErrors to our format
#[cfg(feature = "validation")]
pub fn format_validation_errors(errors: &ValidationErrors) -> Vec<ValidationErrorDetail> {
    let mut details = Vec::new();
    
    for (field, errs) in errors.field_errors() {
        for err in errs {
            details.push(ValidationErrorDetail {
                field: field.to_string(),
                code: err.code.to_string(),
                message: err.message
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| format!("Validation failed for field '{}'", field)),
            });
        }
    }
    
    details
}

/// Extract validated JSON from request
/// 
/// This middleware validates the request body against the type's Validate impl.
/// If validation fails, returns 400 with structured error details.
#[cfg(feature = "validation")]
pub async fn validation_middleware<T>(
    mut request: Request,
    next: Next,
) -> Result<Response, Response>
where
    T: Validate + DeserializeOwned + Send + 'static,
{
    // Check if this is a JSON request
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    if !content_type.starts_with("application/json") {
        return Ok(next.run(request).await);
    }
    
    // Buffer the body so we can validate it
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            let err = AppError::Validation(format!("Failed to read request body: {}", e));
            return Err(err.to_api_error(None).into_response());
        }
    };
    
    // Parse and validate
    let validated: T = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            let err = AppError::Validation(format!("Invalid JSON: {}", e));
            return Err(err.to_api_error(None).into_response());
        }
    };
    
    if let Err(validation_errors) = validated.validate() {
        let details = format_validation_errors(&validation_errors);
        let err = AppError::ValidationErrors(details);
        return Err(err.to_api_error(None).into_response());
    }
    
    // Reconstruct request with validated body
    let request = Request::from_parts(parts, Body::from(bytes));
    
    // Store validated data in extensions for handlers to use
    // Note: In practice, you'd use a custom extractor instead
    let mut request = request;
    request.extensions_mut().insert(ValidatedPayload(validated));
    
    Ok(next.run(request).await)
}

/// Wrapper for validated payload in request extensions
#[cfg(feature = "validation")]
#[derive(Clone)]
pub struct ValidatedPayload<T>(pub T);

/// Custom extractor for validated payloads
#[cfg(feature = "validation")]
impl<T> axum::extract::FromRequestParts<()> for ValidatedPayload<T>
where
    T: Send + Sync + 'static,
{
    type Rejection = Response;
    
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &(),
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ValidatedPayload<T>>()
            .cloned()
            .ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!("Validated payload not found in request extensions"))
                    .to_api_error(None)
                    .into_response()
            })
    }
}

/// Query parameter validation
#[cfg(feature = "validation")]
pub async fn query_validation_middleware<T>(
    mut request: Request,
    next: Next,
) -> Result<Response, Response>
where
    T: Validate + DeserializeOwned + Send + 'static,
{
    // Extract query string
    let query = request.uri().query().unwrap_or("");
    let parsed: T = match serde_qs::from_str(query) {
        Ok(v) => v,
        Err(e) => {
            let err = AppError::Validation(format!("Invalid query parameters: {}", e));
            return Err(err.to_api_error(None).into_response());
        }
    };
    
    if let Err(validation_errors) = parsed.validate() {
        let details = format_validation_errors(&validation_errors);
        let err = AppError::ValidationErrors(details);
        return Err(err.to_api_error(None).into_response());
    }
    
    request.extensions_mut().insert(ValidatedQuery(parsed));
    Ok(next.run(request).await)
}

/// Wrapper for validated query parameters
#[cfg(feature = "validation")]
#[derive(Clone)]
pub struct ValidatedQuery<T>(pub T);

/// Custom extractor for validated query
#[cfg(feature = "validation")]
impl<T> axum::extract::FromRequestParts<()> for ValidatedQuery<T>
where
    T: Send + Sync + 'static,
{
    type Rejection = Response;
    
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &(),
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ValidatedQuery<T>>()
            .cloned()
            .ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!("Validated query not found in request extensions"))
                    .to_api_error(None)
                    .into_response()
            })
    }
}

/// Path parameter validation
#[cfg(feature = "validation")]
pub async fn path_validation_middleware<T>(
    mut request: Request,
    next: Next,
) -> Result<Response, Response>
where
    T: Validate + DeserializeOwned + Send + 'static,
{
    // For path parameters, we'd need to extract them from the matched route
    // This is typically done via axum's Path extractor which already parses
    // For now, we'll skip automatic path validation and let handlers use the Path extractor
    Ok(next.run(request).await)
}

/// Macro to easily add validation to a route
#[cfg(feature = "validation")]
#[macro_export]
macro_rules! validated_route {
    ($method:ident, $path:expr, $handler:expr, $body_ty:ty) => {{
        use axum::routing::$method;
        use $crate::validation::validation_middleware;
        use tower::ServiceBuilder;
        
        axum::routing::$method(
            $path,
            axum::middleware::from_fn_with_state(
                (),
                validation_middleware::<$body_ty>
            ).layer(
                axum::routing::post($handler)
            )
        )
    }};
}

#[cfg(test)]
#[cfg(feature = "validation")]
mod tests {
    use super::*;
    use validator::Validate;
    use serde::{Deserialize, Serialize};
    
    #[derive(Debug, Validate, Deserialize, Serialize)]
    struct TestInput {
        #[validate(length(min = 3, max = 50))]
        name: String,
        
        #[validate(email)]
        email: String,
        
        #[validate(range(min = 18, max = 120))]
        age: u8,
    }
    
    #[test]
    fn test_format_validation_errors() {
        let input = TestInput {
            name: "ab".to_string(),
            email: "invalid".to_string(),
            age: 10,
        };
        
        let errors = input.validate().unwrap_err();
        let formatted = format_validation_errors(&errors);
        
        assert_eq!(formatted.len(), 3);
        assert!(formatted.iter().any(|e| e.field == "name"));
        assert!(formatted.iter().any(|e| e.field == "email"));
        assert!(formatted.iter().any(|e| e.field == "age"));
    }
}