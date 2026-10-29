use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

// Handler modules
pub mod analysis;
pub mod auth;
pub mod bounty;
pub mod consensus_proxy;
pub mod engines;
pub mod health;
pub mod identity;
pub mod reputation;
pub mod submission;
pub mod user;
pub mod wallet;
pub mod web_intel;
pub mod webhook;
pub mod websocket;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Authentication failed")]
    Unauthorized,
    #[error("Resource not found")]
    NotFound,
    #[error("Invalid request: {0}")]
    BadRequest(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Blockchain error: {0}")]
    Blockchain(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Analysis timeout")]
    AnalysisTimeout,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Resource not found"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "Invalid request"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
            ApiError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            ApiError::Blockchain(_) => (StatusCode::BAD_GATEWAY, "Blockchain error"),
            ApiError::Validation(_) => (StatusCode::BAD_REQUEST, "Validation error"),
            ApiError::InsufficientFunds => (StatusCode::PAYMENT_REQUIRED, "Insufficient funds"),
            ApiError::AnalysisTimeout => (StatusCode::REQUEST_TIMEOUT, "Analysis timeout"),
        };

        let body = Json(json!({
            "error": error_message,
            "details": self.to_string()
        }));

        (status, body).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// Common response types
#[derive(serde::Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }

    pub fn success_with_message(data: T, message: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some(message),
        }
    }

    pub fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: Some(message),
        }
    }
}

// Pagination helper
#[derive(serde::Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    20
}

impl PaginationQuery {
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.limit
    }
}

#[derive(serde::Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: u64, page: u32, limit: u32) -> Self {
        let total_pages = (total as f64 / limit as f64).ceil() as u32;
        Self {
            items,
            total,
            page,
            limit,
            total_pages,
        }
    }
}
