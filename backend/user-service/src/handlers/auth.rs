use axum::{
    extract::State,
    http::{header, header::HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::models::*;
use crate::AppState;

// ============= Request/Response Types =============

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[serde(alias = "password")]
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyWalletRequest {
    pub address: String,
    pub signature: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ============= Handlers =============

/// Register a new user
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let response = state.user_service.register(req).await?;
    Ok(Json(response))
}

/// Login user
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let response = state.user_service.login(req).await?;
    Ok(Json(response))
}

/// Return the authenticated user's public identity.
///
/// Used by the API gateway's `/api/v1/auth/verify` proxy to resolve the
/// current user from an access token (user-service is the source of truth
/// for identity under the microservices design).
pub async fn get_me(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<UserPublic>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let user = state.user_service.get_user_by_id(user_id).await?;
    Ok(Json(user.into()))
}

/// Logout user - blacklist the JWT token
pub async fn logout(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<MessageResponse>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    // Extract the raw token to blacklist it
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(token) = auth_header.to_str() {
            if let Some(token) = token.strip_prefix("Bearer ") {
                // Calculate token TTL
                let exp = claims.exp;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| AppError::InternalError("System time error".to_string()))?
                    .as_secs() as i64;

                let ttl = (exp - now).max(0) as usize;

                if ttl > 0 {
                    // Blacklist the token in Redis
                    let blacklist_key = format!("jwt_blacklist:{token}");
                    let mut conn = state.redis_conn.clone();

                    let _: Result<(), redis::RedisError> = redis::cmd("SETEX")
                        .arg(&blacklist_key)
                        .arg(ttl)
                        .arg("blacklisted")
                        .query_async(&mut conn)
                        .await;
                }
            }
        }
    }

    // Also remove session
    state.user_service.logout(user_id).await?;

    Ok(Json(MessageResponse {
        message: "Successfully logged out".to_string(),
    }))
}

/// Refresh access token
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let response = state.user_service.refresh_token(&req.refresh_token).await?;
    Ok(Json(response))
}

/// Verify email
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    state.user_service.verify_email(user_id, &req.token).await?;

    Ok(Json(MessageResponse {
        message: "Email verified successfully".to_string(),
    }))
}

/// Forgot password - email a reset link.
///
/// The token is only ever delivered by email: returning it (or a link holding
/// it) here would let anyone who knows an address take over that account. The
/// response is identical whether or not the account exists.
pub async fn forgot_password(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = req.email.trim().to_ascii_lowercase();

    match state.user_service.create_password_reset_token(&email).await {
        Ok(token) => {
            // Send in the background so response time doesn't reveal whether
            // the account exists.
            let config = state.config.email.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::services::mailer::send_password_reset(&config, &email, &token).await
                {
                    tracing::error!("Could not send password reset email: {}", e);
                }
            });
        }
        Err(e) => {
            tracing::debug!("Password reset not issued: {}", e);
        }
    }

    Ok(Json(json!({
        "message": "If an account with that email exists, a reset link has been sent.",
    })))
}

/// Reset password with token
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    // Validate the reset token and apply the new password
    state
        .user_service
        .reset_password_with_token(&req.token, &req.new_password)
        .await
        .map_err(|e| {
            tracing::warn!("Password reset failed: {}", e);
            AppError::UserError(e)
        })?;

    Ok(Json(MessageResponse {
        message: "Password reset successfully".to_string(),
    }))
}

/// Verify wallet signature and link to account
pub async fn verify_wallet(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<VerifyWalletRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    state
        .user_service
        .link_wallet(user_id, &req.address, &req.signature, &req.message)
        .await?;

    Ok(Json(MessageResponse {
        message: "Wallet verified and linked successfully".to_string(),
    }))
}

// ============= Additional Types =============

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

// ============= Error Handling =============

#[derive(Debug)]
pub enum AppError {
    UserError(UserError),
    Unauthorized(String),
    InternalError(String),
}

impl From<UserError> for AppError {
    fn from(err: UserError) -> Self {
        AppError::UserError(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::UserError(UserError::ValidationError(msg)) => (StatusCode::BAD_REQUEST, msg),
            AppError::UserError(UserError::AuthenticationError(msg)) => {
                (StatusCode::UNAUTHORIZED, msg)
            }
            AppError::UserError(UserError::Unauthorized(msg)) => (StatusCode::FORBIDDEN, msg),
            AppError::UserError(UserError::NotFound) => {
                (StatusCode::NOT_FOUND, "Resource not found".to_string())
            }
            AppError::UserError(UserError::AlreadyExists) => {
                (StatusCode::CONFLICT, "Resource already exists".to_string())
            }
            AppError::UserError(UserError::DatabaseError(msg)) => {
                tracing::error!("Database error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::UserError(UserError::InvalidToken) => (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired token".to_string(),
            ),
            AppError::UserError(UserError::TooManyAttempts) => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many failed attempts. Please try again in 15 minutes.".to_string(),
            ),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::InternalError(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": message,
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}
