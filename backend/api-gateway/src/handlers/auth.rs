use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use ethers::core::types::Signature;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::identity::{bearer_map, fetch_identity, UserIdentity};
use crate::models::user::User;
use crate::utils::crypto::hash_password;
use crate::utils::{ApiError, ApiResult};
use crate::{ApiResponse, AppState};

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
        .route("/verify", get(verify_token))
        .route("/profile", get(get_profile))
        .route("/wallet/connect", post(collect_wallet))
        .route("/wallet/disconnect", post(disconnect_wallet))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub wallet_address: Option<String>,
    pub exp: usize,
    pub iat: usize,
    pub role: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub wallet_address: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub identifier: String, // username or email
    pub password: String,
}

#[derive(Deserialize)]
pub struct WalletConnectRequest {
    pub wallet_address: String,
    pub signature: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub wallet_address: Option<String>,
    pub reputation_score: i32,
    pub total_earnings: String, // BigDecimal as string
    pub created_at: DateTime<Utc>,
    pub is_verified: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            wallet_address: user.wallet_address,
            reputation_score: user.reputation_score,
            total_earnings: user.total_stakes.to_string(),
            created_at: user.created_at,
            is_verified: user.is_verified,
        }
    }
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    // Validate input
    if payload.username.is_empty() || payload.email.is_empty() {
        return Err(ApiError::Validation(
            "Username and email are required".to_string(),
        ));
    }

    // Validate password strength
    if payload.password.len() < 8 {
        return Err(ApiError::Validation(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    // Check for at least one uppercase letter
    if !payload.password.chars().any(|c| c.is_uppercase()) {
        return Err(ApiError::Validation(
            "Password must contain at least one uppercase letter".to_string(),
        ));
    }

    // Check for at least one lowercase letter
    if !payload.password.chars().any(|c| c.is_lowercase()) {
        return Err(ApiError::Validation(
            "Password must contain at least one lowercase letter".to_string(),
        ));
    }

    // Check for at least one digit
    if !payload.password.chars().any(|c| c.is_numeric()) {
        return Err(ApiError::Validation(
            "Password must contain at least one number".to_string(),
        ));
    }

    // Check for at least one special character
    if !payload.password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(ApiError::Validation(
            "Password must contain at least one special character".to_string(),
        ));
    }

    // Validate username format (alphanumeric and underscores only)
    if !payload
        .username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_')
    {
        return Err(ApiError::Validation(
            "Username can only contain letters, numbers, and underscores".to_string(),
        ));
    }

    // Validate username length
    if payload.username.len() < 3 || payload.username.len() > 30 {
        return Err(ApiError::Validation(
            "Username must be between 3 and 30 characters".to_string(),
        ));
    }

    // Auth is owned by user-service. The gateway validates input shape, then
    // forwards to user-service and adapts the response to its public
    // (camelCase) contract so the frontend is unaffected.
    let body = serde_json::json!({
        "username": payload.username,
        "email": payload.email,
        "password": payload.password,
        "ethereum_address": payload.wallet_address,
    });
    forward_auth(&state, "/api/v1/auth/register", body).await
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    // user-service authenticates by email; map the gateway's `identifier`
    // field onto it. (Username login can be re-added in user-service later.)
    let body = serde_json::json!({
        "email": payload.identifier,
        "password": payload.password,
    });
    forward_auth(&state, "/api/v1/auth/login", body).await
}

pub async fn logout(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<()>>> {
    // Forward to user-service, which blacklists the token and clears the
    // session. Logout is best-effort for UX, so failures are swallowed.
    if let Some(hm) = bearer_map(&headers) {
        let _ = state
            .proxy
            .post(
                "user-service",
                "/api/v1/auth/logout",
                serde_json::json!({}),
                Some(hm),
            )
            .await;
    }

    Ok(Json(ApiResponse::success_with_message(
        (),
        "Successfully logged out".to_string(),
    )))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    let body = serde_json::json!({ "refresh_token": payload.refresh_token });
    forward_auth(&state, "/api/v1/auth/refresh", body).await
}

pub async fn verify_token(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    identity_as_user_response(&state, &headers).await
}

pub async fn get_profile(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    identity_as_user_response(&state, &headers).await
}

pub async fn collect_wallet(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<WalletConnectRequest>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    // Wallet linking is owned by user-service (it verifies the signature and
    // stores the address). Forward, then return the refreshed identity.
    let hm = bearer_map(&headers).ok_or(ApiError::Unauthorized)?;
    let body = serde_json::json!({
        "address": payload.wallet_address,
        "signature": payload.signature,
        "message": payload.message,
    });
    let resp = state
        .proxy
        .post(
            "user-service",
            "/api/v1/wallet/link",
            body,
            Some(hm.clone()),
        )
        .await
        .map_err(|e| ApiError::Internal(format!("user-service unreachable: {e}")))?;
    if !resp.status().is_success() {
        return Err(map_auth_status(resp.status().as_u16()));
    }

    match fetch_identity(&state, hm).await {
        Ok(u) => Ok(Json(ApiResponse::success(to_user_response(u)))),
        Err(code) => Err(map_auth_status(code)),
    }
}

pub async fn disconnect_wallet(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    let hm = bearer_map(&headers).ok_or(ApiError::Unauthorized)?;
    let resp = state
        .proxy
        .delete("user-service", "/api/v1/wallet/unlink", Some(hm.clone()))
        .await
        .map_err(|e| ApiError::Internal(format!("user-service unreachable: {e}")))?;
    if !resp.status().is_success() {
        return Err(map_auth_status(resp.status().as_u16()));
    }

    match fetch_identity(&state, hm).await {
        Ok(u) => Ok(Json(ApiResponse::success(to_user_response(u)))),
        Err(code) => Err(map_auth_status(code)),
    }
}

// Helper function
fn generate_tokens(user: &User, secret: &str) -> ApiResult<(String, String)> {
    let now = Utc::now();
    let exp_access = (now + Duration::hours(1)).timestamp() as usize;
    let exp_refresh = (now + Duration::days(30)).timestamp() as usize;

    let claims_access = Claims {
        sub: user.id.to_string(),
        wallet_address: user.wallet_address.clone(),
        exp: exp_access,
        iat: now.timestamp() as usize,
        role: "user".to_string(),
    };

    let claims_refresh = Claims {
        sub: user.id.to_string(),
        wallet_address: user.wallet_address.clone(),
        exp: exp_refresh,
        iat: now.timestamp() as usize,
        role: "refresh".to_string(),
    };

    let encoding_key = EncodingKey::from_secret(secret.as_ref());
    let access_token = encode(&Header::default(), &claims_access, &encoding_key)
        .map_err(|e| ApiError::Internal(format!("Token generation failed: {e}")))?;

    let refresh_token = encode(&Header::default(), &claims_refresh, &encoding_key)
        .map_err(|e| ApiError::Internal(format!("Token generation failed: {e}")))?;

    Ok((access_token, refresh_token))
}

fn decode_token(token: &str, secret: &str) -> ApiResult<Claims> {
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::default();

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|_| ApiError::Unauthorized)
}

fn extract_token_from_header(headers: &HeaderMap) -> ApiResult<String> {
    let auth_header = headers
        .get("Authorization")
        .ok_or(ApiError::Unauthorized)?
        .to_str()
        .map_err(|_| ApiError::Unauthorized)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(ApiError::Unauthorized);
    }

    Ok(auth_header[7..].to_string())
}

async fn authenticate_user(headers: &HeaderMap, state: &AppState) -> ApiResult<User> {
    let token = extract_token_from_header(headers)?;
    let claims = decode_token(&token, &state.config.security.jwt_secret)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::BadRequest("Invalid user ID in token".to_string()))?;

    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(state.db.pool())
        .await?
        .ok_or(ApiError::Unauthorized)
}

fn verify_wallet_signature(address: &str, signature: &str, message: &str) -> bool {
    // Parse the hex signature
    let sig = match signature.parse::<Signature>() {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Recover the signer address from the signature
    // This uses EIP-191 personal_sign recovery (prefix "\x19Ethereum Signed Message:\n")
    let recovered = match sig.recover(message) {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    // Compare recovered address to claimed address (case-insensitive hex comparison)
    let recovered_hex = format!("{recovered:?}"); // "0x..." lowercase
    recovered_hex.eq_ignore_ascii_case(address)
}

/// Verify email address — proxy to user-service
pub async fn verify_email(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Some(hm) = bearer_map(&headers) {
        if let Ok(resp) = state
            .proxy
            .post("user-service", "/api/v1/auth/verify-email", payload.clone(), Some(hm))
            .await
        {
            if resp.status().is_success() {
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "message": "Email verified successfully"
                })));
            }
        }
    }

    let token = payload
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let user_id_str = state
        .redis
        .get_raw(format!("email_verify:{token}"))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    let user_id = Uuid::parse_str(&user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    sqlx::query("UPDATE users SET is_verified = true WHERE id = $1")
        .bind(user_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = state
        .redis
        .delete_raw(format!("email_verify:{token}"))
        .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Email verified successfully"
    })))
}

/// Forgot password — delegate to user-service
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let email = payload
        .get("email")
        .and_then(|e| e.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Forward to user-service (source of truth for user accounts)
    if let Ok(resp) = state
        .proxy
        .post(
            "user-service",
            "/api/v1/auth/forgot-password",
            serde_json::json!({ "email": email }),
            None,
        )
        .await
    {
        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({}));
            return Ok(Json(serde_json::json!({
                "success": true,
                "message": "If an account with that email exists, a password reset link has been sent",
                "resetUrl": body.get("resetUrl").cloned().unwrap_or(serde_json::Value::Null),
                "resetToken": body.get("resetToken").cloned().unwrap_or(serde_json::Value::Null),
            })));
        }
    }

    // Fallback to local gateway DB if user-service is unreachable
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut reset_url: Option<String> = None;
    if let Some(user) = user {
        let reset_token = Uuid::new_v4().to_string();
        let _ = state
            .redis
            .set_raw_with_ttl(
                format!("password_reset:{reset_token}"),
                user.id.to_string(),
                3600,
            )
            .await;

        tracing::info!(
            user_id = %user.id,
            "Password reset link: /reset-password?token={}",
            reset_token
        );
        reset_url = Some(format!("/reset-password?token={reset_token}"));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "If an account with that email exists, a password reset link has been sent",
        "resetUrl": reset_url,
    })))
}

/// Reset password — delegate to user-service
pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = payload
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let new_password = payload
        .get("password")
        .or_else(|| payload.get("new_password"))
        .and_then(|p| p.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    if new_password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Forward to user-service first
    if let Ok(resp) = state
        .proxy
        .post(
            "user-service",
            "/api/v1/auth/reset-password",
            serde_json::json!({
                "token": token,
                "new_password": new_password,
            }),
            None,
        )
        .await
    {
        if resp.status().is_success() {
            return Ok(Json(serde_json::json!({
                "success": true,
                "message": "Password reset successfully"
            })));
        }
    }

    // Fallback to gateway Redis/DB
    let user_id_str = state
        .redis
        .get_raw(format!("password_reset:{token}"))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    let user_id = Uuid::parse_str(&user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    let password_hash =
        hash_password(new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&password_hash)
        .bind(user_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = state
        .redis
        .delete_raw(format!("password_reset:{token}"))
        .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Password reset successfully"
    })))
}

/// Generate API key (validates JWT via claims or user-service identity)
pub async fn generate_api_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    payload: Option<Json<serde_json::Value>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = extract_token_from_header(&headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user_id = match crate::utils::crypto::validate_jwt(&token, &state.config.security.jwt_secret) {
        Ok(claims) => Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?,
        Err(_) => {
            let hm = bearer_map(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
            let identity = fetch_identity(&state, hm)
                .await
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
            sync_user_to_gateway_db(&state, &identity).await;
            identity.id
        }
    };

    let key_name = payload
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("Default API Key");

    // Generate a random API key
    let raw_key = format!("vdx_{}", Uuid::new_v4().to_string().replace("-", ""));
    let key_hash = hash_password(&raw_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let key_id = Uuid::new_v4();
    let now = Utc::now();

    // Store hashed key in database
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, key_hash, name, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(key_id)
    .bind(user_id)
    .bind(&key_hash)
    .bind(key_name)
    .bind(now)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to store API key: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "api_key": raw_key,
        "key_id": key_id,
        "name": key_name,
        "created_at": now,
        "message": "Store this key securely — it will not be shown again"
    })))
}

// ===== user-service auth proxy helpers =====
//
// Auth/identity is owned by user-service. These helpers forward requests via
// the gateway's ProxyService and translate user-service's snake_case contract
// into the gateway's public camelCase contract, so the frontend is unaffected.

/// Sync user-service identity into the gateway's local `users` table so foreign
/// keys (`bounties`, `webhooks`, `reputation_history`, `api_keys`) and the
/// leaderboard always have the user row. Returns the user's reputation_score.
pub async fn sync_user_to_gateway_db(state: &AppState, u: &UserIdentity) -> i32 {
    let score: Option<i32> = sqlx::query_scalar(
        r#"
        INSERT INTO users (id, username, email, password_hash, wallet_address, reputation_score, is_verified, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, 'managed_by_user_service', $4, 100, $5, true, $6, NOW())
        ON CONFLICT (id) DO UPDATE SET
            username = EXCLUDED.username,
            email = EXCLUDED.email,
            wallet_address = COALESCE(EXCLUDED.wallet_address, users.wallet_address),
            is_verified = EXCLUDED.is_verified,
            updated_at = NOW()
        RETURNING reputation_score
        "#,
    )
    .bind(u.id)
    .bind(&u.username)
    .bind(&u.email)
    .bind(&u.ethereum_address)
    .bind(u.email_verified)
    .bind(u.created_at)
    .fetch_optional(state.db.pool())
    .await
    .ok()
    .flatten();

    score.unwrap_or(100)
}

/// Adapt a user-service identity into the gateway's public `UserResponse`.
fn to_user_response_with_rep(u: UserIdentity, reputation_score: i32) -> UserResponse {
    UserResponse {
        id: u.id,
        username: u.username,
        email: u.email,
        wallet_address: u.ethereum_address,
        reputation_score,
        total_earnings: "0".to_string(),
        created_at: u.created_at,
        is_verified: u.email_verified,
    }
}

fn to_user_response(u: UserIdentity) -> UserResponse {
    to_user_response_with_rep(u, 100)
}

/// user-service's auth response shape (snake_case).
#[derive(Debug, Deserialize)]
struct UsAuthResponse {
    access_token: String,
    refresh_token: String,
    user: UserIdentity,
    #[serde(default)]
    expires_in: i64,
}

/// Map a downstream auth error status code to the gateway's ApiError.
/// Takes a raw `u16` to avoid the reqwest/axum `http` StatusCode type split.
fn map_auth_status(code: u16) -> ApiError {
    match code {
        401 | 403 => ApiError::Unauthorized,
        409 => ApiError::BadRequest("User already exists".to_string()),
        400..=499 => ApiError::Validation("Invalid request".to_string()),
        _ => ApiError::Internal("Authentication service error".to_string()),
    }
}

/// Forward an auth request to user-service and adapt the response to the
/// gateway's public `AuthResponse` contract.
async fn forward_auth(
    state: &AppState,
    path: &str,
    body: serde_json::Value,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    let resp = state
        .proxy
        .post("user-service", path, body, None)
        .await
        .map_err(|e| ApiError::Internal(format!("user-service unreachable: {e}")))?;

    let status = resp.status();
    if status.is_success() {
        let ua: UsAuthResponse = resp
            .json()
            .await
            .map_err(|e| ApiError::Internal(format!("invalid user-service response: {e}")))?;
        let rep = sync_user_to_gateway_db(state, &ua.user).await;
        let auth_resp = AuthResponse {
            user: to_user_response_with_rep(ua.user, rep),
            access_token: ua.access_token,
            refresh_token: ua.refresh_token,
            expires_in: if ua.expires_in > 0 { ua.expires_in } else { 3600 },
        };
        Ok(Json(ApiResponse::success(auth_resp)))
    } else {
        // Prefer the downstream error message when present.
        let msg = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string));
        Err(match (status.as_u16(), msg) {
            (400, Some(m)) | (422, Some(m)) => ApiError::Validation(m),
            (409, Some(m)) => ApiError::BadRequest(m),
            (c, _) => map_auth_status(c),
        })
    }
}

/// Fetch the current identity from user-service and return it as the gateway's
/// public `UserResponse`.
async fn identity_as_user_response(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    let hm = bearer_map(headers).ok_or(ApiError::Unauthorized)?;
    match fetch_identity(state, hm).await {
        Ok(u) => {
            let rep = sync_user_to_gateway_db(state, &u).await;
            Ok(Json(ApiResponse::success(to_user_response_with_rep(u, rep))))
        }
        Err(code) => Err(map_auth_status(code)),
    }
}
