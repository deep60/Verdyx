use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::error::ApiError;
use crate::AppState;

/// JWT Claims structure.
///
/// Fields are tolerant of tokens minted by `user-service` (the auth authority
/// under the microservices design), which omit `role`/`nbf`/`jti` and instead
/// carry `is_admin`/`username`/`token_type`. `#[serde(default)]` lets a single
/// validator accept tokens from either source as long as the JWT secret matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,     // Subject (user ID) — decodes from a UUID string
    pub email: String, // User email
    #[serde(default = "default_role")]
    pub role: String, // User role (gateway-minted tokens)
    pub exp: i64,      // Expiration time
    #[serde(default)]
    pub iat: i64, // Issued at
    #[serde(default)]
    pub nbf: i64, // Not before
    #[serde(default)]
    pub jti: String, // JWT ID
    #[serde(default)]
    pub is_admin: bool, // Admin flag (user-service tokens)
    #[serde(default)]
    pub username: String, // Username (user-service tokens)
    #[serde(default)]
    pub token_type: String, // "access" | "refresh" (user-service tokens)
}

fn default_role() -> String {
    "user".to_string()
}

impl Claims {
    pub fn new(user_id: Uuid, email: String, role: String, expires_in_hours: i64) -> Self {
        let now = Utc::now();
        let expiration = now + Duration::hours(expires_in_hours);

        Self {
            sub: user_id,
            is_admin: role == "admin",
            email,
            role,
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            username: String::new(),
            token_type: "access".to_string(),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.nbf && now < self.exp
    }
}

/// JWT token generation and validation
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtService {
    pub fn new(secret: &str) -> Self {
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        let validation = Validation::default();

        Self {
            encoding_key,
            decoding_key,
            validation,
        }
    }

    pub fn generate_token(&self, claims: &Claims) -> Result<String, ApiError> {
        encode(&Header::default(), claims, &self.encoding_key)
            .map_err(|e| ApiError::Internal(format!("Failed to generate token: {e}")))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, ApiError> {
        let claims = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| ApiError::Unauthorized(format!("Invalid token: {e}")))?;

        // user-service mints both access and refresh tokens with the same
        // secret; only access tokens may authorize API requests.
        if claims.token_type == "refresh" {
            return Err(ApiError::Unauthorized(
                "Refresh token cannot be used for authorization".to_string(),
            ));
        }

        Ok(claims)
    }

    pub fn refresh_token(&self, old_claims: &Claims) -> Result<String, ApiError> {
        // Create new claims with extended expiration
        let new_claims = Claims::new(
            old_claims.sub,
            old_claims.email.clone(),
            old_claims.role.clone(),
            24, // 24 hours
        );

        self.generate_token(&new_claims)
    }
}

/// Authentication middleware
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];

            // Recreate JwtService here (in production, this should ideally be in AppState but for now we create it on fly or cached)
            // However, JwtService construction is cheap (key derivation), or we can move it to AppState.
            // Since AppState doesn't have it, we'll verify using the secret from config.

            // NOTE: Ideally JwtService should be in AppState to avoid re-hashing key.
            // But for this refactor, we instantiate it.
            let jwt_service = JwtService::new(&state.config.security.jwt_secret);

            match jwt_service.validate_token(token) {
                Ok(claims) => {
                    request.extensions_mut().insert(claims);
                    Ok(next.run(request).await)
                }
                Err(_) => Err(StatusCode::UNAUTHORIZED),
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Optional authentication middleware (doesn't fail on missing token)
pub async fn optional_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Extract authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            let jwt_service = JwtService::new(&state.config.security.jwt_secret);

            if let Ok(claims) = jwt_service.validate_token(token) {
                request.extensions_mut().insert(claims);
            }
        }
    }

    next.run(request).await
}

/// Admin role middleware (must be used after auth_middleware)
pub async fn require_admin(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let claims = request
        .extensions()
        .get::<Claims>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if claims.role != "admin" && claims.role != "moderator" && !claims.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// API key authentication middleware
pub async fn api_key_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check for API key in header
    let api_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !api_key.starts_with("nxs_") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Hash the API key and look it up in the database
    use sha2::{Digest, Sha256};
    let key_hash = hex::encode(Sha256::digest(api_key.as_bytes()));

    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        r#"SELECT u.id, u.email, u.role
           FROM api_keys ak
           JOIN users u ON u.id = ak.user_id
           WHERE ak.key_hash = $1
             AND ak.is_active = TRUE
             AND (ak.expires_at IS NULL OR ak.expires_at > NOW())"#,
    )
    .bind(&key_hash)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("API key lookup failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (user_id, email, role) = row.ok_or(StatusCode::UNAUTHORIZED)?;

    // Update last_used_at
    let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1")
        .bind(&key_hash)
        .execute(state.db.pool())
        .await;

    let claims = Claims {
        sub: user_id,
        is_admin: role == "admin",
        email,
        role,
        exp: (Utc::now() + Duration::hours(24)).timestamp(),
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        jti: Uuid::new_v4().to_string(),
        username: String::new(),
        token_type: "access".to_string(),
    };

    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Extractor for authenticated user claims
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

impl<S> axum::extract::OptionalFromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Claims>().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new(
            Uuid::new_v4(),
            "test@example.com".to_string(),
            "user".to_string(),
            24,
        );

        assert!(!claims.is_expired());
        assert!(claims.is_valid_now());
    }

    #[test]
    fn test_jwt_service() {
        let jwt_service = JwtService::new("test_secret_key_at_least_32_chars");
        let claims = Claims::new(
            Uuid::new_v4(),
            "test@example.com".to_string(),
            "user".to_string(),
            24,
        );

        let token = jwt_service.generate_token(&claims).unwrap();
        assert!(!token.is_empty());

        let validated_claims = jwt_service.validate_token(&token).unwrap();
        assert_eq!(validated_claims.email, "test@example.com");
    }

    /// The gateway must accept access tokens minted by user-service, which use
    /// a different claim shape (no role/nbf/jti; carries is_admin/token_type).
    #[test]
    fn test_validates_user_service_token_shape() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct UsClaims {
            sub: String,
            email: String,
            username: String,
            is_admin: bool,
            exp: i64,
            iat: i64,
            token_type: String,
        }

        let secret = "shared_secret_at_least_32_chars_long";
        let uid = Uuid::new_v4();
        let us = UsClaims {
            sub: uid.to_string(),
            email: "u@example.com".to_string(),
            username: "u".to_string(),
            is_admin: true,
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            iat: Utc::now().timestamp(),
            token_type: "access".to_string(),
        };
        let token = encode(
            &Header::default(),
            &us,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let claims = JwtService::new(secret).validate_token(&token).unwrap();
        assert_eq!(claims.sub, uid);
        assert_eq!(claims.email, "u@example.com");
        assert!(claims.is_admin);
        assert_eq!(claims.role, "user"); // defaulted when absent
    }

    /// Refresh tokens (token_type = "refresh") must not authorize requests.
    #[test]
    fn test_rejects_refresh_token() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct UsClaims {
            sub: String,
            email: String,
            exp: i64,
            token_type: String,
        }

        let secret = "shared_secret_at_least_32_chars_long";
        let us = UsClaims {
            sub: Uuid::new_v4().to_string(),
            email: "u@example.com".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            token_type: "refresh".to_string(),
        };
        let token = encode(
            &Header::default(),
            &us,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        assert!(JwtService::new(secret).validate_token(&token).is_err());
    }
}
