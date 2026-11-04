use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::middleware::auth::Claims;
use crate::models::user::User;

/// Authentication service for handling user authentication, JWT tokens, and sessions
#[derive(Clone)]
pub struct AuthService {
    jwt_secret: String,
    access_token_expiry_hours: i64,
    refresh_token_expiry_days: i64,
}

/// Password reset token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Email verification token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationToken {
    pub user_id: Uuid,
    pub email: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Refresh token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub device_info: Option<String>,
}

/// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub token_type: String,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            access_token_expiry_hours: 24, // 24 hours for access tokens
            refresh_token_expiry_days: 30, // 30 days for refresh tokens
        }
    }

    /// Hash a password using Argon2
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?
            .to_string();

        Ok(password_hash)
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| anyhow::anyhow!("Invalid password hash: {e}"))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Generate JWT access token
    pub fn generate_access_token(&self, user: &User) -> Result<String> {
        let role = if user.is_engine { "engine" } else { "user" };

        let claims = Claims::new(
            user.id,
            user.email.clone(),
            role.to_string(),
            self.access_token_expiry_hours,
        );

        let encoding_key = EncodingKey::from_secret(self.jwt_secret.as_bytes());

        encode(&Header::default(), &claims, &encoding_key).context("Failed to encode JWT token")
    }

    /// Generate refresh token
    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        device_info: Option<String>,
    ) -> RefreshToken {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::days(self.refresh_token_expiry_days);

        RefreshToken {
            user_id,
            token,
            expires_at,
            device_info,
        }
    }

    /// Validate JWT access token
    pub fn validate_access_token(&self, token: &str) -> Result<Claims> {
        let decoding_key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let validation = Validation::default();

        let token_data = decode::<Claims>(token, &decoding_key, &validation)
            .context("Failed to decode JWT token")?;

        // Additional validation
        if !token_data.claims.is_valid_now() {
            return Err(anyhow::anyhow!("Token has expired"));
        }

        Ok(token_data.claims)
    }

    /// Create complete authentication response
    pub fn create_auth_response(
        &self,
        user: &User,
        device_info: Option<String>,
    ) -> Result<AuthResponse> {
        let access_token = self.generate_access_token(user)?;
        let refresh_token = self.generate_refresh_token(user.id, device_info);

        Ok(AuthResponse {
            access_token,
            refresh_token: refresh_token.token,
            expires_at: Utc::now() + Duration::hours(self.access_token_expiry_hours),
            token_type: "Bearer".to_string(),
        })
    }

    /// Generate password reset token
    pub fn generate_password_reset_token(&self, user_id: Uuid) -> PasswordResetToken {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::hours(24); // 24 hours

        PasswordResetToken {
            user_id,
            token,
            expires_at,
        }
    }

    /// Generate email verification token
    pub fn generate_email_verification_token(
        &self,
        user_id: Uuid,
        email: String,
    ) -> EmailVerificationToken {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::days(7); // 7 days

        EmailVerificationToken {
            user_id,
            email,
            token,
            expires_at,
        }
    }

    /// Validate password reset token (checks expiry)
    pub fn validate_password_reset_token(&self, token: &PasswordResetToken) -> bool {
        token.expires_at > Utc::now()
    }

    /// Validate email verification token (checks expiry)
    pub fn validate_email_verification_token(&self, token: &EmailVerificationToken) -> bool {
        token.expires_at > Utc::now()
    }

    /// Validate password strength
    pub fn validate_password_strength(&self, password: &str) -> Result<()> {
        if password.len() < 8 {
            return Err(anyhow::anyhow!(
                "Password must be at least 8 characters long"
            ));
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if !has_uppercase {
            return Err(anyhow::anyhow!(
                "Password must contain at least one uppercase letter"
            ));
        }

        if !has_lowercase {
            return Err(anyhow::anyhow!(
                "Password must contain at least one lowercase letter"
            ));
        }

        if !has_digit {
            return Err(anyhow::anyhow!("Password must contain at least one digit"));
        }

        if !has_special {
            return Err(anyhow::anyhow!(
                "Password must contain at least one special character"
            ));
        }

        Ok(())
    }

    /// Extract bearer token from authorization header
    pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
        auth_header.strip_prefix("Bearer ")
    }

    /// Generate API key for programmatic access
    pub fn generate_api_key(&self) -> String {
        format!("nxs_{}", Uuid::new_v4().simple())
    }

    /// Validate API key format
    pub fn validate_api_key_format(&self, api_key: &str) -> bool {
        api_key.starts_with("nxs_") && api_key.len() == 36
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let auth_service = AuthService::new("test_secret_key".to_string());
        let password = "SecurePassword123!";

        let hash = auth_service.hash_password(password).unwrap();
        assert!(auth_service.verify_password(password, &hash).unwrap());
        assert!(!auth_service
            .verify_password("WrongPassword", &hash)
            .unwrap());
    }

    #[test]
    fn test_password_strength_validation() {
        let auth_service = AuthService::new("test_secret_key".to_string());

        // Valid password
        assert!(auth_service
            .validate_password_strength("SecurePass123!")
            .is_ok());

        // Too short
        assert!(auth_service.validate_password_strength("Short1!").is_err());

        // No uppercase
        assert!(auth_service
            .validate_password_strength("password123!")
            .is_err());

        // No lowercase
        assert!(auth_service
            .validate_password_strength("PASSWORD123!")
            .is_err());

        // No digit
        assert!(auth_service
            .validate_password_strength("SecurePass!")
            .is_err());

        // No special char
        assert!(auth_service
            .validate_password_strength("SecurePass123")
            .is_err());
    }

    #[test]
    fn test_jwt_token_generation_and_validation() {
        let auth_service = AuthService::new("test_secret_key_at_least_32_chars_long".to_string());
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            Some("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".to_string()),
        );

        let token = auth_service.generate_access_token(&user).unwrap();
        let claims = auth_service.validate_access_token(&token).unwrap();

        assert_eq!(claims.email, user.email);
        assert_eq!(claims.sub, user.id);
    }

    #[test]
    fn test_api_key_generation_and_validation() {
        let auth_service = AuthService::new("test_secret_key".to_string());
        let api_key = auth_service.generate_api_key();

        assert!(auth_service.validate_api_key_format(&api_key));
        assert!(api_key.starts_with("nxs_"));
        assert_eq!(api_key.len(), 36);
    }

    #[test]
    fn test_extract_bearer_token() {
        let header = "Bearer abc123xyz";
        assert_eq!(AuthService::extract_bearer_token(header), Some("abc123xyz"));

        let invalid_header = "abc123xyz";
        assert_eq!(AuthService::extract_bearer_token(invalid_header), None);
    }

    const JWT_TEST_SECRET: &str = "test_secret_key_for_testing_only";

    // Minted by this code while it was on jsonwebtoken 9.3.1, signed with
    // JWT_TEST_SECRET and expiring in 2126. Do not regenerate them: they prove that
    // tokens issued before the upgrade to 10.x stay valid.
    const ACCESS_TOKEN_9_3: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmZWZjYmM5NC1kYmFhLTQ3YTYtOWNhNS0wZDIwNWRlMjhhMGIiLCJlbWFpbCI6InNlcnZpY2VAZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciIsImV4cCI6NDk0NzE0NDkxNCwiaWF0IjoxNzkzNTQ0OTE0LCJuYmYiOjE3OTM1NDQ5MTQsImp0aSI6IjMyN2JkNzM0LTIzODAtNGMyMC05YmQyLWRjNWY3MDNlZjA4YyIsImlzX2FkbWluIjpmYWxzZSwidXNlcm5hbWUiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIn0.HlLOmZwzn8dJq-jLN9Dr2qc7oqbAOLcSk7oJhZDl61Y"; // gitleaks:allow

    fn sign(claims: &serde_json::Value, secret: &str) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": Uuid::new_v4().to_string(),
            "email": "u@example.com",
            "exp": (Utc::now() + Duration::hours(1)).timestamp(),
        })
    }

    #[test]
    fn test_accepts_access_token_issued_before_upgrade() {
        let service = AuthService::new(JWT_TEST_SECRET.to_string());
        let claims = service.validate_access_token(ACCESS_TOKEN_9_3).unwrap();
        assert_eq!(claims.email, "service@example.com");
        assert_eq!(claims.role, "user");
    }

    #[test]
    fn test_rejects_invalid_access_tokens() {
        let service = AuthService::new(JWT_TEST_SECRET.to_string());
        assert!(service
            .validate_access_token(&sign(&valid_claims(), JWT_TEST_SECRET))
            .is_ok());

        let mut wrong_type = valid_claims();
        wrong_type["exp"] = "99999999999".into();
        assert!(service
            .validate_access_token(&sign(&wrong_type, JWT_TEST_SECRET))
            .is_err());

        let mut wrong_type_nbf = valid_claims();
        wrong_type_nbf["nbf"] = "99999999999".into();
        assert!(service
            .validate_access_token(&sign(&wrong_type_nbf, JWT_TEST_SECRET))
            .is_err());

        let mut expired = valid_claims();
        expired["exp"] = (Utc::now() - Duration::hours(1)).timestamp().into();
        assert!(service
            .validate_access_token(&sign(&expired, JWT_TEST_SECRET))
            .is_err());

        assert!(service
            .validate_access_token(&sign(
                &valid_claims(),
                "another_secret_key_of_the_same_size"
            ))
            .is_err());
    }
}
