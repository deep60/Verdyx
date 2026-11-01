use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use ethers::core::types::Signature;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

use crate::config::JwtConfig;
use crate::models::{UserError, UserResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub email: String,
    pub username: String,
    pub is_admin: bool,
    pub exp: i64,           // Expiry timestamp
    pub iat: i64,           // Issued at timestamp
    pub token_type: String, // "access" or "refresh"
}

pub struct AuthService {
    jwt_config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    pub fn new(jwt_config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(jwt_config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(jwt_config.secret.as_bytes());

        Self {
            jwt_config,
            encoding_key,
            decoding_key,
        }
    }

    /// Hash a password using Argon2
    pub fn hash_password(&self, password: &str) -> UserResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| UserError::ValidationError(format!("Failed to hash password: {e}")))?
            .to_string();

        Ok(password_hash)
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, password_hash: &str) -> UserResult<bool> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| UserError::ValidationError(format!("Invalid password hash: {e}")))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Generate an access token
    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: &str,
        username: &str,
        is_admin: bool,
    ) -> UserResult<String> {
        let now = Utc::now();
        let expiry = now + Duration::hours(self.jwt_config.access_token_expiry_hours as i64);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            username: username.to_string(),
            is_admin,
            exp: expiry.timestamp(),
            iat: now.timestamp(),
            token_type: "access".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| UserError::AuthenticationError(format!("Failed to generate token: {e}")))
    }

    /// Generate a refresh token
    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        email: &str,
        username: &str,
        is_admin: bool,
    ) -> UserResult<String> {
        let now = Utc::now();
        let expiry = now + Duration::days(self.jwt_config.refresh_token_expiry_days as i64);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            username: username.to_string(),
            is_admin,
            exp: expiry.timestamp(),
            iat: now.timestamp(),
            token_type: "refresh".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key).map_err(|e| {
            UserError::AuthenticationError(format!("Failed to generate refresh token: {e}"))
        })
    }

    /// Validate and decode a token
    pub fn validate_token(&self, token: &str) -> UserResult<Claims> {
        let validation = Validation::default();

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|_e| UserError::InvalidToken)
    }

    /// Verify Ethereum wallet signature
    pub fn verify_wallet_signature(
        &self,
        message: &str,
        signature: &str,
        expected_address: &str,
    ) -> UserResult<bool> {
        // Parse the signature
        let sig = Signature::from_str(signature)
            .map_err(|e| UserError::ValidationError(format!("Invalid signature format: {e}")))?;

        // Recover the address from the signature
        let recovered_address = sig
            .recover(message)
            .map_err(|e| UserError::ValidationError(format!("Failed to recover address: {e}")))?;

        // Compare with expected address (case-insensitive)
        let recovered_str = format!("{recovered_address:?}").to_lowercase();
        let expected_str = expected_address.to_lowercase();

        Ok(recovered_str == expected_str)
    }

    /// Generate a verification token for email/password reset
    pub fn generate_verification_token(&self) -> String {
        use rand::RngExt;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const TOKEN_LEN: usize = 32;
        let mut rng = rand::rng();

        (0..TOKEN_LEN)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate a 2FA secret
    pub fn generate_2fa_secret(&self) -> String {
        use base32::Alphabet;
        use rand::RngExt;

        let secret: Vec<u8> = (0..20).map(|_| rand::rng().random()).collect();
        base32::encode(Alphabet::Rfc4648 { padding: false }, &secret)
    }

    /// Verify a 2FA code
    pub fn verify_2fa_code(&self, secret: &str, code: &str) -> UserResult<bool> {
        use totp_lite::{totp_custom, Sha1};

        let time_step = 30; // 30 seconds
        let current_time = Utc::now().timestamp() as u64;

        // Decode the base32 secret
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| UserError::ValidationError("Invalid 2FA secret".to_string()))?;

        // Generate current TOTP code
        let expected_code = totp_custom::<Sha1>(time_step, 6, &secret_bytes, current_time);

        // Also check the previous and next time windows for clock drift
        let prev_code = totp_custom::<Sha1>(time_step, 6, &secret_bytes, current_time - time_step);
        let next_code = totp_custom::<Sha1>(time_step, 6, &secret_bytes, current_time + time_step);

        Ok(code == expected_code || code == prev_code || code == next_code)
    }

    /// Get token expiry time in seconds
    pub fn get_access_token_expiry(&self) -> u64 {
        self.jwt_config.access_token_expiry_hours * 3600
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_jwt_config() -> JwtConfig {
        JwtConfig {
            secret: "test_secret_key_for_testing_only".to_string(),
            access_token_expiry_hours: 24,
            refresh_token_expiry_days: 30,
        }
    }

    #[test]
    fn test_password_hashing() {
        let auth_service = AuthService::new(get_test_jwt_config());
        let password = "SecurePassword123!";

        let hash = auth_service.hash_password(password).unwrap();
        assert!(auth_service.verify_password(password, &hash).unwrap());
        assert!(!auth_service
            .verify_password("WrongPassword", &hash)
            .unwrap());
    }

    #[test]
    fn test_token_generation_and_validation() {
        let auth_service = AuthService::new(get_test_jwt_config());
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let username = "testuser";

        let token = auth_service
            .generate_access_token(user_id, email, username, false)
            .unwrap();

        let claims = auth_service.validate_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_verification_token_generation() {
        let auth_service = AuthService::new(get_test_jwt_config());
        let token = auth_service.generate_verification_token();

        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    // Minted by this code while it was on jsonwebtoken 9.3.1, signed with the
    // `get_test_jwt_config` secret and expiring in 2126. Do not regenerate them: they prove that
    // tokens issued before the upgrade to 10.x stay valid.
    const ACCESS_TOKEN_9_3: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6ImZpeHR1cmUiLCJpc19hZG1pbiI6ZmFsc2UsImV4cCI6NDk0NzE0NTA3NywiaWF0IjoxNzkzNTQ1MDc3LCJ0b2tlbl90eXBlIjoiYWNjZXNzIn0.a-o2vEyBvgTpjdhyXM3UZqVGGq9flKjlY7VpiPMNwT8"; // gitleaks:allow
    const REFRESH_TOKEN_9_3: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6ImZpeHR1cmUiLCJpc19hZG1pbiI6ZmFsc2UsImV4cCI6NDk0NzE0NTA3NywiaWF0IjoxNzkzNTQ1MDc3LCJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.Tk35zi1RYDdWYjRCn0NyftenUcrO1a68bz6i8zKGFyc"; // gitleaks:allow

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
            "email": "test@example.com",
            "username": "testuser",
            "is_admin": false,
            "exp": (Utc::now() + Duration::hours(1)).timestamp(),
            "iat": Utc::now().timestamp(),
            "token_type": "access",
        })
    }

    #[test]
    fn test_accepts_tokens_issued_before_upgrade() {
        let auth_service = AuthService::new(get_test_jwt_config());

        let access = auth_service.validate_token(ACCESS_TOKEN_9_3).unwrap();
        assert_eq!(access.sub, "11111111-1111-4111-8111-111111111111");
        assert_eq!(access.email, "user@example.com");
        assert_eq!(access.token_type, "access");

        let refresh = auth_service.validate_token(REFRESH_TOKEN_9_3).unwrap();
        assert_eq!(refresh.sub, access.sub);
        assert_eq!(refresh.token_type, "refresh");
    }

    /// Claims of the wrong JSON type (GHSA-h395-gr6q-cpjc) must be rejected,
    /// not treated as absent.
    #[test]
    fn test_rejects_claims_of_wrong_type() {
        let config = get_test_jwt_config();
        let auth_service = AuthService::new(get_test_jwt_config());
        assert!(auth_service
            .validate_token(&sign(&valid_claims(), &config.secret))
            .is_ok());

        for (claim, bad_value) in [
            ("exp", serde_json::json!("99999999999")),
            ("exp", serde_json::json!(null)),
            ("exp", serde_json::json!(9_999_999_999.5)),
            ("iat", serde_json::json!("now")),
            ("sub", serde_json::json!(1)),
            ("is_admin", serde_json::json!("true")),
            ("token_type", serde_json::json!(1)),
        ] {
            let mut claims = valid_claims();
            claims[claim] = bad_value.clone();
            assert!(
                auth_service
                    .validate_token(&sign(&claims, &config.secret))
                    .is_err(),
                "accepted {claim} = {bad_value}"
            );
        }
    }

    #[test]
    fn test_rejects_expired_token() {
        let config = get_test_jwt_config();
        let mut claims = valid_claims();
        claims["exp"] = (Utc::now() - Duration::hours(1)).timestamp().into();
        assert!(AuthService::new(get_test_jwt_config())
            .validate_token(&sign(&claims, &config.secret))
            .is_err());
    }

    #[test]
    fn test_rejects_token_signed_with_another_key() {
        let token = sign(&valid_claims(), "another_secret_key_of_the_same_size");
        assert!(AuthService::new(get_test_jwt_config())
            .validate_token(&token)
            .is_err());
    }
}
