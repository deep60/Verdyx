use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{Duration, Utc};
use hex;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use ring::{
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid hash format")]
    InvalidHashFormat,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Random generation failed")]
    RandomGenerationFailed,
}

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResult {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairInfo {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

/// Hash utilities for file and data integrity verification
pub struct HashUtils;

impl HashUtils {
    /// Generate SHA-256 hash of data
    pub fn sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Generate MD5 hash of data (for compatibility, though deprecated for security)
    pub fn md5(data: &[u8]) -> String {
        let digest = md5::compute(data);
        format!("{digest:x}")
    }

    /// Generate SHA-1 hash of data
    pub fn sha1(data: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Generate multiple hashes at once for comprehensive file fingerprinting
    pub fn multi_hash(data: &[u8]) -> HashResult {
        HashResult {
            sha256: Self::sha256(data),
            md5: Self::md5(data),
            sha1: Self::sha1(data),
        }
    }

    /// Verify if a hash matches the expected value
    pub fn verify_sha256(data: &[u8], expected_hash: &str) -> bool {
        let computed_hash = Self::sha256(data);
        computed_hash.eq_ignore_ascii_case(expected_hash)
    }
}

/// Digital signature utilities for API authentication and data integrity
pub struct SignatureUtils;

impl SignatureUtils {
    /// Generate a new Ed25519 key pair
    pub fn generate_keypair() -> CryptoResult<KeyPairInfo> {
        let rng = SystemRandom::new();
        let keypair_doc =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| CryptoError::KeyGenerationFailed)?;

        let keypair = Ed25519KeyPair::from_pkcs8(keypair_doc.as_ref())
            .map_err(|_| CryptoError::KeyGenerationFailed)?;

        let public_key = BASE64.encode(keypair.public_key().as_ref());
        let private_key = BASE64.encode(keypair_doc.as_ref());

        Ok(KeyPairInfo {
            public_key,
            private_key,
        })
    }

    /// Sign a message with a private key
    pub fn sign_message(private_key_b64: &str, message: &[u8]) -> CryptoResult<String> {
        let private_key_bytes = BASE64
            .decode(private_key_b64)
            .map_err(|_| CryptoError::InvalidKeyFormat)?;

        let keypair = Ed25519KeyPair::from_pkcs8(&private_key_bytes)
            .map_err(|_| CryptoError::InvalidKeyFormat)?;

        let signature = keypair.sign(message);
        Ok(BASE64.encode(signature.as_ref()))
    }

    /// Verify a signature
    pub fn verify_signature(
        public_key_b64: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> CryptoResult<bool> {
        let public_key_bytes = BASE64
            .decode(public_key_b64)
            .map_err(|_| CryptoError::InvalidKeyFormat)?;

        let signature_bytes = BASE64
            .decode(signature_b64)
            .map_err(|_| CryptoError::InvalidSignature)?;

        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);

        match public_key.verify(message, &signature_bytes) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create a signature info struct for API responses
    pub fn create_signature_info(
        private_key_b64: &str,
        message: &str,
    ) -> CryptoResult<SignatureInfo> {
        let message_bytes = message.as_bytes();
        let signature = Self::sign_message(private_key_b64, message_bytes)?;

        let keypair_bytes = BASE64
            .decode(private_key_b64)
            .map_err(|_| CryptoError::InvalidKeyFormat)?;
        let keypair = Ed25519KeyPair::from_pkcs8(&keypair_bytes)
            .map_err(|_| CryptoError::InvalidKeyFormat)?;
        let public_key = BASE64.encode(keypair.public_key().as_ref());

        Ok(SignatureInfo {
            signature,
            public_key,
            message: message.to_string(),
        })
    }
}

/// Password and secret management utilities
pub struct SecretUtils;

impl SecretUtils {
    const PBKDF2_ROUNDS: u32 = 100_000;
    const SALT_LENGTH: usize = 32;
    const KEY_LENGTH: usize = 32;

    /// Generate a random salt
    pub fn generate_salt() -> CryptoResult<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut salt = vec![0u8; Self::SALT_LENGTH];
        rng.fill(&mut salt)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(salt)
    }

    /// Hash a password with PBKDF2
    pub fn hash_password(password: &str, salt: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hash = vec![0u8; Self::KEY_LENGTH];
        let rounds = NonZeroU32::new(Self::PBKDF2_ROUNDS).unwrap();

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            salt,
            password.as_bytes(),
            &mut hash,
        );

        Ok(hash)
    }

    /// Verify a password against its hash
    pub fn verify_password(password: &str, salt: &[u8], expected_hash: &[u8]) -> bool {
        let computed_hash = match Self::hash_password(password, salt) {
            Ok(hash) => hash,
            Err(_) => return false,
        };

        // Constant-time comparison to prevent timing attacks.
        // Avoids the deprecated `ring::constant_time` module; this manual
        // implementation runs in time proportional to the input length only.
        if computed_hash.len() != expected_hash.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in computed_hash.iter().zip(expected_hash.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Generate a secure random token
    pub fn generate_token(length: usize) -> CryptoResult<String> {
        let rng = SystemRandom::new();
        let mut token = vec![0u8; length];
        rng.fill(&mut token)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(hex::encode(token))
    }

    /// Generate an API key
    pub fn generate_api_key() -> CryptoResult<String> {
        Self::generate_token(32)
    }
}

/// Ethereum address and blockchain-related crypto utilities
pub struct BlockchainUtils;

impl BlockchainUtils {
    /// Validate Ethereum address format
    pub fn is_valid_ethereum_address(address: &str) -> bool {
        if !address.starts_with("0x") {
            return false;
        }

        let addr_without_prefix = &address[2..];
        if addr_without_prefix.len() != 40 {
            return false;
        }

        addr_without_prefix.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Convert address to checksum format (EIP-55)
    pub fn to_checksum_address(address: &str) -> CryptoResult<String> {
        if !Self::is_valid_ethereum_address(address) {
            return Err(CryptoError::InvalidHashFormat);
        }

        let addr_lower = address[2..].to_lowercase();
        let hash = Self::keccak256(addr_lower.as_bytes());
        let hash_hex = hex::encode(hash);

        let mut checksum = String::from("0x");
        for (i, c) in addr_lower.chars().enumerate() {
            if c.is_ascii_digit() {
                checksum.push(c);
            } else {
                let hash_char = hash_hex.chars().nth(i).unwrap();
                if hash_char >= '8' {
                    checksum.push(c.to_uppercase().next().unwrap());
                } else {
                    checksum.push(c);
                }
            }
        }

        Ok(checksum)
    }

    /// Keccak256 hash (used by Ethereum)
    pub fn keccak256(data: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Generate a message hash for Ethereum signing
    pub fn ethereum_message_hash(message: &str) -> Vec<u8> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut full_message = prefix.into_bytes();
        full_message.extend_from_slice(message.as_bytes());
        Self::keccak256(&full_message)
    }
}

/// General crypto utilities
pub struct CryptoUtils;

impl CryptoUtils {
    /// Generate a cryptographically secure UUID v4
    pub fn generate_uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Generate a nonce for preventing replay attacks
    pub fn generate_nonce() -> CryptoResult<u64> {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 8];
        rng.fill(&mut bytes)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Create a timestamped hash for submission tracking
    pub fn create_submission_id(user_id: &str, file_hash: &str, timestamp: i64) -> String {
        let data = format!("{user_id}:{file_hash}:{timestamp}");
        HashUtils::sha256(data.as_bytes())
    }

    /// Validate hex string format
    pub fn is_valid_hex(s: &str) -> bool {
        s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Convert bytes to human readable size
    pub fn bytes_to_human_readable(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        const THRESHOLD: f64 = 1024.0;

        if bytes == 0 {
            return "0 B".to_string();
        }

        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
            size /= THRESHOLD;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }
}

// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // Subject (user ID)
    pub exp: usize,  // Expiration time
    pub iat: usize,  // Issued at
    pub user_id: String,
    pub wallet_address: Option<String>,
}

/// JWT token utilities
pub fn validate_jwt(token: &str, secret: &str) -> CryptoResult<JwtClaims> {
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::default();

    match decode::<JwtClaims>(token, &key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(_) => Err(CryptoError::InvalidSignature),
    }
}

/// Generate JWT token
pub fn generate_jwt(
    user_id: &str,
    wallet_address: Option<String>,
    secret: &str,
) -> CryptoResult<String> {
    let now = Utc::now();
    let exp = now + Duration::hours(24); // Token expires in 24 hours

    let claims = JwtClaims {
        sub: user_id.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        user_id: user_id.to_string(),
        wallet_address,
    };

    let key = EncodingKey::from_secret(secret.as_ref());
    match encode(&Header::default(), &claims, &key) {
        Ok(token) => Ok(token),
        Err(_) => Err(CryptoError::KeyGenerationFailed),
    }
}

/// Calculate SHA256 for file uploads (alias for main function)
pub fn calculate_sha256(data: &[u8]) -> String {
    HashUtils::sha256(data)
}

/// Calculate file hash for uploads (alias)
pub fn calculate_file_hash(data: &[u8]) -> String {
    HashUtils::sha256(data)
}

/// Hash password using bcrypt
pub fn hash_password(password: &str) -> CryptoResult<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|_| CryptoError::EncryptionFailed)
}

/// Verify password using bcrypt
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    bcrypt::verify(password, hash).map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"Hello, Verdyx!";
        let hash = HashUtils::sha256(data);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = SignatureUtils::generate_keypair().unwrap();
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.private_key.is_empty());
    }

    #[test]
    fn test_signature_verification() {
        let keypair = SignatureUtils::generate_keypair().unwrap();
        let message = b"Test message";
        let signature = SignatureUtils::sign_message(&keypair.private_key, message).unwrap();
        let is_valid =
            SignatureUtils::verify_signature(&keypair.public_key, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_ethereum_address_validation() {
        assert!(BlockchainUtils::is_valid_ethereum_address(
            "0x742d35Cc6435C2cb62fb0CF4cE385FA4d8457B5a"
        ));
        assert!(!BlockchainUtils::is_valid_ethereum_address(
            "invalid_address"
        ));
        assert!(!BlockchainUtils::is_valid_ethereum_address("0x123")); // Too short
    }

    #[test]
    fn test_password_hashing() {
        let password = "secure_password_123";
        let salt = SecretUtils::generate_salt().unwrap();
        let hash = SecretUtils::hash_password(password, &salt).unwrap();

        assert!(SecretUtils::verify_password(password, &salt, &hash));
        assert!(!SecretUtils::verify_password(
            "wrong_password",
            &salt,
            &hash
        ));
    }

    #[test]
    fn test_multi_hash() {
        let data = b"Verdyx test data";
        let hashes = HashUtils::multi_hash(data);

        assert_eq!(hashes.sha256.len(), 64);
        assert_eq!(hashes.md5.len(), 32);
        assert_eq!(hashes.sha1.len(), 40);
    }

    #[test]
    fn test_bytes_to_human_readable() {
        assert_eq!(CryptoUtils::bytes_to_human_readable(0), "0 B");
        assert_eq!(CryptoUtils::bytes_to_human_readable(1024), "1.00 KB");
        assert_eq!(CryptoUtils::bytes_to_human_readable(1536), "1.50 KB");
        assert_eq!(CryptoUtils::bytes_to_human_readable(1048576), "1.00 MB");
    }

    const JWT_TEST_SECRET: &str = "test_secret_key_for_testing_only";

    // Minted by the `JwtClaims` encoding on jsonwebtoken 9.3.1, signed with
    // JWT_TEST_SECRET and expiring in 2126. Do not regenerate them: they prove that
    // tokens issued before the upgrade to 10.x stay valid.
    const JWT_TOKEN_9_3: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJleHAiOjQ5NDcxNDQ5MTQsImlhdCI6MTc5MzU0NDkxNCwidXNlcl9pZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsIndhbGxldF9hZGRyZXNzIjpudWxsfQ.OTRqMYvdbQUxRrjEIz8bCU1eyzA0nNge-jscYf4f14A"; // gitleaks:allow

    fn sign_jwt(claims: &serde_json::Value, secret: &str) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn valid_jwt_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "user-1",
            "exp": (Utc::now() + Duration::hours(1)).timestamp(),
            "iat": Utc::now().timestamp(),
            "user_id": "user-1",
            "wallet_address": null,
        })
    }

    #[test]
    fn test_validate_jwt_accepts_token_issued_before_upgrade() {
        let claims = validate_jwt(JWT_TOKEN_9_3, JWT_TEST_SECRET).unwrap();
        assert_eq!(claims.sub, "11111111-1111-4111-8111-111111111111");
        assert_eq!(claims.user_id, claims.sub);
    }

    #[test]
    fn test_validate_jwt_accepts_freshly_generated_token() {
        let token = generate_jwt("user-1", None, JWT_TEST_SECRET).unwrap();
        assert_eq!(validate_jwt(&token, JWT_TEST_SECRET).unwrap().sub, "user-1");
    }

    #[test]
    fn test_validate_jwt_rejects_claims_of_wrong_type() {
        assert!(validate_jwt(
            &sign_jwt(&valid_jwt_claims(), JWT_TEST_SECRET),
            JWT_TEST_SECRET
        )
        .is_ok());

        for (claim, bad_value) in [
            ("exp", serde_json::json!("99999999999")),
            ("exp", serde_json::json!(null)),
            ("iat", serde_json::json!("now")),
            ("sub", serde_json::json!(1)),
            ("user_id", serde_json::json!(1)),
        ] {
            let mut claims = valid_jwt_claims();
            claims[claim] = bad_value.clone();
            assert!(
                validate_jwt(&sign_jwt(&claims, JWT_TEST_SECRET), JWT_TEST_SECRET).is_err(),
                "accepted {claim} = {bad_value}"
            );
        }
    }

    #[test]
    fn test_validate_jwt_rejects_expired_token() {
        let mut claims = valid_jwt_claims();
        claims["exp"] = (Utc::now() - Duration::hours(1)).timestamp().into();
        assert!(validate_jwt(&sign_jwt(&claims, JWT_TEST_SECRET), JWT_TEST_SECRET).is_err());
    }

    #[test]
    fn test_validate_jwt_rejects_token_signed_with_another_key() {
        let token = sign_jwt(&valid_jwt_claims(), "another_secret_key_of_the_same_size");
        assert!(validate_jwt(&token, JWT_TEST_SECRET).is_err());
    }
}
