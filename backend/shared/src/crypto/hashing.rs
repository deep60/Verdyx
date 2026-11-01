//! Secure hashing functions for passwords, data integrity, and identifiers

use super::{CryptoError, CryptoResult};
use blake3;
use sha2::{Digest, Sha256, Sha512};

/// Hash data using SHA-256
pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Hash data using SHA-512
pub fn sha512(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Hash data using BLAKE3 (faster and more secure than SHA-256)
pub fn blake3_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Hash password using Argon2id (memory-hard, resistant to GPU attacks)
pub fn hash_password(password: &str) -> CryptoResult<String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| CryptoError::Hashing(format!("Argon2 hashing failed: {}", e)))
}

/// Verify password against Argon2 hash
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };

    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| CryptoError::Verification(format!("Invalid hash format: {}", e)))?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate HMAC-SHA256 for message authentication
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify HMAC-SHA256
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], expected_mac: &str) -> CryptoResult<bool> {
    let computed = hmac_sha256(key, message);
    Ok(constant_time_compare(&computed, expected_mac))
}

/// Constant-time string comparison (prevents timing attacks)
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Generate a cryptographically secure random token
pub fn generate_token(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a hex-encoded random token
pub fn generate_hex_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut token = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut token);
    hex::encode(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello world");
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_blake3() {
        let hash = blake3_hash(b"test data");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_password_hashing() {
        let password = "SuperSecurePassword123!";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_hmac() {
        let key = b"secret_key";
        let message = b"important message";
        let mac = hmac_sha256(key, message);

        assert!(verify_hmac_sha256(key, message, &mac).unwrap());
        assert!(!verify_hmac_sha256(b"wrong_key", message, &mac).unwrap());
    }

    #[test]
    fn test_token_generation() {
        let token = generate_token(32);
        assert_eq!(token.len(), 32);

        let hex_token = generate_hex_token(16);
        assert_eq!(hex_token.len(), 32); // 16 bytes = 32 hex chars
    }
}
