//! Encryption and decryption utilities using AES-GCM

use super::{CryptoError, CryptoResult};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

/// Encrypt data using AES-256-GCM
pub fn encrypt_aes_gcm(key: &[u8; 32], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());

    // Generate random nonce (12 bytes for GCM)
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

    // Prepend nonce to ciphertext (nonce || ciphertext)
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_aes_gcm(key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> CryptoResult<Vec<u8>> {
    if ciphertext_with_nonce.len() < 12 {
        return Err(CryptoError::Decryption("Ciphertext too short".to_string()));
    }

    let cipher = Aes256Gcm::new(key.into());

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}

/// Encrypt and encode as base64
pub fn encrypt_to_base64(key: &[u8; 32], plaintext: &[u8]) -> CryptoResult<String> {
    let encrypted = encrypt_aes_gcm(key, plaintext)?;
    Ok(base64::encode(encrypted))
}

/// Decrypt from base64
pub fn decrypt_from_base64(key: &[u8; 32], base64_str: &str) -> CryptoResult<Vec<u8>> {
    let encrypted = base64::decode(base64_str)
        .map_err(|e| CryptoError::Decryption(format!("Invalid base64: {}", e)))?;
    decrypt_aes_gcm(key, &encrypted)
}

/// Generate a random 256-bit encryption key
pub fn generate_key() -> [u8; 32] {
    Aes256Gcm::generate_key(&mut OsRng).into()
}

/// Generate a random 96-bit nonce for AES-GCM
fn generate_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Derive encryption key from password using PBKDF2
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = generate_key();
        let plaintext = b"secret data";

        let ciphertext = encrypt_aes_gcm(&key, plaintext).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_base64_encryption() {
        let key = generate_key();
        let plaintext = b"confidential information";

        let encrypted_b64 = encrypt_to_base64(&key, plaintext).unwrap();
        let decrypted = decrypt_from_base64(&key, &encrypted_b64).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"data";

        let ciphertext = encrypt_aes_gcm(&key1, plaintext).unwrap();
        let result = decrypt_aes_gcm(&key2, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation() {
        let password = "my_secure_password";
        let salt = b"random_salt_12345";

        let key1 = derive_key_from_password(password, salt);
        let key2 = derive_key_from_password(password, salt);

        assert_eq!(key1, key2); // Same password/salt = same key
    }
}
