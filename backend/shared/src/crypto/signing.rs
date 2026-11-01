//! Digital signature utilities for authentication and verification

use super::{CryptoError, CryptoResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// Generate a new Ed25519 keypair
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message using Ed25519
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> String {
    let signature = signing_key.sign(message);
    hex::encode(signature.to_bytes())
}

/// Verify an Ed25519 signature
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_hex: &str,
) -> CryptoResult<bool> {
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| CryptoError::Verification(format!("Invalid signature hex: {}", e)))?;

    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Verification("Invalid signature length".to_string()))?,
    );

    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Ethereum signature verification (for wallet authentication)
pub fn verify_ethereum_signature(
    message: &str,
    signature: &str,
    expected_address: &str,
) -> CryptoResult<bool> {
    use ethers::core::types::Signature as EthSignature;
    use std::str::FromStr;

    let sig = EthSignature::from_str(signature)
        .map_err(|e| CryptoError::Verification(format!("Invalid Ethereum signature: {}", e)))?;

    let recovered_address = sig
        .recover(message)
        .map_err(|e| CryptoError::Verification(format!("Failed to recover address: {}", e)))?;

    let recovered_str = format!("{:?}", recovered_address).to_lowercase();
    let expected_str = expected_address.to_lowercase();

    Ok(recovered_str == expected_str)
}

/// Sign data with a private key (hex-encoded)
pub fn sign_with_hex_key(private_key_hex: &str, message: &[u8]) -> CryptoResult<String> {
    let key_bytes = hex::decode(private_key_hex)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid hex key: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(CryptoError::InvalidKey("Key must be 32 bytes".to_string()));
    }

    let signing_key = SigningKey::from_bytes(&key_bytes.try_into().unwrap());
    Ok(sign_message(&signing_key, message))
}

/// Verify signature with public key (hex-encoded)
pub fn verify_with_hex_key(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> CryptoResult<bool> {
    let key_bytes = hex::decode(public_key_hex)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid hex key: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(CryptoError::InvalidKey("Key must be 32 bytes".to_string()));
    }

    let verifying_key = VerifyingKey::from_bytes(&key_bytes.try_into().unwrap())
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {}", e)))?;

    verify_signature(&verifying_key, message, signature_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"test message";

        let signature = sign_message(&signing_key, message);
        assert!(verify_signature(&verifying_key, message, &signature).unwrap());
    }

    #[test]
    fn test_signature_verification_fails_wrong_message() {
        let (signing_key, verifying_key) = generate_keypair();
        let signature = sign_message(&signing_key, b"original message");

        assert!(!verify_signature(&verifying_key, b"different message", &signature).unwrap());
    }

    #[test]
    fn test_hex_key_signing() {
        let (signing_key, verifying_key) = generate_keypair();
        let private_hex = hex::encode(signing_key.to_bytes());
        let public_hex = hex::encode(verifying_key.to_bytes());

        let message = b"test";
        let signature = sign_with_hex_key(&private_hex, message).unwrap();

        assert!(verify_with_hex_key(&public_hex, message, &signature).unwrap());
    }
}
