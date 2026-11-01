//! Cryptographic utilities for Verdyx
//!
//! Provides secure hashing, signing, and encryption functions

pub mod encryption;
pub mod hashing;
pub mod signing;

pub use encryption::*;
pub use hashing::*;
pub use signing::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Hashing error: {0}")]
    Hashing(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
