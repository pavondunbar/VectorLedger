//! Unified crypto error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed (bad key, corrupted ciphertext, or wrong nonce)")]
    DecryptionFailed,

    #[error("Signature verification failed")]
    SignatureInvalid,

    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    #[error("Hash chain broken at sequence {sequence}: expected {expected}, got {actual}")]
    HashChainBroken {
        sequence: u64,
        expected: String,
        actual: String,
    },

    #[error("Merkle proof verification failed")]
    MerkleProofInvalid,

    #[error("Password hashing failed: {0}")]
    PasswordHashFailed(String),

    #[error("Key derivation failed: {0}")]
    KdfFailed(String),

    #[error("Random number generation failed")]
    RngFailed,
}
