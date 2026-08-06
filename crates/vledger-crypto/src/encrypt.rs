//! AES-256-GCM authenticated encryption for data at rest.
//!
//! ## Design
//! - Every ciphertext includes a randomly generated 96-bit nonce prepended to
//!   the ciphertext bytes.  The format is: `nonce (12 bytes) || ciphertext`.
//! - The GCM authentication tag (16 bytes) is appended by the `aes-gcm` crate
//!   inside `ciphertext`.
//! - Optional Additional Authenticated Data (AAD) binds the ciphertext to its
//!   context (e.g. table_id || page_id) without encrypting that context.
//! - Keys are zeroized on drop.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce as AesNonce,
};
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;
use crate::{Nonce, SymmetricKey};

/// A zeroizing wrapper around a 256-bit AES-GCM key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct EncryptionKey {
    bytes: SymmetricKey,
}

impl EncryptionKey {
    /// Generate a random key using the OS CSPRNG.
    pub fn generate() -> Self {
        let key = Aes256Gcm::generate_key(OsRng);
        Self {
            bytes: key.into(),
        }
    }

    /// Load from raw bytes.
    pub fn from_bytes(bytes: SymmetricKey) -> Self {
        Self { bytes }
    }

    /// Export raw bytes.  Treat with care — caller must zeroize after use.
    pub fn as_bytes(&self) -> &SymmetricKey {
        &self.bytes
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.bytes))
    }
}

/// Encrypt `plaintext` under `key` with optional `aad`.
///
/// Returns `nonce (12 bytes) || ciphertext_with_tag`.
pub fn encrypt(
    key: &EncryptionKey,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = key.cipher();
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let aad_bytes = aad.unwrap_or(&[]);

    let payload = Payload {
        msg: plaintext,
        aad: aad_bytes,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to the output
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt `ciphertext` (in `nonce || ciphertext_with_tag` format) under `key`.
pub fn decrypt(
    key: &EncryptionKey,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 12 {
        return Err(CryptoError::DecryptionFailed);
    }

    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let nonce = AesNonce::from_slice(nonce_bytes);
    let aad_bytes = aad.unwrap_or(&[]);

    let payload = Payload {
        msg: ct,
        aad: aad_bytes,
    };

    let cipher = key.cipher();
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Extract the nonce from a `nonce || ciphertext` blob.
pub fn extract_nonce(ciphertext: &[u8]) -> Option<Nonce> {
    if ciphertext.len() < 12 {
        return None;
    }
    let mut n = [0u8; 12];
    n.copy_from_slice(&ciphertext[..12]);
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::generate();
        let plaintext = b"VectorGuard Labs \xE2\x80\x94 financial record";
        let ct = encrypt(&key, plaintext, None).unwrap();
        let pt = decrypt(&key, &ct, None).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let ct = encrypt(&key1, b"secret", None).unwrap();
        assert!(decrypt(&key2, &ct, None).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = EncryptionKey::generate();
        let mut ct = encrypt(&key, b"secret data", None).unwrap();
        // Flip a byte in the ciphertext (not the nonce)
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt(&key, &ct, None).is_err());
    }

    #[test]
    fn aad_mismatch_fails() {
        let key = EncryptionKey::generate();
        let ct = encrypt(&key, b"data", Some(b"table_id=42")).unwrap();
        // Decrypt with wrong AAD
        assert!(decrypt(&key, &ct, Some(b"table_id=99")).is_err());
        // Decrypt with no AAD
        assert!(decrypt(&key, &ct, None).is_err());
        // Correct AAD succeeds
        assert!(decrypt(&key, &ct, Some(b"table_id=42")).is_ok());
    }
}
