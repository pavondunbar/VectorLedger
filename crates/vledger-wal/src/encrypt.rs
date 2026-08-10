//! WAL segment-level AES-256-GCM encryption.
//!
//! ## Design
//!
//! Every WAL record is individually encrypted before it is written to disk.
//! The on-disk format for an encrypted record is:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │  ENCRYPTED_MAGIC : u32  (0x45574C52  "EWLR")                        │
//! │  nonce           : [u8; 12]  (random, unique per record)             │
//! │  ciphertext_len  : u32  (length of the AES-GCM ciphertext+tag)      │
//! │  ciphertext      : [u8; ciphertext_len]  (plaintext record + 16-byte │
//! │                    GCM authentication tag)                           │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The AAD (Additional Authenticated Data) bound to each record is
//! `segment_index.to_le_bytes()` — this prevents ciphertext blocks from
//! being transplanted between segments without detection.
//!
//! ## Key derivation
//!
//! Per-segment keys are derived from the database master key using HKDF:
//!
//! ```text
//! segment_key = HKDF(master_key, context = "vgdb/wal/segment/<index>")
//! ```
//!
//! This means rotating the master key automatically changes the encryption
//! of all new WAL segments, while old segments remain decryptable with the
//! old key until they are vacuumed.
//!
//! ## Backwards compatibility
//!
//! Unencrypted WAL segments (magic = 0x56474442) are still readable.
//! The reader checks the first 4 bytes: if they match `ENCRYPTED_MAGIC` the
//! record is decrypted; otherwise it is passed through as plaintext.
//! This allows a live migration from unencrypted to encrypted WAL without
//! downtime.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce as AesNonce,
};

use crate::error::WalError;

/// Magic prefix for encrypted WAL records (spells "EWLR").
pub const ENCRYPTED_MAGIC: u32 = 0x45574C52;

/// Size of the encrypted record header (magic + nonce + ciphertext_len).
pub const ENC_HEADER_SIZE: usize = 4 + 12 + 4; // 20 bytes

/// A 32-byte AES-256-GCM key for WAL encryption.
pub type WalKey = [u8; 32];

// ── Encryption ────────────────────────────────────────────────────────────────

/// Encrypt a raw WAL record byte-slice.
///
/// `record_bytes` is the full serialized plaintext record
/// (header + payload + crc32).
///
/// `segment_index` is bound as AAD so the ciphertext cannot be replayed
/// into a different segment.
///
/// Returns the on-disk encrypted blob.
pub fn encrypt_record(
    key:           &WalKey,
    record_bytes:  &[u8],
    segment_index: u64,
) -> Result<Vec<u8>, WalError> {
    let cipher = build_cipher(key);
    let nonce  = Aes256Gcm::generate_nonce(OsRng);
    let aad    = segment_index.to_le_bytes();

    let payload = Payload {
        msg: record_bytes,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| WalError::Encryption(e.to_string()))?;

    let ciphertext_len = ciphertext.len() as u32;

    // Assemble: ENCRYPTED_MAGIC || nonce || ciphertext_len || ciphertext
    let mut out = Vec::with_capacity(ENC_HEADER_SIZE + ciphertext.len());
    out.extend_from_slice(&ENCRYPTED_MAGIC.to_le_bytes());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext_len.to_le_bytes());
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

// ── Decryption ────────────────────────────────────────────────────────────────

/// Attempt to decrypt an encrypted record blob.
///
/// Returns the plaintext record bytes on success.
/// Returns `Err(WalError::Decryption)` if the tag or AAD does not verify —
/// indicating corruption or a wrong key.
pub fn decrypt_record(
    key:           &WalKey,
    blob:          &[u8],
    segment_index: u64,
) -> Result<Vec<u8>, WalError> {
    if blob.len() < ENC_HEADER_SIZE {
        return Err(WalError::Encryption(format!(
            "encrypted blob too short: {} bytes",
            blob.len()
        )));
    }

    // Verify magic
    let magic = u32::from_le_bytes(blob[0..4].try_into().unwrap());
    if magic != ENCRYPTED_MAGIC {
        return Err(WalError::Encryption(format!(
            "expected ENCRYPTED_MAGIC {:#010x}, got {:#010x}",
            ENCRYPTED_MAGIC, magic
        )));
    }

    let nonce_bytes = &blob[4..16];
    let ct_len      = u32::from_le_bytes(blob[16..20].try_into().unwrap()) as usize;

    if blob.len() < ENC_HEADER_SIZE + ct_len {
        return Err(WalError::Encryption(format!(
            "encrypted blob truncated: declared ciphertext_len={ct_len}, \
             available={}",
            blob.len() - ENC_HEADER_SIZE
        )));
    }

    let ciphertext = &blob[ENC_HEADER_SIZE..ENC_HEADER_SIZE + ct_len];
    let nonce      = AesNonce::from_slice(nonce_bytes);
    let aad        = segment_index.to_le_bytes();

    let cipher  = build_cipher(key);
    let payload = Payload { msg: ciphertext, aad: &aad };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| WalError::Decryption)
}

/// Returns `true` if `bytes` starts with the encrypted record magic.
#[inline]
pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && u32::from_le_bytes(bytes[0..4].try_into().unwrap()) == ENCRYPTED_MAGIC
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive a per-segment AES-256-GCM key from a 32-byte master key using
/// HKDF-SHA256.
///
/// The derivation context is `"vgdb/wal/segment/<index>"` so each segment
/// gets a unique key.
pub fn derive_segment_key(
    master_key:    &[u8; 32],
    segment_index: u64,
) -> Result<WalKey, WalError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk  = Hkdf::<Sha256>::new(None, master_key);
    let ctx = format!("vgdb/wal/segment/{segment_index}");
    let mut okm = [0u8; 32];
    hk.expand(ctx.as_bytes(), &mut okm)
        .map_err(|e| WalError::Encryption(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn build_cipher(key: &WalKey) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> WalKey {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() { *b = i as u8; }
        k
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key      = test_key();
        let record   = b"WAL record payload for test 123";
        let segment  = 42u64;

        let blob      = encrypt_record(&key, record, segment).unwrap();
        let plaintext = decrypt_record(&key, &blob, segment).unwrap();
        assert_eq!(plaintext, record);
    }

    #[test]
    fn wrong_segment_index_fails() {
        let key     = test_key();
        let record  = b"financial data";
        let blob    = encrypt_record(&key, record, 1).unwrap();
        // Decrypt with wrong segment index → AAD mismatch → GCM tag fail
        assert!(decrypt_record(&key, &blob, 2).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0xFF;

        let blob = encrypt_record(&key1, b"secret record", 0).unwrap();
        assert!(decrypt_record(&key2, &blob, 0).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key   = test_key();
        let mut blob = encrypt_record(&key, b"data", 0).unwrap();
        // Flip a byte in the ciphertext
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(decrypt_record(&key, &blob, 0).is_err());
    }

    #[test]
    fn is_encrypted_detection() {
        let key  = test_key();
        let blob = encrypt_record(&key, b"record", 0).unwrap();
        assert!(is_encrypted(&blob));

        // A plaintext WAL record starts with WAL_MAGIC (0x56474442)
        let plaintext_header = 0x56474442u32.to_le_bytes();
        assert!(!is_encrypted(&plaintext_header));
    }

    #[test]
    fn derive_segment_key_is_deterministic() {
        let master = [0xABu8; 32];
        let k1 = derive_segment_key(&master, 5).unwrap();
        let k2 = derive_segment_key(&master, 5).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_segments_get_different_keys() {
        let master = [0xABu8; 32];
        let k0 = derive_segment_key(&master, 0).unwrap();
        let k1 = derive_segment_key(&master, 1).unwrap();
        assert_ne!(k0, k1);
    }
}
