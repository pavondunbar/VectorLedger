//! Key derivation using HKDF-SHA256.
//!
//! Per-table and per-row encryption keys are derived from a master key so
//! that:
//! - Compromising one table key doesn't compromise the master key.
//! - The key hierarchy is deterministic — any key can be re-derived from the
//!   master key + the derivation context.
//!
//! Derivation contexts use a structured string so that keys for different
//! purposes are cryptographically separated:
//!
//! ```text
//! vgdb/table/{table_id}/encrypt       → table encryption key
//! vgdb/table/{table_id}/sign          → table signing key
//! vgdb/table/{table_id}/row/{row_id}  → per-row key
//! vgdb/wal/sign                       → WAL signing key
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;
use crate::SymmetricKey;

/// A 256-bit master key from which all other keys are derived.
/// Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: SymmetricKey,
}

impl MasterKey {
    /// Load from raw bytes (typically from an HSM or secure enclave).
    pub fn from_bytes(bytes: SymmetricKey) -> Self {
        Self { bytes }
    }

    /// Generate a random master key.  In production, the master key should
    /// come from an HSM, not generated in-process.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Derive a 256-bit child key for the given context string.
    ///
    /// The context must uniquely identify the key's purpose.  Using the same
    /// context for different purposes is a security error.
    pub fn derive(&self, context: &str) -> Result<DerivedKey, CryptoError> {
        let hk = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut okm = [0u8; 32];
        hk.expand(context.as_bytes(), &mut okm)
            .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
        Ok(DerivedKey {
            bytes: okm,
            context: context.to_string(),
        })
    }

    /// Derive the encryption key for a specific table.
    pub fn table_encrypt_key(&self, table_id: u32) -> Result<DerivedKey, CryptoError> {
        self.derive(&format!("vgdb/table/{}/encrypt", table_id))
    }

    /// Derive the signing key for a specific table's audit log.
    pub fn table_sign_key(&self, table_id: u32) -> Result<DerivedKey, CryptoError> {
        self.derive(&format!("vgdb/table/{}/sign", table_id))
    }

    /// Derive the per-row encryption key.
    pub fn row_key(&self, table_id: u32, row_id: u64) -> Result<DerivedKey, CryptoError> {
        self.derive(&format!("vgdb/table/{}/row/{}", table_id, row_id))
    }

    /// Derive the WAL signing key.
    pub fn wal_sign_key(&self) -> Result<DerivedKey, CryptoError> {
        self.derive("vgdb/wal/sign")
    }
}

/// A derived 256-bit key, ready for use in encryption or signing.
/// Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKey {
    pub(crate) bytes: SymmetricKey,
    #[zeroize(skip)]
    pub context: String,
}

impl DerivedKey {
    /// Export raw bytes.
    pub fn as_bytes(&self) -> &SymmetricKey {
        &self.bytes
    }

    /// Convert into an `EncryptionKey` for use with AES-256-GCM.
    pub fn into_encryption_key(self) -> crate::encrypt::EncryptionKey {
        crate::encrypt::EncryptionKey::from_bytes(self.bytes)
    }

    /// Convert into a raw 32-byte array for use as an Ed25519 seed.
    pub fn into_signing_seed(self) -> [u8; 32] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_context_same_key() {
        let master = MasterKey::generate();
        let k1 = master.derive("vgdb/table/1/encrypt").unwrap();
        let k2 = master.derive("vgdb/table/1/encrypt").unwrap();
        assert_eq!(k1.bytes, k2.bytes);
    }

    #[test]
    fn different_context_different_key() {
        let master = MasterKey::generate();
        let k1 = master.derive("vgdb/table/1/encrypt").unwrap();
        let k2 = master.derive("vgdb/table/2/encrypt").unwrap();
        assert_ne!(k1.bytes, k2.bytes);
    }

    #[test]
    fn table_keys_are_separated() {
        let master = MasterKey::generate();
        let enc = master.table_encrypt_key(1).unwrap();
        let sign = master.table_sign_key(1).unwrap();
        assert_ne!(enc.bytes, sign.bytes);
    }
}
