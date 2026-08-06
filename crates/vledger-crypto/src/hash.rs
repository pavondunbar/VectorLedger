//! BLAKE3 hashing and hash-chain verification.
//!
//! ## Why BLAKE3?
//! - ~3× faster than SHA-256 on modern CPUs (SIMD, parallelism).
//! - Designed for exactly this use case: content-addressed storage and
//!   authenticated data structures.
//! - 256-bit output — identical size to SHA-256, drop-in for Merkle trees.

use crate::{CryptoError, Hash, ZERO_HASH};

/// Hash arbitrary bytes with BLAKE3.
pub fn hash_bytes(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Hash two child hashes together (used for Merkle tree internal nodes).
/// The children are domain-separated with a 0x01 prefix to distinguish
/// internal nodes from leaves (0x00 prefix).
pub fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]); // internal node domain separator
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Hash a leaf value.  Domain-separated from internal nodes.
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]); // leaf domain separator
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Encode a hash as a lowercase hex string (64 characters).
pub fn hash_to_hex(hash: &Hash) -> String {
    hex::encode(hash)
}

/// Decode a 64-character hex string into a Hash.
pub fn hash_from_hex(s: &str) -> Result<Hash, CryptoError> {
    let bytes = hex::decode(s)
        .map_err(|e| CryptoError::InvalidKey(format!("hex decode failed: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("hash must be 32 bytes".into()))
}

/// Represents a single entry in a hash chain.
///
/// Every ledger entry, WAL record, or page carries:
/// - its own content hash
/// - the hash of the previous entry in the chain
///
/// This means any tampering with a historical record invalidates every
/// subsequent hash in the chain — immediately detectable.
#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub sequence: u64,
    pub prev_hash: Hash,
    pub content_hash: Hash,
    /// Hash of (prev_hash || content_hash || sequence_bytes)
    pub chain_hash: Hash,
}

impl ChainEntry {
    /// Compute a new chain entry from its predecessor's chain_hash and the
    /// current record's content.
    pub fn new(sequence: u64, prev_chain_hash: &Hash, content: &[u8]) -> Self {
        let content_hash = hash_bytes(content);
        let chain_hash = compute_chain_hash(sequence, prev_chain_hash, &content_hash);
        Self {
            sequence,
            prev_hash: *prev_chain_hash,
            content_hash,
            chain_hash,
        }
    }

    /// Verify that this entry is internally consistent.
    pub fn verify(&self) -> bool {
        let expected = compute_chain_hash(self.sequence, &self.prev_hash, &self.content_hash);
        expected == self.chain_hash
    }
}

/// Compute `BLAKE3(seq_le || prev_hash || content_hash)`.
fn compute_chain_hash(sequence: u64, prev_hash: &Hash, content_hash: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&sequence.to_le_bytes());
    hasher.update(prev_hash);
    hasher.update(content_hash);
    *hasher.finalize().as_bytes()
}

/// Verify an ordered slice of chain entries is unbroken.
///
/// Returns `Ok(())` if the chain is intact, or a `CryptoError::HashChainBroken`
/// pointing at the first broken link.
pub fn verify_chain(entries: &[ChainEntry]) -> Result<(), CryptoError> {
    let mut prev_chain_hash = ZERO_HASH;

    for entry in entries {
        // Recompute to verify internal consistency
        if !entry.verify() {
            return Err(CryptoError::HashChainBroken {
                sequence: entry.sequence,
                expected: hash_to_hex(&prev_chain_hash),
                actual: hash_to_hex(&entry.chain_hash),
            });
        }
        // Verify chain linkage
        if entry.prev_hash != prev_chain_hash {
            return Err(CryptoError::HashChainBroken {
                sequence: entry.sequence,
                expected: hash_to_hex(&prev_chain_hash),
                actual: hash_to_hex(&entry.prev_hash),
            });
        }
        prev_chain_hash = entry.chain_hash;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_bytes_is_deterministic() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_different_hashes() {
        assert_ne!(hash_bytes(b"hello"), hash_bytes(b"world"));
    }

    #[test]
    fn chain_integrity_happy_path() {
        let e1 = ChainEntry::new(1, &ZERO_HASH, b"entry one");
        let e2 = ChainEntry::new(2, &e1.chain_hash, b"entry two");
        let e3 = ChainEntry::new(3, &e2.chain_hash, b"entry three");
        assert!(verify_chain(&[e1, e2, e3]).is_ok());
    }

    #[test]
    fn chain_detects_tampering() {
        let e1 = ChainEntry::new(1, &ZERO_HASH, b"entry one");
        let mut e2 = ChainEntry::new(2, &e1.chain_hash, b"entry two");
        // Tamper with e2's chain hash
        e2.chain_hash[0] ^= 0xFF;
        let e3 = ChainEntry::new(3, &e2.chain_hash, b"entry three");
        assert!(verify_chain(&[e1, e2, e3]).is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let h = hash_bytes(b"test");
        let s = hash_to_hex(&h);
        let h2 = hash_from_hex(&s).unwrap();
        assert_eq!(h, h2);
    }
}
