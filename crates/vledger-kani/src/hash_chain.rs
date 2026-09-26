//! Kani proof harnesses for hash chain integrity properties.
//!
//! Proves structural properties that do not require unwinding into BLAKE3:
//! 1. ZERO_HASH is exactly 32 zero bytes.
//! 2. Hash type alias is the correct size.
//! 3. merkle_root of empty input returns ZERO_HASH (provable without BLAKE3).
//!
//! Note: Harnesses that call hash_bytes() or merkle_root() with non-empty
//! inputs require Kani to unwind through BLAKE3's 64 compression rounds,
//! which exceeds tractable bounds. Those properties are covered by the
//! existing unit tests (hash_chain_is_consistent, verify_chain_integrity).

use vledger_crypto::{
    merkle::merkle_root,
    Hash, ZERO_HASH,
};

// ── Harness 1: ZERO_HASH is all zeros ─────────────────────────────────────────

/// Prove that ZERO_HASH is exactly [0u8; 32].
#[cfg(kani)]
#[kani::proof]
pub fn zero_hash_is_all_zeros() {
    assert_eq!(ZERO_HASH, [0u8; 32], "ZERO_HASH must be exactly 32 zero bytes");
    for b in ZERO_HASH.iter() {
        assert_eq!(*b, 0u8, "every byte of ZERO_HASH must be zero");
    }
}

// ── Harness 2: Hash type is 32 bytes ──────────────────────────────────────────

/// Prove that the Hash type alias is always 32 bytes in size.
#[cfg(kani)]
#[kani::proof]
pub fn hash_type_is_32_bytes() {
    assert_eq!(std::mem::size_of::<Hash>(), 32, "Hash must be 32 bytes");
}

// ── Harness 3: ZERO_HASH is not changed by copying ────────────────────────────

/// Prove that ZERO_HASH can be copied and compared safely.
#[cfg(kani)]
#[kani::proof]
pub fn zero_hash_copy_semantics() {
    let a = ZERO_HASH;
    let b = ZERO_HASH;
    assert_eq!(a, b, "ZERO_HASH copies must be equal");
    assert_eq!(a, [0u8; 32], "ZERO_HASH copy must equal [0u8;32]");
}

// ── Harness 4: merkle_root of empty slice is ZERO_HASH ────────────────────────

/// Prove that merkle_root(&[]) returns ZERO_HASH.
/// This is the base-case check in merkle.rs — no BLAKE3 call is made.
#[cfg(kani)]
#[kani::proof]
pub fn merkle_root_empty_is_zero_hash() {
    let empty: &[[u8; 32]] = &[];
    let root = merkle_root(empty);
    assert_eq!(root, ZERO_HASH, "merkle_root of empty slice must be ZERO_HASH");
}

// ── Harness 5: any_hash is 32 bytes ───────────────────────────────────────────

/// Prove that any symbolic Hash value has exactly 32 bytes.
/// This verifies the type contract that all hash values in the system
/// are the same fixed size.
#[cfg(kani)]
#[kani::proof]
pub fn any_hash_is_32_bytes() {
    let h: Hash = kani::any();
    assert_eq!(h.len(), 32, "any Hash value must be 32 bytes");
    assert_eq!(std::mem::size_of_val(&h), 32);
}
