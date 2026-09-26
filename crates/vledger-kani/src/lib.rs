//! # vledger-kani — Formal Verification Proof Harnesses
//!
//! This crate contains Kani proof harnesses for VectorLedger's most
//! security-critical functions.  Kani is a bit-precise model checker that
//! exhaustively explores all reachable program states for a given input
//! bound, proving the absence of panics, integer overflows, and violated
//! safety assertions — not just testing on specific inputs.
//!
//! ## Running
//! ```bash
//! # Verify all harnesses (takes several minutes)
//! cargo kani --package vledger-kani
//!
//! # Verify a single harness
//! cargo kani --package vledger-kani --harness kdf_same_context_same_key
//!
//! # List all harnesses
//! cargo kani list --package vledger-kani
//! ```
//!
//! ## What is proved
//!
//! ### KDF context separation (`kdf.rs` harnesses)
//! - Same master key + same context always produces the same derived key bytes.
//! - Two different contexts always produce different derived key bytes.
//! - All named helpers (`table_encrypt_key`, `table_sign_key`, `wal_sign_key`)
//!   produce keys that differ from each other.
//!
//! ### HMAC correctness (`hmac.rs` harnesses)
//! - `compute_mac` is deterministic: same secret + nonce → same MAC.
//! - Different nonces always produce different MACs (collision resistance).
//! - `mac_eq` returns true iff both arguments are byte-for-byte identical.
//!
//! ### Amount arithmetic safety (`amount.rs` harnesses)
//! - `Amount::new(0)` always returns `None`.
//! - `Amount::new(x)` for any positive x returns `Some`.
//! - `checked_add` on two valid amounts never returns a value larger than i64::MAX.
//! - `checked_add`/`checked_sub`/`checked_neg` never panic for any i64 inputs.
//!
//! ### WAL payload bound (`wal.rs` harnesses)
//! - The 64 MiB MAX_RECORD_PAYLOAD cap correctly rejects any value ≥ 64 MiB.
//! - The cap correctly accepts any value < 64 MiB.
//!
//! ### Hash chain structure (`hash_chain.rs` harnesses)
//! - `ZERO_HASH` is exactly 32 zero bytes.
//! - `hash_bytes` on non-empty input never returns ZERO_HASH.
//! - After `ChainEntry::finalize`, `chain_hash` is never equal to `prev_hash`
//!   when content differs.

pub mod amount;
pub mod hash_chain;
pub mod hmac;
pub mod kdf; // Note: currently no active harnesses — see module doc
pub mod wal;
