//! # vledger-crypto
//!
//! All cryptographic primitives for VectorLedger, centralised in one crate
//! so that algorithm choices are auditable in a single place.
//!
//! ## What lives here
//! | Module      | Purpose                                              |
//! |-------------|------------------------------------------------------|
//! | `hash`      | BLAKE3 content hashing and hash-chain verification   |
//! | `sign`      | Ed25519 commit signing / verification                |
//! | `encrypt`   | AES-256-GCM data-at-rest encryption                  |
//! | `kdf`       | HKDF key derivation for per-table / per-row keys     |
//! | `merkle`    | Merkle tree construction and membership proofs       |
//! | `password`  | Argon2id password hashing for authentication         |
//! | `error`     | Unified `CryptoError` type                           |

pub mod encrypt;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod merkle;
pub mod password;
pub mod sign;

pub use error::CryptoError;

/// 32-byte hash value (BLAKE3 output).
pub type Hash = [u8; 32];

/// 64-byte Ed25519 signature.
pub type Signature = [u8; 64];

/// 32-byte Ed25519 public key.
pub type PublicKey = [u8; 32];

/// 32-byte symmetric encryption key.
pub type SymmetricKey = [u8; 32];

/// 12-byte AES-GCM nonce.
pub type Nonce = [u8; 12];

/// The zero hash — used as the `prev_hash` sentinel for the first record.
pub const ZERO_HASH: Hash = [0u8; 32];
