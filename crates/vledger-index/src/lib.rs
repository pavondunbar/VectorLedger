//! # vledger-index
//!
//! Index structures for VectorLedger.
//!
//! Phase 1 ships a simple in-memory sorted map (B-tree via `BTreeMap`) that
//! acts as the primary key index.  Phase 2 will replace this with a persistent
//! B+ tree backed by the page store.

pub mod error;
pub mod btree;
pub mod hash_index;

pub use error::IndexError;
pub use btree::BTreeIndex;
pub use hash_index::HashIndex;
