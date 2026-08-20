//! # vledger-pages
//!
//! Immutable data page storage for VectorLedger.
//!
//! ## Design
//! Pages are the atomic unit of storage on disk.  Every page is:
//! - Fixed size (default 8 KiB, configurable at database init time).
//! - Immutable once written — new versions are new pages.
//! - Checksummed (CRC-32) to detect silent corruption.
//! - Optionally encrypted (AES-256-GCM) per-table key.
//! - Hashed (BLAKE3) for Merkle tree membership.
//!
//! ## On-disk layout
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  PageHeader  (fixed, 64 bytes)                              │
//! │  ├─ magic        : u32                                      │
//! │  ├─ version      : u8                                       │
//! │  ├─ flags        : u8  (encrypted, compressed, …)          │
//! │  ├─ page_id      : u64                                      │
//! │  ├─ table_id     : u32                                      │
//! │  ├─ prev_page_id : u64  (0 = first page)                   │
//! │  ├─ slot_count   : u16                                      │
//! │  ├─ free_bytes   : u16                                      │
//! │  ├─ content_hash : [u8; 32]  (BLAKE3 of slot area)         │
//! │  └─ crc32        : u32  (over entire page incl. header)    │
//! │  SlotDirectory   (variable, 4 bytes per slot)               │
//! │  Slot data       (variable)                                 │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod error;
pub mod header;
pub mod page;
pub mod store;

pub use error::PageError;
pub use header::{PageFlags, PageHeader};
pub use page::Page;
pub use store::{spawn_page_commit_flusher, PageFlushState, PageStore};

/// Default page size: 8 KiB — the plaintext data capacity.
/// Encrypted pages are written to a separate `.epages` file whose on-disk
/// record size includes the GCM overhead (nonce 12 + tag 16 + footer 4 = 32).
pub const DEFAULT_PAGE_SIZE: usize = 8 * 1024;

/// Page magic number — "VGPG" in ASCII.
pub const PAGE_MAGIC: u32 = 0x56475047;

/// Page format version.
pub const PAGE_VERSION: u8 = 1;
