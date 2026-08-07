//! # vledger-wal
//!
//! Append-only Write-Ahead Log (WAL) for VectorLedger.
//!
//! ## Design
//! Every mutation to the database passes through the WAL before any page is
//! modified.  The commit path is:
//!
//! ```text
//! Client
//!   │
//!   ▼
//! Validate
//!   │
//!   ▼
//! Append WAL record   ← this crate
//!   │
//!   ▼
//! fsync()             ← durability guaranteed here
//!   │
//!   ▼
//! Update pages / indexes
//!   │
//!   ▼
//! Write COMMIT record ← this crate
//!   │
//!   ▼
//! Ack to client
//! ```
//!
//! On crash, the recovery path replays all committed WAL records and discards
//! any partial (uncommitted) records.
//!
//! ## Record format (on disk)
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │  magic     : u32  (0xVectorLedger_WAL)                           │
//! │  version   : u8   (1)                                    │
//! │  record_type: u8                                         │
//! │  tx_id     : u64                                         │
//! │  sequence  : u64  (monotonic, never reused)              │
//! │  timestamp : i64  (UTC unix nanoseconds)                 │
//! │  payload_len: u32                                        │
//! │  payload   : [u8; payload_len]                           │
//! │  crc32     : u32  (over all preceding bytes)             │
//! └──────────────────────────────────────────────────────────┘
//! ```

pub mod error;
pub mod record;
pub mod segment;
pub mod writer;
pub mod reader;
pub mod recovery;

pub use error::WalError;
pub use record::{WalRecord, RecordType};
pub use writer::{WalWriter, WalSyncMode, FlushState, spawn_group_commit_flusher};
pub use reader::WalReader;
pub use recovery::recover;

/// WAL magic number — spells "VectorLedger" in hex.
pub const WAL_MAGIC: u32 = 0x56474442;

/// Current WAL format version.
pub const WAL_VERSION: u8 = 1;

/// Default segment size: 64 MiB.  Segments roll over when full.
pub const DEFAULT_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;
