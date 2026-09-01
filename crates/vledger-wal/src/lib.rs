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

pub mod encrypt;
pub mod error;
pub mod key_rotation;
pub mod reader;
pub mod record;
pub mod recovery;
pub mod segment;
pub mod writer;

pub use encrypt::{decrypt_record, derive_segment_key, encrypt_record, is_encrypted, WalKey};
pub use error::WalError;
pub use key_rotation::{rotate_wal_key, KeyRotationResult};
pub use reader::{WalReader, scan_last_sequence_in_segment};
pub use record::{RecordType, WalRecord};
pub use recovery::{recover, recover_streaming, recover_verified, decode_table_id_only};
pub use writer::{spawn_group_commit_flusher, FlushState, WalSyncMode, WalWriter};

/// WAL magic number — spells "VectorLedger" in hex.
pub const WAL_MAGIC: u32 = 0x56474442;

/// Current WAL format version.
pub const WAL_VERSION: u8 = 1;

/// Default segment size: 64 MiB.  Segments roll over when full.
pub const DEFAULT_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;
