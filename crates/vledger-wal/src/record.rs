//! WAL record definitions.
//!
//! Every record written to the WAL has a fixed header followed by a
//! variable-length payload.  The CRC-32 covers the entire record so that
//! partial / torn writes are detected on recovery.

use serde::{Deserialize, Serialize};

/// Discriminant byte for each WAL record type.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    /// Marks the start of a transaction.
    Begin = 0x01,
    /// A data mutation (insert / update-as-new-version / logical delete).
    Data = 0x02,
    /// Successful end of a transaction — data is visible after this.
    Commit = 0x03,
    /// Transaction was aborted — all preceding Data records for this tx are
    /// discarded during recovery.
    Rollback = 0x04,
    /// Checkpoint marker — recovery can start from here instead of the
    /// beginning of the segment.
    Checkpoint = 0x05,
    /// Schema change (DDL).
    Schema = 0x06,
    /// Segment header — first record in every new segment file.
    SegmentHeader = 0x07,
}

impl TryFrom<u8> for RecordType {
    type Error = crate::WalError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Begin),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Commit),
            0x04 => Ok(Self::Rollback),
            0x05 => Ok(Self::Checkpoint),
            0x06 => Ok(Self::Schema),
            0x07 => Ok(Self::SegmentHeader),
            other => Err(crate::WalError::UnknownRecordType(other)),
        }
    }
}

/// Fixed-size header prefix for every WAL record.
///
/// Total header size: 4 + 1 + 1 + 8 + 8 + 8 + 4 = **34 bytes**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordHeader {
    /// Magic number — sanity check, not a security boundary.
    pub magic: u32,
    /// WAL format version.
    pub version: u8,
    /// Record type discriminant.
    pub record_type: u8,
    /// Transaction ID this record belongs to.
    pub tx_id: u64,
    /// Monotonically increasing sequence number across the entire WAL.
    /// Never reused, never reset.  Used for total ordering.
    pub sequence: u64,
    /// UTC timestamp in nanoseconds since Unix epoch.
    pub timestamp_ns: i64,
    /// Length of the payload that follows this header, in bytes.
    pub payload_len: u32,
}

impl RecordHeader {
    pub const SERIALIZED_SIZE: usize = 34;
}

/// A complete WAL record: header + payload + checksum.
#[derive(Debug, Clone)]
pub struct WalRecord {
    pub header: RecordHeader,
    /// Arbitrary payload bytes.  Serialized via `bincode` by the writer.
    pub payload: Vec<u8>,
    /// CRC-32 of `header bytes || payload bytes`.
    /// Verified on read; written by the writer after computing.
    pub crc32: u32,
}

impl WalRecord {
    /// Total on-disk size of this record in bytes.
    pub fn on_disk_size(&self) -> usize {
        RecordHeader::SERIALIZED_SIZE + self.payload.len() + 4 // 4 bytes for crc32
    }
}

// ── Payload types ────────────────────────────────────────────────────────────

/// Payload for [`RecordType::Begin`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginPayload {
    /// Human-readable description or tag (optional, for audit logs).
    pub description: Option<String>,
}

/// Payload for [`RecordType::Data`].
///
/// Describes a single row-level mutation.  The database never overwrites
/// existing rows — every mutation appends a new version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPayload {
    /// Target table identifier.
    pub table_id: u32,
    /// Page number within the table where this row version will be written.
    pub page_id: u64,
    /// Slot within the page.
    pub slot_id: u16,
    /// The kind of mutation.
    pub mutation: MutationKind,
    /// Serialized row data (bincode-encoded row struct).
    pub row_data: Vec<u8>,
    /// BLAKE3 hash of `row_data` — integrity check independent of CRC-32.
    pub row_hash: [u8; 32],
    /// Hash of the previous version of this row (for hash chaining).
    /// `None` for the first version.
    pub prev_hash: Option<[u8; 32]>,
}

/// The kind of row-level mutation stored in a [`DataPayload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationKind {
    /// Brand-new row.
    Insert,
    /// New version of an existing row (old version remains, MVCC).
    Update,
    /// Logical deletion marker — old data is retained for audit.
    Delete,
}

/// Payload for [`RecordType::Commit`].
///
/// The `signature` field is an Ed25519 signature over
/// `tx_hash || record_count_le4` produced by the database signing key
/// (`vledger-crypto::sign::DbSigningKey`).  It is verified during WAL
/// recovery before any committed transaction is replayed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitPayload {
    /// Number of Data records committed in this transaction.
    pub record_count: u32,
    /// BLAKE3 hash of all Data payload hashes in sequence — a per-transaction
    /// integrity root.
    pub tx_hash: [u8; 32],
    /// Ed25519 signature over `tx_hash || record_count.to_le_bytes()`.
    /// Empty `Vec` when signing is disabled (dev / legacy recovery).
    /// Exactly 64 bytes when present.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Ed25519 public key of the signer (32 bytes), embedded so verifiers
    /// can check authenticity without out-of-band key distribution.
    /// Empty `Vec` when signing is disabled.
    #[serde(default)]
    pub signer_pubkey: Vec<u8>,
}

/// Payload for [`RecordType::Checkpoint`].
///
/// Written by [`WalWriter::checkpoint_with_merkle_root`] after an fsync.
/// The `root_signature` field (when present) is an Ed25519 signature over
/// `page_merkle_root || last_committed_sequence.to_le_bytes()` (40 bytes),
/// produced with the same `DbSigningKey` used for commit signing.
/// Verifiers can use the embedded `signer_pubkey` without out-of-band key
/// distribution.  Empty `Vec` fields indicate an unsigned / legacy record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointPayload {
    /// Sequence number of the last committed WAL record before this checkpoint.
    pub last_committed_sequence: u64,
    /// BLAKE3 Merkle root of all entry page hashes at checkpoint time.
    pub page_merkle_root: [u8; 32],
    /// Ed25519 signature over `page_merkle_root || last_committed_sequence.to_le_bytes()`.
    /// Empty when signing is disabled.
    #[serde(default)]
    pub root_signature: Vec<u8>,
    /// Ed25519 public key of the signer (32 bytes).  Empty when unsigned.
    #[serde(default)]
    pub signer_pubkey: Vec<u8>,
}

