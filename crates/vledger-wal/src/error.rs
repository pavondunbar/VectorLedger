//! WAL error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WAL record checksum mismatch (expected {expected:#010x}, got {actual:#010x})")]
    ChecksumMismatch { expected: u32, actual: u32 },

    #[error("WAL magic mismatch — file may be corrupt or not a WAL segment")]
    BadMagic,

    #[error("Unsupported WAL version: {0}")]
    UnsupportedVersion(u8),

    #[error("Truncated WAL record at offset {offset}: need {needed} bytes, have {available}")]
    TruncatedRecord {
        offset: u64,
        needed: usize,
        available: usize,
    },

    #[error("Unknown record type byte: {0:#04x}")]
    UnknownRecordType(u8),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("WAL segment is full (max {max_bytes} bytes)")]
    SegmentFull { max_bytes: u64 },

    #[error("Attempted to write to a sealed (read-only) WAL segment")]
    SegmentSealed,

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Transaction {0} not found in WAL")]
    TransactionNotFound(u64),
}
