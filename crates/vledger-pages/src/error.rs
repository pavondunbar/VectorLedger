//! Page-layer error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "Page checksum mismatch on page {page_id} (expected {expected:#010x}, got {actual:#010x})"
    )]
    ChecksumMismatch {
        page_id: u64,
        expected: u32,
        actual: u32,
    },

    #[error("Page magic mismatch on page {page_id}")]
    BadMagic { page_id: u64 },

    #[error("Unsupported page version {version} on page {page_id}")]
    UnsupportedVersion { page_id: u64, version: u8 },

    #[error("Page {page_id} is full ({free_bytes} free, {needed} needed)")]
    PageFull {
        page_id: u64,
        free_bytes: usize,
        needed: usize,
    },

    #[error("Slot {slot_id} not found on page {page_id}")]
    SlotNotFound { page_id: u64, slot_id: u16 },

    #[error("Page {page_id} is sealed — mutations are not allowed")]
    PageSealed { page_id: u64 },

    #[error("Content hash mismatch on page {page_id}")]
    ContentHashMismatch { page_id: u64 },

    #[error("Crypto error: {0}")]
    Crypto(#[from] vledger_crypto::CryptoError),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
