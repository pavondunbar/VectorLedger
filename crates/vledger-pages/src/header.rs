//! Page header definition.

use serde::{Deserialize, Serialize};
use vledger_crypto::Hash;

use crate::{PAGE_MAGIC, PAGE_VERSION};

/// Bit flags stored in `PageHeader::flags`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFlags {
    /// No special flags.
    None = 0x00,
    /// Slot area is AES-256-GCM encrypted.
    Encrypted = 0x01,
    /// This is an overflow page (continuation of a large row).
    Overflow = 0x02,
    /// This page has been logically deleted (MVCC tombstone at page level).
    Deleted = 0x04,
}

impl PageFlags {
    pub fn is_encrypted(flags: u8) -> bool {
        flags & (PageFlags::Encrypted as u8) != 0
    }
    pub fn is_overflow(flags: u8) -> bool {
        flags & (PageFlags::Overflow as u8) != 0
    }
    pub fn is_deleted(flags: u8) -> bool {
        flags & (PageFlags::Deleted as u8) != 0
    }
}

/// Fixed-size page header.  Serializes to exactly 50 bytes with bincode.
///
/// Layout (bincode standard, varint u64/u32):
/// ```text
/// magic         4 bytes  (u32 fixed LE)
/// version       1 byte
/// flags         1 byte
/// page_id       1..9 bytes  (varint u64)
/// table_id      1..5 bytes  (varint u32)
/// prev_page_id  1..9 bytes  (varint u64)
/// slot_count    1..3 bytes  (varint u16)
/// free_bytes    1..3 bytes  (varint u16)
/// content_hash  32 bytes    (fixed [u8; 32])
/// crc32         4 bytes     (u32 fixed LE)
/// ─────────────────────────────────────────
/// Actual measured size with all-zero values: 50 bytes
/// ```
///
/// SIZE is measured empirically — do not change this without re-measuring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageHeader {
    pub magic: u32,
    pub version: u8,
    /// Bitmask of [`PageFlags`].
    pub flags: u8,
    pub page_id: u64,
    pub table_id: u32,
    pub prev_page_id: u64,
    pub slot_count: u16,
    pub free_bytes: u16,
    /// BLAKE3 hash of the slot area (excludes header).
    pub content_hash: Hash,
    /// CRC-32 of header bytes[0..SIZE-4] and page body.
    /// Must be the last field.
    pub crc32: u32,
}

impl PageHeader {
    /// Serialized size in bytes (measured with bincode standard + fixed_int_encoding).
    pub const SIZE: usize = 66;

    /// Create a new header for a fresh, empty page.
    pub fn new(page_id: u64, table_id: u32, page_size: usize) -> Self {
        let free_bytes = (page_size - Self::SIZE) as u16;
        Self {
            magic: PAGE_MAGIC,
            version: PAGE_VERSION,
            flags: 0,
            page_id,
            table_id,
            prev_page_id: 0,
            slot_count: 0,
            free_bytes,
            content_hash: vledger_crypto::ZERO_HASH,
            crc32: 0,
        }
    }

    /// Validate magic and version.
    pub fn validate_magic(&self) -> bool {
        self.magic == PAGE_MAGIC && self.version == PAGE_VERSION
    }
}
