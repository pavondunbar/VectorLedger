//! In-memory representation of a database page.
//!
//! A `Page` owns its raw byte buffer.  Rows are written into slots.
//! Once a page is sealed, it becomes read-only and its content hash is final.

use crc32fast::Hasher as Crc32Hasher;
use vledger_crypto::hash::hash_bytes;

use crate::error::PageError;
use crate::header::PageHeader;
use crate::DEFAULT_PAGE_SIZE;

/// Offset of the slot directory relative to the start of the page body
/// (after the header).
const SLOT_DIR_ENTRY_SIZE: usize = 4; // offset:u16 + length:u16

/// A slot directory entry: (offset_from_body_start, data_length).
#[derive(Debug, Clone, Copy)]
pub struct SlotEntry {
    pub offset: u16,
    pub length: u16,
}

/// An immutable-once-sealed database page.
pub struct Page {
    /// Raw byte buffer.  Exactly `page_size` bytes.
    buf: Vec<u8>,
    /// Decoded header (kept in sync with buf[0..PageHeader::SIZE]).
    pub header: PageHeader,
    /// Whether the page has been sealed (no more writes allowed).
    pub sealed: bool,
    /// Page size in bytes.
    pub page_size: usize,
}

impl Page {
    /// Create a fresh, empty page.
    pub fn new(page_id: u64, table_id: u32) -> Self {
        Self::with_size(page_id, table_id, DEFAULT_PAGE_SIZE)
    }

    pub fn with_size(page_id: u64, table_id: u32, page_size: usize) -> Self {
        assert!(page_size >= PageHeader::SIZE + 64, "page too small");
        let buf = vec![0u8; page_size];
        let header = PageHeader::new(page_id, table_id, page_size);
        let mut page = Self {
            buf,
            header,
            sealed: false,
            page_size,
        };
        page.flush_header();
        page
    }

    /// Deserialize a page from raw bytes (e.g. read from disk).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, PageError> {
        if bytes.len() < PageHeader::SIZE {
            return Err(PageError::Io(std::io::Error::other(
                "page buffer too small",
            )));
        }

        let header: PageHeader = bincode::serde::decode_from_slice(
            &bytes[..PageHeader::SIZE],
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .map(|(h, _)| h)
        .map_err(|e: bincode::error::DecodeError| PageError::Serialization(e.to_string()))?;

        if !header.validate_magic() {
            return Err(PageError::BadMagic {
                page_id: header.page_id,
            });
        }

        let page_size = bytes.len();
        let page = Self {
            buf: bytes,
            header,
            sealed: true,
            page_size,
        };

        page.verify_checksum()?;
        page.verify_content_hash()?;
        Ok(page)
    }

    /// Append a row's serialized bytes as a new slot.
    ///
    /// Returns the slot index on success.
    pub fn write_slot(&mut self, data: &[u8]) -> Result<u16, PageError> {
        if self.sealed {
            return Err(PageError::PageSealed {
                page_id: self.header.page_id,
            });
        }

        let slot_count = self.header.slot_count as usize;
        let dir_bytes = slot_count * SLOT_DIR_ENTRY_SIZE;
        let needed = SLOT_DIR_ENTRY_SIZE + data.len();

        if (self.header.free_bytes as usize) < needed {
            return Err(PageError::PageFull {
                page_id: self.header.page_id,
                free_bytes: self.header.free_bytes as usize,
                needed,
            });
        }

        // Slot data grows from the end of the page toward the header.
        // Slot directory grows from the header toward the end of the page.
        let body_start = PageHeader::SIZE;
        let data_end = self.page_size - {
            // Sum of all existing slot data lengths
            (0..slot_count)
                .map(|i| {
                    self.read_slot_entry(i)
                        .map(|e| e.length as usize)
                        .unwrap_or(0)
                })
                .sum::<usize>()
        };
        let data_start = data_end - data.len();

        // Write slot data
        self.buf[data_start..data_end].copy_from_slice(data);

        // Write slot directory entry
        let dir_offset = body_start + dir_bytes;
        let slot_offset = (data_start - body_start) as u16;
        self.buf[dir_offset..dir_offset + 2].copy_from_slice(&slot_offset.to_le_bytes());
        self.buf[dir_offset + 2..dir_offset + 4]
            .copy_from_slice(&(data.len() as u16).to_le_bytes());

        self.header.slot_count += 1;
        self.header.free_bytes -= needed as u16;
        Ok((slot_count) as u16)
    }

    /// Read raw bytes for slot at `slot_id`.
    pub fn read_slot(&self, slot_id: u16) -> Result<&[u8], PageError> {
        let entry = self
            .read_slot_entry(slot_id as usize)
            .ok_or(PageError::SlotNotFound {
                page_id: self.header.page_id,
                slot_id,
            })?;
        let body_start = PageHeader::SIZE;
        let start = body_start + entry.offset as usize;
        let end = start + entry.length as usize;
        Ok(&self.buf[start..end])
    }

    /// Seal the page: compute content hash and CRC-32, then make it read-only.
    pub fn seal(&mut self) {
        // 1. Flush all pending slot metadata into the header struct
        self.flush_header();

        // 2. Content hash covers the body area (everything after the 64-byte header)
        let body = &self.buf[PageHeader::SIZE..];
        self.header.content_hash = hash_bytes(body);

        // 3. Set crc32 = 0 in struct, flush so the buffer is clean before CRC
        self.header.crc32 = 0;
        self.flush_header();

        // 4. Compute CRC over header[0..60] + body[64..]
        let crc = self.compute_crc();

        // 5. Write CRC into header struct and buffer (final flush)
        self.header.crc32 = crc;
        self.flush_header();

        self.sealed = true;
    }

    /// Return the raw page bytes (for writing to disk).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// BLAKE3 hash of the entire page buffer (used in Merkle tree).
    pub fn page_hash(&self) -> vledger_crypto::Hash {
        hash_bytes(&self.buf)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn read_slot_entry(&self, index: usize) -> Option<SlotEntry> {
        if index >= self.header.slot_count as usize {
            return None;
        }
        let dir_offset = PageHeader::SIZE + index * SLOT_DIR_ENTRY_SIZE;
        let offset = u16::from_le_bytes(self.buf[dir_offset..dir_offset + 2].try_into().ok()?);
        let length = u16::from_le_bytes(self.buf[dir_offset + 2..dir_offset + 4].try_into().ok()?);
        Some(SlotEntry { offset, length })
    }

    fn flush_header(&mut self) {
        let encoded = bincode::serde::encode_to_vec(
            &self.header,
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .expect("PageHeader serialization must not fail");
        self.buf[..encoded.len()].copy_from_slice(&encoded);
    }

    fn compute_crc(&self) -> u32 {
        // CRC-32 covers:
        //   header bytes [0..60]  (everything before the crc32 field)
        //   page body    [64..]
        let mut h = Crc32Hasher::new();
        h.update(&self.buf[..PageHeader::SIZE - 4]); // header sans crc32 field
        h.update(&self.buf[PageHeader::SIZE..]); // full page body
        h.finalize()
    }

    fn verify_checksum(&self) -> Result<(), PageError> {
        let expected = self.header.crc32;
        let computed = self.compute_crc();
        if computed != expected {
            return Err(PageError::ChecksumMismatch {
                page_id: self.header.page_id,
                expected,
                actual: computed,
            });
        }
        Ok(())
    }

    fn verify_content_hash(&self) -> Result<(), PageError> {
        let body = &self.buf[PageHeader::SIZE..];
        let computed = hash_bytes(body);
        if computed != self.header.content_hash {
            return Err(PageError::ContentHashMismatch {
                page_id: self.header.page_id,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_slot() {
        let mut page = Page::new(1, 42);
        let data = b"hello financial record";
        let slot = page.write_slot(data).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(page.read_slot(0).unwrap(), data);
    }

    #[test]
    fn sealed_page_roundtrip() {
        let mut page = Page::new(7, 1);
        page.write_slot(b"row one").unwrap();
        page.write_slot(b"row two").unwrap();
        page.seal();

        let bytes = page.as_bytes().to_vec();
        let loaded = Page::from_bytes(bytes).unwrap();
        assert_eq!(loaded.read_slot(0).unwrap(), b"row one");
        assert_eq!(loaded.read_slot(1).unwrap(), b"row two");
    }

    #[test]
    fn tampered_page_fails_checksum() {
        let mut page = Page::new(1, 1);
        page.write_slot(b"sensitive data").unwrap();
        page.seal();

        let mut bytes = page.as_bytes().to_vec();
        // Flip a bit in the slot data area
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        assert!(Page::from_bytes(bytes).is_err());
    }
}
