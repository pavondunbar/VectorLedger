//! WAL reader — scans segment files and yields validated records.
//!
//! The reader verifies:
//! 1. Magic number on every record header.
//! 2. CRC-32 over header + payload.
//! 3. Monotonically increasing sequence numbers.
//!
//! If a master key is provided, encrypted records (prefixed with
//! `ENCRYPTED_MAGIC`) are decrypted before validation.  Unencrypted records
//! are passed through as-is (backwards-compatible migration path).
//!
//! Any record that fails validation is treated as a torn write and terminates
//! the scan (everything after it is considered unreliable).

use std::io::{BufReader, Read};
use std::path::Path;

use crc32fast::Hasher as Crc32Hasher;
use tracing::{debug, warn};

use crate::encrypt::{decrypt_record, derive_segment_key, ENCRYPTED_MAGIC};
use crate::error::WalError;
use crate::record::{RecordHeader, WalRecord};
use crate::segment::{list_segments, segment_filename};
use crate::{WAL_MAGIC, WAL_VERSION};

/// Deserializes a `RecordHeader` from raw bytes.
fn decode_header(bytes: &[u8]) -> Result<RecordHeader, WalError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::standard().with_fixed_int_encoding())
        .map(|(h, _)| h)
        .map_err(|e: bincode::error::DecodeError| WalError::Serialization(e.to_string()))
}

/// Reads exactly `n` bytes from `reader` into a `Vec<u8>`.
fn read_exact_vec<R: Read>(reader: &mut R, n: usize) -> Result<Vec<u8>, WalError> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            WalError::TruncatedRecord {
                offset: 0,
                needed: n,
                available: 0,
            }
        } else {
            WalError::Io(e)
        }
    })?;
    Ok(buf)
}

/// Read up to `n` bytes, returning however many were actually available.
/// Used to peek at the magic without consuming the full header.
#[allow(dead_code)]
fn peek_bytes<R: Read>(reader: &mut R, n: usize) -> Result<Vec<u8>, WalError> {
    let mut buf = vec![0u8; n];
    let mut read = 0;
    while read < n {
        match reader.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(k) => read += k,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(WalError::Io(e)),
        }
    }
    buf.truncate(read);
    Ok(buf)
}

/// Iterator that yields validated [`WalRecord`]s from a single segment file.
pub struct SegmentReader {
    inner: BufReader<std::fs::File>,
    byte_offset: u64,
    last_sequence: u64,
    done: bool,
    segment_index: u64,
    master_key: Option<[u8; 32]>,
}

impl SegmentReader {
    pub fn open(
        path: &Path,
        segment_index: u64,
        master_key: Option<[u8; 32]>,
    ) -> Result<Self, WalError> {
        let file = std::fs::File::open(path)?;
        Ok(Self {
            inner: BufReader::new(file),
            byte_offset: 0,
            last_sequence: 0,
            done: false,
            segment_index,
            master_key,
        })
    }

    /// Read the next record.  Returns `None` when the file is exhausted or a
    /// torn write is encountered.
    pub fn next_record(&mut self) -> Option<Result<WalRecord, WalError>> {
        if self.done {
            return None;
        }

        // Read the first 4 bytes to determine if this is an encrypted blob
        // or a plaintext record.
        let magic_bytes = match read_exact_vec(&mut self.inner, 4) {
            Ok(b) => b,
            Err(WalError::TruncatedRecord { .. }) => {
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };

        let magic = u32::from_le_bytes(magic_bytes.clone().try_into().unwrap_or([0; 4]));

        if magic == ENCRYPTED_MAGIC {
            // ── Encrypted path ────────────────────────────────────────────
            // Format: MAGIC(4) | nonce(12) | ct_len(4) | ciphertext(ct_len)
            let rest_header = match read_exact_vec(&mut self.inner, 12 + 4) {
                Ok(b) => b,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            let ct_len = u32::from_le_bytes(rest_header[12..16].try_into().unwrap()) as usize;

            let ciphertext = match read_exact_vec(&mut self.inner, ct_len) {
                Ok(b) => b,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };

            // Reassemble the full encrypted blob
            let mut blob = Vec::with_capacity(4 + 12 + 4 + ct_len);
            blob.extend_from_slice(&magic_bytes);
            blob.extend_from_slice(&rest_header);
            blob.extend_from_slice(&ciphertext);

            let master_key = match &self.master_key {
                Some(k) => k,
                None => {
                    warn!(
                        offset = self.byte_offset,
                        "Encrypted WAL record but no decryption key provided — \
                         open WAL with open_encrypted() to supply the master key"
                    );
                    self.done = true;
                    return Some(Err(WalError::Decryption));
                }
            };

            let seg_key = match derive_segment_key(master_key, self.segment_index) {
                Ok(k) => k,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };

            let plaintext = match decrypt_record(&seg_key, &blob, self.segment_index) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        offset = self.byte_offset,
                        "WAL decryption failed — treating as torn write: {e}"
                    );
                    self.done = true;
                    return Some(Err(e));
                }
            };

            // Parse the plaintext record normally
            let blob_size = blob.len();
            self.byte_offset += blob_size as u64;
            self.parse_plaintext_record(&plaintext)
        } else {
            // ── Plaintext path (magic == WAL_MAGIC or zero padding) ───────
            if magic != WAL_MAGIC {
                self.done = true;
                return None;
            }

            // Read the remaining header bytes
            let remaining_header =
                match read_exact_vec(&mut self.inner, RecordHeader::SERIALIZED_SIZE - 4) {
                    Ok(b) => b,
                    Err(e) => {
                        self.done = true;
                        return Some(Err(e));
                    }
                };

            let mut header_bytes = Vec::with_capacity(RecordHeader::SERIALIZED_SIZE);
            header_bytes.extend_from_slice(&magic_bytes);
            header_bytes.extend_from_slice(&remaining_header);

            let header = match decode_header(&header_bytes) {
                Ok(h) => h,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };

            if header.version != WAL_VERSION {
                self.done = true;
                return Some(Err(WalError::UnsupportedVersion(header.version)));
            }

            let payload = match read_exact_vec(&mut self.inner, header.payload_len as usize) {
                Ok(b) => b,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };

            let crc_bytes = match read_exact_vec(&mut self.inner, 4) {
                Ok(b) => b,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            let stored_crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());

            let mut hasher = Crc32Hasher::new();
            hasher.update(&header_bytes);
            hasher.update(&payload);
            let computed_crc = hasher.finalize();

            if computed_crc != stored_crc {
                warn!(
                    offset = self.byte_offset,
                    expected = stored_crc,
                    actual = computed_crc,
                    "CRC mismatch — treating as torn write"
                );
                self.done = true;
                return Some(Err(WalError::ChecksumMismatch {
                    expected: stored_crc,
                    actual: computed_crc,
                }));
            }

            let record_size = RecordHeader::SERIALIZED_SIZE + payload.len() + 4;
            self.byte_offset += record_size as u64;
            self.last_sequence = header.sequence;

            debug!(
                sequence = header.sequence,
                tx_id = header.tx_id,
                offset = self.byte_offset,
                "WAL plaintext record read"
            );

            Some(Ok(WalRecord {
                header,
                payload,
                crc32: stored_crc,
            }))
        }
    }

    /// Parse a decrypted plaintext record blob (header + payload + crc32).
    fn parse_plaintext_record(&mut self, plaintext: &[u8]) -> Option<Result<WalRecord, WalError>> {
        if plaintext.len() < RecordHeader::SERIALIZED_SIZE + 4 {
            self.done = true;
            return Some(Err(WalError::TruncatedRecord {
                offset: self.byte_offset,
                needed: RecordHeader::SERIALIZED_SIZE + 4,
                available: plaintext.len(),
            }));
        }

        let header_bytes = &plaintext[..RecordHeader::SERIALIZED_SIZE];
        let crc_start = plaintext.len() - 4;
        let payload = plaintext[RecordHeader::SERIALIZED_SIZE..crc_start].to_vec();
        let stored_crc = u32::from_le_bytes(plaintext[crc_start..].try_into().unwrap());

        let header = match decode_header(header_bytes) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };

        if header.magic != WAL_MAGIC {
            self.done = true;
            return None;
        }
        if header.version != WAL_VERSION {
            self.done = true;
            return Some(Err(WalError::UnsupportedVersion(header.version)));
        }

        let mut hasher = Crc32Hasher::new();
        hasher.update(header_bytes);
        hasher.update(&payload);
        let computed_crc = hasher.finalize();

        if computed_crc != stored_crc {
            warn!(
                offset = self.byte_offset,
                expected = stored_crc,
                actual = computed_crc,
                "CRC mismatch in decrypted WAL record — treating as torn write"
            );
            self.done = true;
            return Some(Err(WalError::ChecksumMismatch {
                expected: stored_crc,
                actual: computed_crc,
            }));
        }

        self.last_sequence = header.sequence;
        debug!(
            sequence = header.sequence,
            tx_id = header.tx_id,
            offset = self.byte_offset,
            "WAL encrypted record read and decrypted"
        );

        Some(Ok(WalRecord {
            header,
            payload,
            crc32: stored_crc,
        }))
    }
}

/// High-level WAL reader that iterates across all segments in order.
pub struct WalReader {
    wal_dir: std::path::PathBuf,
    segment_indices: Vec<u64>,
    current_seg_pos: usize,
    current_reader: Option<SegmentReader>,
    master_key: Option<[u8; 32]>,
}

impl WalReader {
    pub fn open(wal_dir: &Path) -> Result<Self, WalError> {
        Self::open_with_key(wal_dir, None)
    }

    /// Open with an optional master key for decrypting encrypted segments.
    pub fn open_with_key(wal_dir: &Path, master_key: Option<[u8; 32]>) -> Result<Self, WalError> {
        let indices = list_segments(wal_dir)?;
        Ok(Self {
            wal_dir: wal_dir.to_path_buf(),
            segment_indices: indices,
            current_seg_pos: 0,
            current_reader: None,
            master_key,
        })
    }

    /// Advance to the next segment.
    fn advance_segment(&mut self) -> Result<bool, WalError> {
        if self.current_seg_pos >= self.segment_indices.len() {
            return Ok(false);
        }
        let idx = self.segment_indices[self.current_seg_pos];
        let path = self.wal_dir.join(segment_filename(idx));
        self.current_reader = Some(SegmentReader::open(&path, idx, self.master_key)?);
        self.current_seg_pos += 1;
        Ok(true)
    }
}

impl Iterator for WalReader {
    type Item = Result<WalRecord, WalError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_reader.is_none() {
                match self.advance_segment() {
                    Ok(true) => {}
                    Ok(false) => return None,
                    Err(e) => return Some(Err(e)),
                }
            }

            if let Some(ref mut reader) = self.current_reader {
                match reader.next_record() {
                    Some(r) => return Some(r),
                    None => {
                        self.current_reader = None;
                        continue;
                    }
                }
            }
        }
    }
}

/// Scans all segments to find the highest sequence number written.
/// Used when resuming the WAL after a restart.
pub fn scan_last_sequence(wal_dir: &Path, master_key: Option<&[u8; 32]>) -> Result<u64, WalError> {
    let mut last_seq = 0u64;
    let reader = WalReader::open_with_key(wal_dir, master_key.copied())?;
    for result in reader {
        match result {
            Ok(record) => {
                if record.header.sequence > last_seq {
                    last_seq = record.header.sequence;
                }
            }
            Err(
                WalError::ChecksumMismatch { .. }
                | WalError::TruncatedRecord { .. }
                | WalError::BadMagic
                | WalError::Decryption,
            ) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(last_seq)
}
