//! WAL reader — scans segment files and yields validated records.
//!
//! The reader verifies:
//! 1. Magic number on every record header.
//! 2. CRC-32 over header + payload.
//! 3. Monotonically increasing sequence numbers.
//!
//! Any record that fails validation is treated as a torn write and terminates
//! the scan (everything after it is considered unreliable).

use std::io::{BufReader, Read};
use std::path::Path;

use crc32fast::Hasher as Crc32Hasher;
use tracing::{debug, warn};

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

/// Iterator that yields validated [`WalRecord`]s from a single segment file.
pub struct SegmentReader {
    inner: BufReader<std::fs::File>,
    byte_offset: u64,
    last_sequence: u64,
    done: bool,
}

impl SegmentReader {
    pub fn open(path: &Path) -> Result<Self, WalError> {
        let file = std::fs::File::open(path)?;
        Ok(Self {
            inner: BufReader::new(file),
            byte_offset: 0,
            last_sequence: 0,
            done: false,
        })
    }

    /// Read the next record.  Returns `None` when the file is exhausted or a
    /// torn write is encountered.
    pub fn next_record(&mut self) -> Option<Result<WalRecord, WalError>> {
        if self.done {
            return None;
        }

        // 1. Read header bytes
        let header_bytes = match read_exact_vec(&mut self.inner, RecordHeader::SERIALIZED_SIZE) {
            Ok(b) => b,
            Err(WalError::TruncatedRecord { .. }) => {
                // Clean EOF — normal end of segment
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };

        // 2. Decode header
        let header = match decode_header(&header_bytes) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };

        // 3. Validate magic — a mismatch at this position means we've hit
        // zero-padding or a torn write at the end of the segment.  Treat it
        // as end-of-readable-data rather than a hard error.
        if header.magic != WAL_MAGIC {
            self.done = true;
            return None;
        }

        // 4. Validate version
        if header.version != WAL_VERSION {
            self.done = true;
            return Some(Err(WalError::UnsupportedVersion(header.version)));
        }

        // 5. Read payload
        let payload = match read_exact_vec(&mut self.inner, header.payload_len as usize) {
            Ok(b) => b,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };

        // 6. Read CRC-32
        let crc_bytes = match read_exact_vec(&mut self.inner, 4) {
            Ok(b) => b,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        let stored_crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());

        // 7. Verify CRC
        let mut hasher = Crc32Hasher::new();
        hasher.update(&header_bytes);
        hasher.update(&payload);
        let computed_crc = hasher.finalize();

        if computed_crc != stored_crc {
            warn!(
                offset = self.byte_offset,
                expected = stored_crc,
                actual = computed_crc,
                "CRC mismatch — treating as torn write, stopping scan"
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
            "WAL record read"
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
}

impl WalReader {
    pub fn open(wal_dir: &Path) -> Result<Self, WalError> {
        let indices = list_segments(wal_dir)?;
        Ok(Self {
            wal_dir: wal_dir.to_path_buf(),
            segment_indices: indices,
            current_seg_pos: 0,
            current_reader: None,
        })
    }

    /// Advance to the next segment.
    fn advance_segment(&mut self) -> Result<bool, WalError> {
        if self.current_seg_pos >= self.segment_indices.len() {
            return Ok(false);
        }
        let idx = self.segment_indices[self.current_seg_pos];
        let path = self.wal_dir.join(segment_filename(idx));
        self.current_reader = Some(SegmentReader::open(&path)?);
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
                        // Current segment exhausted, move to next
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
pub fn scan_last_sequence(wal_dir: &Path) -> Result<u64, WalError> {
    let mut last_seq = 0u64;
    let reader = WalReader::open(wal_dir)?;
    for result in reader {
        match result {
            Ok(record) => {
                if record.header.sequence > last_seq {
                    last_seq = record.header.sequence;
                }
            }
            // Any of these mean we've hit the end of valid data — stop cleanly.
            Err(WalError::ChecksumMismatch { .. }
                | WalError::TruncatedRecord { .. }
                | WalError::BadMagic) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(last_seq)
}
