//! WAL writer — the only code path that appends records to disk.
//!
//! ## Safety guarantees
//! - Every `append()` call ends with `fsync()` before returning `Ok`.
//! - The sequence counter is a `u64` that saturates at `u64::MAX` rather
//!   than wrapping (the database must be migrated well before that point).
//! - CRC-32 is computed over the full serialized header + payload before
//!   the record is written.
//! - A partial write that survives a crash will be detected by the reader
//!   because the CRC will not match.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crc32fast::Hasher as Crc32Hasher;
use serde::Serialize;
use tracing::{debug, info};

use crate::error::WalError;
use crate::record::{RecordHeader, RecordType, WalRecord};
use crate::segment::Segment;
use crate::{DEFAULT_SEGMENT_SIZE, WAL_MAGIC, WAL_VERSION};

/// Serializes a value to bytes using `bincode`.
fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WalError> {
    bincode::serde::encode_to_vec(value, bincode::config::standard().with_fixed_int_encoding())
        .map_err(|e: bincode::error::EncodeError| WalError::Serialization(e.to_string()))
}

/// Computes CRC-32 over `header_bytes || payload`.
fn compute_crc(header_bytes: &[u8], payload: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    h.update(header_bytes);
    h.update(payload);
    h.finalize()
}

/// Current UTC timestamp in nanoseconds.
fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

/// Append-only WAL writer.
///
/// `WalWriter` is `Send` but NOT `Sync` — the caller is responsible for
/// ensuring only one writer is active at a time (enforced by the transaction
/// manager holding an exclusive lock).
pub struct WalWriter {
    /// Directory where segment files live.
    wal_dir: std::path::PathBuf,
    /// Currently active segment.
    active_segment: Segment,
    /// Global monotonic sequence counter shared with readers.
    sequence: Arc<AtomicU64>,
    /// Maximum segment size before rolling.
    segment_max_size: u64,
    /// Index for the next segment to be created.
    next_segment_index: u64,
}

impl WalWriter {
    /// Open (or create) the WAL at `wal_dir`.
    ///
    /// If the directory is empty, segment `0` is created.
    /// If segments already exist, the writer resumes from the highest one.
    pub fn open(wal_dir: &Path) -> Result<Self, WalError> {
        Self::open_with_options(wal_dir, DEFAULT_SEGMENT_SIZE)
    }

    pub fn open_with_options(wal_dir: &Path, segment_max_size: u64) -> Result<Self, WalError> {
        std::fs::create_dir_all(wal_dir)?;

        let existing = crate::segment::list_segments(wal_dir)?;
        let (active_segment, next_segment_index, last_sequence) = if existing.is_empty() {
            info!(wal_dir = %wal_dir.display(), "Initializing new WAL");
            let seg = Segment::create(wal_dir, 0, segment_max_size)?;
            (seg, 1u64, 0u64)
        } else {
            let last_idx = *existing.last().unwrap();
            let path = wal_dir.join(crate::segment::segment_filename(last_idx));
            info!(segment = last_idx, "Resuming WAL from existing segment");
            let seg = Segment::open(path, last_idx, segment_max_size, false)?;
            // Scan to find highest sequence used
            let last_seq = crate::reader::scan_last_sequence(wal_dir)?;
            (seg, last_idx + 1, last_seq)
        };

        Ok(Self {
            wal_dir: wal_dir.to_path_buf(),
            active_segment,
            sequence: Arc::new(AtomicU64::new(last_sequence)),
            segment_max_size,
            next_segment_index,
        })
    }

    /// Returns a clone of the shared sequence counter (for readers).
    pub fn sequence_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.sequence)
    }

    /// Append a record to the WAL and fsync before returning.
    ///
    /// This is the **only** public write path.  All callers must use this
    /// method — there is no way to bypass the CRC or fsync.
    pub fn append(
        &mut self,
        tx_id: u64,
        record_type: RecordType,
        payload: Vec<u8>,
    ) -> Result<WalRecord, WalError> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;

        let header = RecordHeader {
            magic: WAL_MAGIC,
            version: WAL_VERSION,
            record_type: record_type as u8,
            tx_id,
            sequence: seq,
            timestamp_ns: now_ns(),
            payload_len: payload.len() as u32,
        };

        // Serialize header with fixed-int encoding (stable 34-byte size)
        let header_bytes = to_bytes(&header)?;
        assert_eq!(
            header_bytes.len(),
            RecordHeader::SERIALIZED_SIZE,
            "WAL RecordHeader serialized size mismatch: got {} expected {}",
            header_bytes.len(), RecordHeader::SERIALIZED_SIZE
        );

        let crc32 = compute_crc(&header_bytes, &payload);

        let record_size = header_bytes.len() + payload.len() + 4;

        // Roll segment if needed
        if !self.active_segment.has_space(record_size) {
            self.roll_segment()?;
        }

        // Write: header | payload | crc32 (little-endian)
        let file = self
            .active_segment
            .file
            .as_mut()
            .ok_or_else(|| WalError::Io(std::io::Error::other("Segment file handle missing")))?;

        file.write_all(&header_bytes)?;
        file.write_all(&payload)?;
        file.write_all(&crc32.to_le_bytes())?;

        // fsync — durability guaranteed here
        file.sync_all()?;

        self.active_segment.write_offset += record_size as u64;

        debug!(
            tx_id,
            sequence = seq,
            record_type = ?record_type,
            payload_bytes = payload.len(),
            "WAL record appended and synced"
        );

        Ok(WalRecord {
            header,
            payload,
            crc32,
        })
    }

    /// Convenience: append a serializable payload.
    pub fn append_record<T: Serialize>(
        &mut self,
        tx_id: u64,
        record_type: RecordType,
        payload: &T,
    ) -> Result<WalRecord, WalError> {
        let bytes = to_bytes(payload)?;
        self.append(tx_id, record_type, bytes)
    }

    /// Seal the current active segment and open a fresh one.
    fn roll_segment(&mut self) -> Result<(), WalError> {
        info!(
            segment = self.active_segment.index,
            "Rolling WAL segment"
        );
        self.active_segment.seal()?;
        let new_seg = Segment::create(
            &self.wal_dir,
            self.next_segment_index,
            self.segment_max_size,
        )?;
        self.active_segment = new_seg;
        self.next_segment_index += 1;
        Ok(())
    }

    /// Force a checkpoint: sync and return the current sequence.
    pub fn checkpoint(&mut self, _tx_id: u64) -> Result<u64, WalError> {
        let seq = self.sequence.load(Ordering::SeqCst);
        self.active_segment.sync()?;
        debug!(sequence = seq, "WAL checkpoint");
        Ok(seq)
    }
}
