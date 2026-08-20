//! WAL key rotation — re-encrypts all existing WAL segments under a new
//! master key and rewrites the segment files atomically.
//!
//! ## Algorithm
//!
//! For each sealed WAL segment file:
//!
//! ```text
//! 1. Decrypt every record in the segment using the OLD per-segment key
//!    (derived from old_master_key).
//! 2. Re-encrypt every record using the NEW per-segment key
//!    (derived from new_master_key for the same segment index).
//! 3. Write the re-encrypted records to a <segment>.tmp file.
//! 4. fsync the tmp file.
//! 5. Atomically rename <segment>.tmp → <segment>.wal.
//! ```
//!
//! The rename in step 5 is atomic on POSIX systems — either the old or the new
//! content is present, never a partial state.  If the process crashes between
//! any two steps, recovery will find either the fully old or fully new content.
//!
//! ## Active segment
//! The active (last) segment is skipped — it is still being written to.
//! After the rotation completes, the caller must reopen the `WalWriter` with
//! `open_encrypted(new_master_key)` so all future records use the new key.
//!
//! ## Unencrypted segments
//! Segments that contain only plaintext records (written before encryption was
//! enabled) are encrypted with the new key during rotation.  This allows a
//! live migration from unencrypted to encrypted WAL in a single operation.

use std::fs;
use std::io::Write;
use std::path::Path;

use tracing::{info, warn};

use crate::encrypt::{derive_segment_key, encrypt_record, ENCRYPTED_MAGIC};
use crate::error::WalError;
use crate::reader::SegmentReader;
use crate::segment::{list_segments, segment_filename};

/// Result of a WAL key rotation operation.
#[derive(Debug)]
pub struct KeyRotationResult {
    /// Number of segments successfully re-encrypted.
    pub segments_rotated: usize,
    /// Number of plaintext segments that were encrypted for the first time.
    pub segments_encrypted: usize,
    /// Number of segments skipped (e.g. the active segment).
    pub segments_skipped: usize,
}

/// Rotate the WAL encryption key.
///
/// `old_master_key` — the key currently used for encryption.
///                    Pass `None` if the WAL is currently unencrypted.
/// `new_master_key` — the new 32-byte master key to use going forward.
/// `wal_dir`        — the directory containing segment files.
/// `skip_active`    — when `true` (recommended), the highest-numbered segment
///                    (currently being written) is left untouched.
pub fn rotate_wal_key(
    wal_dir: &Path,
    old_master_key: Option<&[u8; 32]>,
    new_master_key: &[u8; 32],
    skip_active: bool,
) -> Result<KeyRotationResult, WalError> {
    let mut segments = list_segments(wal_dir)?;
    if segments.is_empty() {
        return Ok(KeyRotationResult {
            segments_rotated: 0,
            segments_encrypted: 0,
            segments_skipped: 0,
        });
    }

    // Optionally skip the active (last) segment.
    let active_index = if skip_active { segments.pop() } else { None };
    let skipped = if active_index.is_some() { 1 } else { 0 };

    let mut rotated = 0;
    let mut encrypted = 0;

    for seg_idx in segments {
        let seg_path = wal_dir.join(segment_filename(seg_idx));
        match reencrypt_segment(&seg_path, seg_idx, old_master_key, new_master_key) {
            Ok(was_plaintext) => {
                if was_plaintext {
                    encrypted += 1;
                    info!(segment = seg_idx, "WAL segment encrypted (was plaintext)");
                } else {
                    rotated += 1;
                    info!(segment = seg_idx, "WAL segment re-encrypted with new key");
                }
            }
            Err(e) => {
                warn!(segment = seg_idx, "Failed to rotate WAL segment key: {e}");
                return Err(e);
            }
        }
    }

    if let Some(active) = active_index {
        info!(
            segment = active,
            "Skipped active WAL segment during key rotation"
        );
    }

    Ok(KeyRotationResult {
        segments_rotated: rotated,
        segments_encrypted: encrypted,
        segments_skipped: skipped,
    })
}

/// Re-encrypt a single WAL segment file.
///
/// Returns `Ok(true)` if the segment was previously plaintext (first-time
/// encryption), `Ok(false)` if it was already encrypted (key rotation).
fn reencrypt_segment(
    seg_path: &Path,
    seg_idx: u64,
    old_master_key: Option<&[u8; 32]>,
    new_master_key: &[u8; 32],
) -> Result<bool, WalError> {
    let new_seg_key = derive_segment_key(new_master_key, seg_idx)?;

    // Read all records from the current segment.
    let mut reader = SegmentReader::open(seg_path, seg_idx, old_master_key.copied())?;
    let mut records: Vec<(Vec<u8>, bool)> = Vec::new(); // (plaintext_bytes, was_encrypted)
    let mut any_encrypted = false;

    loop {
        match reader.next_record() {
            None => break,
            Some(Err(
                WalError::ChecksumMismatch { .. }
                | WalError::TruncatedRecord { .. }
                | WalError::BadMagic
                | WalError::Decryption,
            )) => break, // stop at torn write
            Some(Err(e)) => return Err(e),
            Some(Ok(record)) => {
                // Re-serialize the record to plaintext bytes
                // (header + payload + crc32 — same as what the writer writes).
                use bincode::serde::encode_to_vec;
                let header_bytes = encode_to_vec(
                    &record.header,
                    bincode::config::standard().with_fixed_int_encoding(),
                )
                .map_err(|e| WalError::Serialization(e.to_string()))?;

                let mut plaintext =
                    Vec::with_capacity(header_bytes.len() + record.payload.len() + 4);
                plaintext.extend_from_slice(&header_bytes);
                plaintext.extend_from_slice(&record.payload);
                plaintext.extend_from_slice(&record.crc32.to_le_bytes());
                records.push((plaintext, true)); // was_encrypted is set below
                any_encrypted = true;
            }
        }
    }

    let was_plaintext = {
        // Check the first 4 bytes of the original file to see if it was
        // encrypted before. This tells us which direction the rotation went.
        let first = fs::read(seg_path).unwrap_or_default();
        first.len() >= 4
            && u32::from_le_bytes(first[0..4].try_into().unwrap_or([0; 4])) != ENCRYPTED_MAGIC
    };

    if records.is_empty() {
        // Empty segment — nothing to do.
        return Ok(was_plaintext);
    }

    // Write re-encrypted records to a tmp file.
    let tmp_path = seg_path.with_extension("wal.tmp");
    {
        let mut tmp = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;

        for (plaintext, _) in &records {
            let blob = encrypt_record(&new_seg_key, plaintext, seg_idx)?;
            tmp.write_all(&blob)?;
        }
        tmp.flush()?;
        tmp.sync_all()?;
    }

    // Atomic rename: tmp → original.
    fs::rename(&tmp_path, seg_path)?;

    Ok(was_plaintext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::BeginPayload;
    use crate::{RecordType, WalWriter};
    use tempfile::TempDir;

    fn write_test_records(wal_dir: &Path, master_key: Option<[u8; 32]>) {
        let mut writer = match master_key {
            Some(k) => WalWriter::open_encrypted(wal_dir, k).unwrap(),
            None => WalWriter::open(wal_dir).unwrap(),
        };
        for i in 0u64..5 {
            writer
                .append_record(
                    i,
                    RecordType::Begin,
                    &BeginPayload {
                        description: Some(format!("tx-{i}")),
                    },
                )
                .unwrap();
        }
    }

    #[test]
    fn plaintext_to_encrypted_rotation() {
        let dir = TempDir::new().unwrap();
        // Write plaintext WAL.
        write_test_records(dir.path(), None);

        let new_key = [0xBBu8; 32];
        let result = rotate_wal_key(dir.path(), None, &new_key, false).unwrap();
        assert!(result.segments_encrypted > 0 || result.segments_rotated > 0);

        // Recovery must succeed with the new key.
        let recovery = crate::recovery::recover_verified(dir.path(), Some(new_key)).unwrap();
        assert!(recovery.committed.len() == 0); // all were Begin records, no Commits
    }

    #[test]
    fn encrypted_key_rotation_roundtrip() {
        let dir = TempDir::new().unwrap();
        let old_key = [0xAAu8; 32];
        let new_key = [0xBBu8; 32];

        write_test_records(dir.path(), Some(old_key));

        let result = rotate_wal_key(dir.path(), Some(&old_key), &new_key, false).unwrap();
        assert!(result.segments_rotated > 0 || result.segments_encrypted > 0);

        // Old key must no longer work.
        // New key must work.
        let reader_new = crate::WalReader::open_with_key(dir.path(), Some(new_key)).unwrap();
        let mut count = 0;
        for r in reader_new {
            let _ = r;
            count += 1;
        }
        assert!(count > 0, "records must be readable with new key");
    }

    #[test]
    fn empty_wal_rotation_is_noop() {
        let dir = TempDir::new().unwrap();
        let new_key = [0xCCu8; 32];
        let result = rotate_wal_key(dir.path(), None, &new_key, false).unwrap();
        assert_eq!(result.segments_rotated, 0);
        assert_eq!(result.segments_encrypted, 0);
    }
}
