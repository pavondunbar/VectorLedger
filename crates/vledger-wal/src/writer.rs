//! WAL writer — the only code path that appends records to disk.
//!
//! ## Sync modes
//!
//! | Mode | fsync behaviour | Durability | Typical TPS |
//! |---|---|---|---|
//! | `PerRecord` | after every `append()` | strongest (no data loss on crash) | baseline |
//! | `GroupCommit` | background flush every `group_commit_delay_ms` | up to 1 WAL flush worth of data loss on hard crash | 5–20× faster |
//! | `NoSync` | never | none (dev / test only) | fastest |
//!
//! `GroupCommit` is the recommended production mode for most deployments.
//! It matches PostgreSQL's default `synchronous_commit = off` behaviour:
//! a hard power-loss can lose the last few milliseconds of committed
//! transactions, but the database remains consistent and restartable.
//!
//! ## Safety guarantees (all modes)
//! - CRC-32 is computed over the full serialized header + payload before
//!   the record is written, so a partial write is always detected on recovery.
//! - The sequence counter saturates at `u64::MAX` rather than wrapping.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crc32fast::Hasher as Crc32Hasher;
use serde::Serialize;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::encrypt::{derive_segment_key, encrypt_record};
use crate::error::WalError;
use crate::record::{CheckpointPayload, RecordHeader, RecordType, WalRecord};
use crate::segment::Segment;
use crate::{DEFAULT_SEGMENT_SIZE, WAL_MAGIC, WAL_VERSION};

// ── WalSyncMode ───────────────────────────────────────────────────────────────

/// Controls when the WAL calls `fsync` to commit writes to stable storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalSyncMode {
    /// `fsync` after every single record append.
    ///
    /// Strongest durability: zero data loss on crash.
    /// Slowest throughput: every write pays full disk latency.
    PerRecord,

    /// Accumulate writes in the OS page cache and `fsync` on a background
    /// timer (default: every 2 ms).
    ///
    /// A hard crash can lose at most `group_commit_delay_ms` worth of
    /// committed transactions, but the WAL remains consistent — no
    /// corruption, just a small rollback window.
    ///
    /// This is the recommended mode for most production deployments and
    /// matches PostgreSQL's `synchronous_commit = off` default behaviour.
    GroupCommit,

    /// Never call `fsync`.
    ///
    /// **Development and testing only.**  Any crash will likely corrupt or
    /// lose data.  Never use in production.
    NoSync,
}

impl Default for WalSyncMode {
    fn default() -> Self {
        Self::GroupCommit
    }
}

impl std::fmt::Display for WalSyncMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerRecord => write!(f, "per_record"),
            Self::GroupCommit => write!(f, "group_commit"),
            Self::NoSync => write!(f, "no_sync"),
        }
    }
}

impl std::str::FromStr for WalSyncMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "per_record" | "fsync" => Ok(Self::PerRecord),
            "group_commit" | "group" => Ok(Self::GroupCommit),
            "no_sync" | "none" => Ok(Self::NoSync),
            other => Err(format!(
                "unknown wal_sync_mode '{other}' — use: per_record, group_commit, no_sync"
            )),
        }
    }
}

// ── Shared flush state (group commit) ────────────────────────────────────────

/// Shared state between `WalWriter` and the background flush task.
///
/// The background task calls `flush()` periodically; `WalWriter::append()`
/// signals `dirty` after each write so the task knows there is work to do.
pub struct FlushState {
    /// Set to `true` after any un-fsynced write.
    pub dirty: AtomicBool,
    /// Notified when the background task should exit (server shutdown).
    pub shutdown: Notify,
}

impl FlushState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            dirty: AtomicBool::new(false),
            shutdown: Notify::new(),
        })
    }
}

// ── Shared segment handle for background flusher ──────────────────────────────

/// A `Sync`-safe handle to the active segment file used by the background
/// flush task.  Protected by a `std::sync::Mutex` (not tokio) because the
/// flusher runs in a `tokio::task::spawn_blocking` context.
pub type SharedSegment = Arc<std::sync::Mutex<Option<std::fs::File>>>;

// ── Serialization helpers ─────────────────────────────────────────────────────

fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WalError> {
    bincode::serde::encode_to_vec(value, bincode::config::standard().with_fixed_int_encoding())
        .map_err(|e: bincode::error::EncodeError| WalError::Serialization(e.to_string()))
}

fn compute_crc(header_bytes: &[u8], payload: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    h.update(header_bytes);
    h.update(payload);
    h.finalize()
}

fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

// ── WalWriter ─────────────────────────────────────────────────────────────────

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
    /// Sync mode — controls when fsync is called.
    pub sync_mode: WalSyncMode,
    /// Shared flush state used by the group-commit background task.
    /// `None` when sync_mode != GroupCommit.
    pub flush_state: Option<Arc<FlushState>>,
    /// Optional master key for AES-256-GCM per-segment encryption.
    /// When `Some`, every record is encrypted before being written to disk.
    /// When `None`, records are written in plaintext (dev / legacy mode).
    encryption_key: Option<[u8; 32]>,
}

impl WalWriter {
    /// Open (or create) the WAL at `wal_dir` with the default sync mode
    /// (`GroupCommit`).
    pub fn open(wal_dir: &Path) -> Result<Self, WalError> {
        Self::open_with_options(wal_dir, DEFAULT_SEGMENT_SIZE, WalSyncMode::default(), None)
    }

    /// Open with encryption enabled.  All records written through this writer
    /// will be AES-256-GCM encrypted on disk.  Pass the database master key —
    /// per-segment keys are derived automatically via HKDF.
    pub fn open_encrypted(wal_dir: &Path, master_key: [u8; 32]) -> Result<Self, WalError> {
        Self::open_with_options(
            wal_dir,
            DEFAULT_SEGMENT_SIZE,
            WalSyncMode::default(),
            Some(master_key),
        )
    }

    /// Open with explicit options.
    pub fn open_with_options(
        wal_dir: &Path,
        segment_max_size: u64,
        sync_mode: WalSyncMode,
        master_key: Option<[u8; 32]>,
    ) -> Result<Self, WalError> {
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
            let last_seq = crate::reader::scan_last_sequence(wal_dir, master_key.as_ref())?;
            (seg, last_idx + 1, last_seq)
        };

        let flush_state = if sync_mode == WalSyncMode::GroupCommit {
            Some(FlushState::new())
        } else {
            None
        };

        let encrypted = master_key.is_some();
        info!(sync_mode = %sync_mode, encrypted, "WAL opened");

        Ok(Self {
            wal_dir: wal_dir.to_path_buf(),
            active_segment,
            sequence: Arc::new(AtomicU64::new(last_sequence)),
            segment_max_size,
            next_segment_index,
            sync_mode,
            flush_state,
            encryption_key: master_key,
        })
    }

    /// Returns a clone of the shared sequence counter (for readers).
    pub fn sequence_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.sequence)
    }

    /// Append a record to the WAL.
    ///
    /// Whether an fsync is issued immediately depends on `sync_mode`:
    /// - `PerRecord`  → fsync before returning.
    /// - `GroupCommit`→ write to OS buffer; background task fsyncs later.
    /// - `NoSync`     → write to OS buffer; never fsynced (dev only).
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

        let header_bytes = to_bytes(&header)?;
        assert_eq!(
            header_bytes.len(),
            RecordHeader::SERIALIZED_SIZE,
            "WAL RecordHeader size mismatch: got {} expected {}",
            header_bytes.len(),
            RecordHeader::SERIALIZED_SIZE
        );

        let crc32 = compute_crc(&header_bytes, &payload);
        let record_size = header_bytes.len() + payload.len() + 4;

        // If encryption is enabled, encrypt the entire plaintext record
        // (header + payload + crc32) and write the encrypted blob instead.
        if let Some(master_key) = self.encryption_key {
            // Assemble the plaintext record bytes
            let mut plaintext = Vec::with_capacity(header_bytes.len() + payload.len() + 4);
            plaintext.extend_from_slice(&header_bytes);
            plaintext.extend_from_slice(&payload);
            plaintext.extend_from_slice(&crc32.to_le_bytes());

            let seg_key = derive_segment_key(&master_key, self.active_segment.index)?;
            let blob = encrypt_record(&seg_key, &plaintext, self.active_segment.index)?;

            // Roll if needed for the encrypted blob.
            if !self.active_segment.has_space(blob.len()) {
                self.roll_segment()?;
                // Re-derive key for new segment after roll.
                let seg_key2 = derive_segment_key(&master_key, self.active_segment.index)?;
                let blob2 = encrypt_record(&seg_key2, &plaintext, self.active_segment.index)?;
                let blob_len = blob2.len();
                let file = self
                    .active_segment
                    .file
                    .as_mut()
                    .ok_or_else(|| WalError::Io(std::io::Error::other("no file after roll")))?;
                file.write_all(&blob2)?;
                self.active_segment.write_offset += blob_len as u64;
            } else {
                let blob_len = blob.len();
                let file = self
                    .active_segment
                    .file
                    .as_mut()
                    .ok_or_else(|| WalError::Io(std::io::Error::other("no file")))?;
                file.write_all(&blob)?;
                self.active_segment.write_offset += blob_len as u64;
            }
        } else {
            // Plaintext path.
            if !self.active_segment.has_space(record_size) {
                self.roll_segment()?;
            }
            let file = self.active_segment.file.as_mut().ok_or_else(|| {
                WalError::Io(std::io::Error::other("Segment file handle missing"))
            })?;
            file.write_all(&header_bytes)?;
            file.write_all(&payload)?;
            file.write_all(&crc32.to_le_bytes())?;
            self.active_segment.write_offset += record_size as u64;
        }

        // Sync behaviour depends on mode — applied after the write regardless
        // of whether the record was encrypted.
        {
            let file = self.active_segment.file.as_ref().ok_or_else(|| {
                WalError::Io(std::io::Error::other(
                    "Segment file handle missing for sync",
                ))
            })?;
            match self.sync_mode {
                WalSyncMode::PerRecord => {
                    file.sync_all()?;
                }
                WalSyncMode::GroupCommit => {
                    if let Some(ref fs) = self.flush_state {
                        fs.dirty.store(true, Ordering::Release);
                    }
                }
                WalSyncMode::NoSync => {
                    #[cfg(debug_assertions)]
                    debug!("WAL no_sync mode — write not fsynced");
                }
            }
        }

        debug!(
            tx_id,
            sequence    = seq,
            record_type = ?record_type,
            payload_bytes = payload.len(),
            sync_mode   = %self.sync_mode,
            encrypted   = self.encryption_key.is_some(),
            "WAL record appended"
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

    /// Force an immediate fsync of the active segment, regardless of
    /// `sync_mode`.  Called by the group-commit background task and by
    /// `checkpoint()`.
    pub fn sync(&mut self) -> Result<(), WalError> {
        if let Some(ref fs) = self.flush_state {
            // Only fsync if there is actually something dirty.
            if fs.dirty.load(Ordering::Acquire) {
                if let Some(ref file) = self.active_segment.file {
                    file.sync_all()?;
                }
                fs.dirty.store(false, Ordering::Release);
            }
        } else if let Some(ref file) = self.active_segment.file {
            file.sync_all()?;
        }
        Ok(())
    }

    /// Seal the current active segment and open a fresh one.
    fn roll_segment(&mut self) -> Result<(), WalError> {
        info!(segment = self.active_segment.index, "Rolling WAL segment");
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
        self.sync()?;
        debug!(sequence = seq, "WAL checkpoint");
        Ok(seq)
    }

    /// Force a checkpoint and write a [`CheckpointPayload`] record to the WAL.
    ///
    /// This is the richer variant used by [`LedgerStore::checkpoint`]:
    ///
    /// 1. `fsync` the active segment (same as `checkpoint`).
    /// 2. Append a `Checkpoint` record that embeds:
    ///    - `last_committed_sequence` — the WAL position at checkpoint time.
    ///    - `page_merkle_root`        — the BLAKE3 Merkle root over all entry
    ///      pages, computed by the caller from [`PageStore::table_merkle_root`].
    ///    - `root_signature`          — optional Ed25519 signature over
    ///      `page_merkle_root || last_committed_sequence.to_le_bytes()` using
    ///      the database signing key.
    ///    - `signer_pubkey`           — the signing key's public key (32 bytes),
    ///      so verifiers do not need out-of-band key distribution.
    ///
    /// The record is written **after** the fsync so that the root represents
    /// data that is already durable on disk.
    ///
    /// Passing `signing_key = None` writes the checkpoint without a signature
    /// (backwards-compatible with dev / unsigned deployments).
    pub fn checkpoint_with_merkle_root(
        &mut self,
        page_merkle_root: [u8; 32],
        signing_key: Option<&vledger_crypto::sign::DbSigningKey>,
    ) -> Result<u64, WalError> {
        // 1. fsync first — the root must cover only already-durable data.
        let seq = self.sequence.load(Ordering::SeqCst);
        self.sync()?;

        // 2. Optionally sign the root.
        //    Signed message: page_merkle_root (32 bytes) || seq.to_le_bytes() (8 bytes) = 40 bytes.
        let (root_signature, signer_pubkey) = if let Some(sk) = signing_key {
            let mut msg = Vec::with_capacity(40);
            msg.extend_from_slice(&page_merkle_root);
            msg.extend_from_slice(&seq.to_le_bytes());
            let sig = sk.sign(&msg);
            let pubkey = sk.public_key().to_bytes();
            (sig.to_vec(), pubkey.to_vec())
        } else {
            (Vec::new(), Vec::new())
        };

        // 3. Write the Checkpoint record (tx_id = 0 — not transaction-bound).
        let payload = CheckpointPayload {
            last_committed_sequence: seq,
            page_merkle_root,
            root_signature,
            signer_pubkey,
        };
        self.append_record(0, RecordType::Checkpoint, &payload)?;

        info!(
            sequence = seq,
            root = hex::encode(page_merkle_root),
            signed = signing_key.is_some(),
            "WAL checkpoint with Merkle root written"
        );
        Ok(seq)
    }

    /// Returns the index of the currently active WAL segment.
    pub fn active_segment_index(&self) -> u64 {
        self.active_segment.index
    }
}

// ── Group-commit background task ──────────────────────────────────────────────

/// Spawn the group-commit background flush task.
///
/// The task wakes every `delay_ms` milliseconds and, if the WAL has any
/// un-fsynced writes, calls `sync_all()` on the active segment file.
///
/// Pass the `CancellationToken` from the server's graceful shutdown; the
/// task exits cleanly when it fires.
///
/// Returns immediately if `sync_mode != GroupCommit`.
pub fn spawn_group_commit_flusher(
    wal_dir: std::path::PathBuf,
    flush_state: Arc<FlushState>,
    delay_ms: u64,
    shutdown: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        let interval = Duration::from_millis(delay_ms);
        info!(
            wal_dir = %wal_dir.display(),
            delay_ms,
            "Group-commit flusher started"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    // Only do I/O if there is something to flush.
                    if !flush_state.dirty.load(Ordering::Acquire) {
                        continue;
                    }

                    // Re-open the active segment file for a targeted fsync.
                    // We re-open by scanning the WAL directory for the
                    // highest-numbered segment — this is safe because
                    // WalWriter is the only writer (exclusive Mutex) and
                    // segment files are append-only.
                    let flushed = tokio::task::spawn_blocking({
                        let wal_dir     = wal_dir.clone();
                        let flush_state = Arc::clone(&flush_state);
                        move || -> Result<(), WalError> {
                            let segments = crate::segment::list_segments(&wal_dir)?;
                            let idx = match segments.last() {
                                Some(i) => *i,
                                None    => return Ok(()),
                            };
                            let path = wal_dir.join(crate::segment::segment_filename(idx));
                            // Open in append mode — does not truncate.
                            let file = std::fs::OpenOptions::new()
                                .write(true)
                                .open(&path)?;
                            file.sync_all()?;
                            flush_state.dirty.store(false, Ordering::Release);
                            Ok(())
                        }
                    }).await;

                    match flushed {
                        Ok(Ok(())) => {
                            debug!(delay_ms, "Group-commit flush OK");
                        }
                        Ok(Err(e)) => {
                            warn!("Group-commit flush error: {e}");
                        }
                        Err(e) => {
                            warn!("Group-commit flush task panicked: {e}");
                        }
                    }
                }
                _ = shutdown.cancelled() => {
                    // Do a final flush on shutdown to minimise data loss.
                    if flush_state.dirty.load(Ordering::Acquire) {
                        let wal_dir2 = wal_dir.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            if let Ok(segments) = crate::segment::list_segments(&wal_dir2) {
                                if let Some(idx) = segments.last() {
                                    let path = wal_dir2.join(
                                        crate::segment::segment_filename(*idx)
                                    );
                                    if let Ok(f) = std::fs::OpenOptions::new()
                                        .write(true).open(path)
                                    {
                                        let _ = f.sync_all();
                                    }
                                }
                            }
                        }).await;
                        info!("Group-commit flusher: final flush on shutdown complete");
                    }
                    break;
                }
            }
        }

        info!("Group-commit flusher exited");
    });
}
