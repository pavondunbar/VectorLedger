//! WORM append-only audit log writer.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use tracing::{debug, warn};

use crate::error::AuditError;
use crate::event::{AuditEvent, AuditEventKind};

/// Append-only WORM audit log.
///
/// Thread-safe — a single `AuditLog` can be shared across multiple Tokio
/// tasks via `Arc<AuditLog>`.
pub struct AuditLog {
    log_path: PathBuf,
    file: Mutex<File>,
    next_seq: AtomicU64,
    /// BLAKE3 chain hash of the last written event.
    last_chain: Mutex<String>,
}

impl AuditLog {
    /// Open (or create) the audit log at `log_path`.
    ///
    /// If the file already exists, the last event is read to restore the
    /// chain state and sequence counter.
    pub fn open(log_path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let log_path = log_path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Restore sequence / chain tip from existing log
        let (next_seq, last_chain) = Self::scan_tail(&log_path)?;

        let file = OpenOptions::new()
            .create(true)
            .append(true) // WORM: O_APPEND only — never seek or truncate
            .open(&log_path)?;

        Ok(Self {
            log_path,
            file: Mutex::new(file),
            next_seq: AtomicU64::new(next_seq),
            last_chain: Mutex::new(last_chain),
        })
    }

    /// Append an `AuditEventKind` to the log and return the completed event.
    pub fn append(&self, kind: AuditEventKind) -> Result<AuditEvent, AuditError> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);

        let mut event = AuditEvent {
            sequence: seq,
            ts: Utc::now(),
            event: kind,
            content_hash: String::new(),
            chain_hash: String::new(),
            prev_hash: String::new(),
        };

        // Compute hashes under the lock to keep the chain consistent.
        let mut last_chain = self.last_chain.lock().unwrap();
        event.finalise(&last_chain);

        let line =
            serde_json::to_string(&event).map_err(|e| AuditError::Serialisation(e.to_string()))?;

        {
            let mut file = self.file.lock().unwrap();
            writeln!(file, "{line}")?;
            file.flush()?;
            // fsync — WORM durability guarantee
            file.sync_all()?;
        }

        *last_chain = event.chain_hash.clone();
        debug!(seq, kind = event.event.name(), "Audit event appended");
        Ok(event)
    }

    /// Current chain tip hash.
    pub fn chain_tip(&self) -> String {
        self.last_chain.lock().unwrap().clone()
    }

    /// Current sequence number (next event to be written).
    pub fn next_sequence(&self) -> u64 {
        self.next_seq.load(Ordering::SeqCst)
    }

    /// Verify the entire chain from the first event to the last.
    ///
    /// Returns `Ok(event_count)` or `Err(AuditError::ChainBroken { … })`.
    pub fn verify_chain(&self) -> Result<u64, AuditError> {
        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);
        let mut prev_hash = AuditEvent::ZERO_HASH.to_string();
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(&line)
                .map_err(|e| AuditError::Serialisation(e.to_string()))?;

            if !event.verify() {
                return Err(AuditError::ChainBroken {
                    sequence: event.sequence,
                    reason: "content_hash or chain_hash mismatch".into(),
                });
            }
            if event.prev_hash != prev_hash {
                return Err(AuditError::ChainBroken {
                    sequence: event.sequence,
                    reason: format!(
                        "prev_hash mismatch: expected {prev_hash}, got {}",
                        event.prev_hash
                    ),
                });
            }
            prev_hash = event.chain_hash.clone();
            count += 1;
        }
        Ok(count)
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /// Read the log file to find the last sequence and chain hash.
    /// Returns `(1, ZERO_HASH)` if the file is empty or doesn't exist.
    fn scan_tail(path: &Path) -> Result<(u64, String), AuditError> {
        if !path.exists() {
            return Ok((1, AuditEvent::ZERO_HASH.to_string()));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut last_seq: u64 = 0;
        let mut last_chain: String = AuditEvent::ZERO_HASH.to_string();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEvent>(&line) {
                Ok(ev) => {
                    last_seq = ev.sequence;
                    last_chain = ev.chain_hash;
                }
                Err(e) => {
                    warn!("Skipping malformed audit log line: {e}");
                }
            }
        }

        Ok((last_seq + 1, last_chain))
    }
}
