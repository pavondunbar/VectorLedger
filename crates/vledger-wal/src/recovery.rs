//! WAL crash recovery.
//!
//! Recovery algorithm:
//!
//! ```text
//! 1. Open WalReader and scan all segments in order.
//! 2. Collect Begin / Data records into a pending transaction map keyed by tx_id.
//! 3. On Commit  → move the transaction to the committed set.
//! 4. On Rollback → discard the transaction from pending.
//! 5. After full scan → discard all still-pending (uncommitted) transactions.
//! 6. Return the ordered list of committed Data records for page replay.
//! ```
//!
//! Torn writes (CRC failures) terminate the scan; everything after the tear
//! is discarded.

use std::collections::HashMap;
use std::path::Path;

use tracing::{info, warn};

use crate::error::WalError;
use crate::reader::WalReader;
use crate::record::{CommitPayload, DataPayload, RecordType, WalRecord};

/// A fully committed transaction, ready for replay into the page store.
#[derive(Debug)]
pub struct CommittedTransaction {
    pub tx_id: u64,
    /// The Commit record itself (contains tx_hash for integrity verification).
    pub commit_record: WalRecord,
    /// Data records in sequence order.
    pub data_records: Vec<WalRecord>,
}

/// Result of a WAL recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryResult {
    /// Committed transactions in sequence order, ready for replay.
    pub committed: Vec<CommittedTransaction>,
    /// Number of transactions that were in-flight at the time of crash
    /// and have been discarded.
    pub discarded_tx_count: usize,
    /// Highest WAL sequence number seen.
    pub last_sequence: u64,
    /// Whether recovery was stopped early due to a torn write.
    pub torn_write_detected: bool,
}

/// Run WAL recovery over `wal_dir`.
///
/// This is called once at database startup before any writes are accepted.
/// The returned [`RecoveryResult`] drives the page store replay.
pub fn recover(wal_dir: &Path) -> Result<RecoveryResult, WalError> {
    info!(wal_dir = %wal_dir.display(), "Starting WAL recovery");

    let reader = WalReader::open(wal_dir)?;

    // tx_id → list of data records accumulated so far
    let mut pending: HashMap<u64, Vec<WalRecord>> = HashMap::new();
    let mut committed: Vec<CommittedTransaction> = Vec::new();
    let mut last_sequence = 0u64;
    let mut torn_write_detected = false;

    for result in reader {
        match result {
            Err(WalError::ChecksumMismatch { .. }
                | WalError::TruncatedRecord { .. }
                | WalError::BadMagic) => {
                warn!("Torn write / end of valid WAL data — stopping recovery scan");
                torn_write_detected = true;
                break;
            }
            Err(e) => return Err(e),
            Ok(record) => {
                if record.header.sequence > last_sequence {
                    last_sequence = record.header.sequence;
                }

                let record_type = RecordType::try_from(record.header.record_type)?;
                let tx_id = record.header.tx_id;

                match record_type {
                    RecordType::Begin => {
                        pending.entry(tx_id).or_insert_with(Vec::new);
                    }

                    RecordType::Data => {
                        pending.entry(tx_id).or_insert_with(Vec::new).push(record);
                    }

                    RecordType::Commit => {
                        let data_records = pending.remove(&tx_id).unwrap_or_default();
                        committed.push(CommittedTransaction {
                            tx_id,
                            commit_record: record,
                            data_records,
                        });
                    }

                    RecordType::Rollback => {
                        pending.remove(&tx_id);
                    }

                    RecordType::Checkpoint => {
                        // Checkpoints are informational during recovery — they
                        // tell us we can trust the page store up to this point.
                        // Full page replay is still performed for correctness.
                    }

                    RecordType::Schema | RecordType::SegmentHeader => {
                        // Handled by upper layers during full replay.
                    }
                }
            }
        }
    }

    let discarded_tx_count = pending.len();
    if discarded_tx_count > 0 {
        warn!(
            count = discarded_tx_count,
            "Discarding uncommitted transactions after crash"
        );
    }

    // Sort committed transactions by their commit record's sequence number
    // to guarantee replay order.
    committed.sort_by_key(|tx| tx.commit_record.header.sequence);

    info!(
        committed = committed.len(),
        discarded = discarded_tx_count,
        last_sequence,
        torn_write = torn_write_detected,
        "WAL recovery complete"
    );

    Ok(RecoveryResult {
        committed,
        discarded_tx_count,
        last_sequence,
        torn_write_detected,
    })
}

/// Decode a [`DataPayload`] from a WAL record's raw payload bytes.
pub fn decode_data_payload(record: &WalRecord) -> Result<DataPayload, WalError> {
    bincode::serde::decode_from_slice(&record.payload, bincode::config::standard().with_fixed_int_encoding())
        .map(|(p, _)| p)
        .map_err(|e: bincode::error::DecodeError| WalError::Serialization(e.to_string()))
}

/// Decode a [`CommitPayload`] from a WAL record's raw payload bytes.
pub fn decode_commit_payload(record: &WalRecord) -> Result<CommitPayload, WalError> {
    bincode::serde::decode_from_slice(&record.payload, bincode::config::standard().with_fixed_int_encoding())
        .map(|(p, _)| p)
        .map_err(|e: bincode::error::DecodeError| WalError::Serialization(e.to_string()))
}
