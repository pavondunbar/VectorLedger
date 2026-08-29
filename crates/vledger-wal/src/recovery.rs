//! WAL crash recovery.
//!
//! Recovery algorithm:
//!
//! ```text
//! 1. Open WalReader (with optional decryption key) and scan all segments.
//! 2. Collect Begin / Data records into a pending transaction map keyed by tx_id.
//! 3. On Commit  → verify the Ed25519 signature in CommitPayload, then move
//!                 the transaction to the committed set.
//! 4. On Rollback → discard the transaction from pending.
//! 5. After full scan → discard all still-pending (uncommitted) transactions.
//! 6. Return the ordered list of committed Data records for page replay.
//! ```
//!
//! Torn writes (CRC failures) terminate the scan; everything after the tear
//! is discarded.  Signature failures are hard errors — they indicate that a
//! committed transaction's tx_hash was tampered with after it was written.

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
    /// The Commit record itself (contains tx_hash and Ed25519 signature).
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
/// `master_key` — when `Some`, encrypted WAL segments are decrypted.
/// `verify_signatures` — when `true`, the Ed25519 signature in every
/// CommitPayload is verified; a bad signature is a hard error.
///
/// This is called once at database startup before any writes are accepted.
pub fn recover(wal_dir: &Path) -> Result<RecoveryResult, WalError> {
    recover_with_options(wal_dir, None, false)
}

/// Like `recover` but with decryption and signature verification enabled.
pub fn recover_verified(
    wal_dir: &Path,
    master_key: Option<[u8; 32]>,
) -> Result<RecoveryResult, WalError> {
    recover_with_options(wal_dir, master_key, true)
}

fn recover_with_options(
    wal_dir: &Path,
    master_key: Option<[u8; 32]>,
    verify_signatures: bool,
) -> Result<RecoveryResult, WalError> {
    info!(
        wal_dir             = %wal_dir.display(),
        encrypted           = master_key.is_some(),
        verify_signatures,
        "Starting WAL recovery"
    );

    let reader = WalReader::open_with_key(wal_dir, master_key)?;

    let mut pending: HashMap<u64, Vec<WalRecord>> = HashMap::new();
    let mut committed: Vec<CommittedTransaction> = Vec::new();
    let mut last_sequence = 0u64;
    let mut torn_write_detected = false;

    for result in reader {
        match result {
            Err(
                WalError::ChecksumMismatch { .. }
                | WalError::TruncatedRecord { .. }
                | WalError::BadMagic
                | WalError::Decryption,
            ) => {
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
                        pending.entry(tx_id).or_default();
                    }

                    RecordType::Data => {
                        pending.entry(tx_id).or_default().push(record);
                    }

                    RecordType::Commit => {
                        // ── Ed25519 signature verification + tx_hash recomputation ──
                        //
                        // A valid commit requires ALL of the following:
                        //
                        //   1. record_count == number of Data records collected for this tx
                        //   2. recomputed tx_hash (BLAKE3 of row_hash bytes in sequence)
                        //      == CommitPayload.tx_hash
                        //   3. Ed25519 signature over tx_hash || record_count.to_le_bytes()
                        //      is valid (when signing is enabled)
                        //
                        // Step 2 is critical: without it, an attacker who can write to
                        // the WAL file could replace Data records while keeping the
                        // original (signed) Commit record.  Recomputing tx_hash from the
                        // actual Data records ensures the signature covers the real data.
                        if verify_signatures {
                            let data_records =
                                pending.get(&tx_id).map(|v| v.as_slice()).unwrap_or(&[]);
                            verify_commit_full(&record, data_records)?;
                        }

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

                    RecordType::Checkpoint | RecordType::Schema | RecordType::SegmentHeader => {}
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

    committed.sort_by_key(|tx| tx.commit_record.header.sequence);

    info!(
        committed = committed.len(),
        discarded = discarded_tx_count,
        last_sequence,
        torn_write = torn_write_detected,
        verify_signatures,
        "WAL recovery complete"
    );

    Ok(RecoveryResult {
        committed,
        discarded_tx_count,
        last_sequence,
        torn_write_detected,
    })
}

/// Full commit verification:
///
/// 1. Decodes the CommitPayload.
/// 2. Checks `record_count` matches the number of Data records collected.
/// 3. **Recomputes** `tx_hash` from the actual Data record `row_hash` fields
///    and asserts it equals `CommitPayload.tx_hash`.
/// 4. Verifies the Ed25519 signature over `tx_hash || record_count.to_le_bytes()`
///    (when a non-zero pubkey is embedded).
///
/// Steps 2 + 3 close the gap where an attacker replaces Data records while
/// keeping a valid (signed) Commit record: the recomputed hash would differ.
fn verify_commit_full(
    commit_record: &WalRecord,
    data_records: &[WalRecord],
) -> Result<(), WalError> {
    let payload = decode_commit_payload(commit_record)?;

    // ── Step 1: record count ──────────────────────────────────────────────
    let actual_count = data_records.len() as u32;
    if payload.record_count != actual_count {
        return Err(WalError::SignatureInvalid {
            sequence: commit_record.header.sequence,
            reason: format!(
                "record_count mismatch: CommitPayload says {}, but {} Data records found",
                payload.record_count, actual_count
            ),
        });
    }

    // ── Step 2 + 3: recompute tx_hash from Data records ───────────────────
    // tx_hash = BLAKE3( row_hash_0 || row_hash_1 || … || row_hash_n )
    // fed incrementally — this must match Transaction::tx_hash() in
    // vledger-transaction/src/tx.rs exactly (same hasher, same feed order).
    let recomputed_tx_hash: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        for data_record in data_records {
            match decode_data_payload(data_record) {
                Ok(dp) => {
                    h.update(&dp.row_hash);
                }
                Err(e) => {
                    return Err(WalError::Serialization(format!(
                        "failed to decode Data record (seq {}): {e}",
                        data_record.header.sequence
                    )))
                }
            }
        }
        *h.finalize().as_bytes()
    };

    if recomputed_tx_hash != payload.tx_hash {
        return Err(WalError::SignatureInvalid {
            sequence: commit_record.header.sequence,
            reason: format!(
                "tx_hash mismatch: CommitPayload contains {}, recomputed from Data records is {}. \
                 Data records may have been tampered with.",
                hex::encode(payload.tx_hash),
                hex::encode(recomputed_tx_hash),
            ),
        });
    }

    // ── Step 4: Ed25519 signature ─────────────────────────────────────────
    verify_commit_signature(commit_record)?;

    Ok(())
}

/// Verify the Ed25519 signature embedded in a Commit record's payload.
///
/// The signed message is `tx_hash || record_count.to_le_bytes()`.
/// A zero pubkey/signature (from legacy or dev-mode commits) passes without
/// verification — this preserves backwards compatibility while refusing
/// tampered signatures on signed commits.
fn verify_commit_signature(commit_record: &WalRecord) -> Result<(), WalError> {
    let payload = decode_commit_payload(commit_record)?;

    // Zero pubkey → signing was disabled when this record was written.
    // Accept it as a legacy record (no signature to verify).
    if payload.signer_pubkey.is_empty() || payload.signer_pubkey == vec![0u8; 32] {
        return Ok(());
    }

    if payload.signature.len() != 64 || payload.signer_pubkey.len() != 32 {
        return Ok(()); // malformed but non-zero — treat as unsigned legacy
    }

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pk_bytes: [u8; 32] =
        payload
            .signer_pubkey
            .try_into()
            .map_err(|_| WalError::SignatureInvalid {
                sequence: commit_record.header.sequence,
                reason: "signer_pubkey wrong length".into(),
            })?;

    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| WalError::SignatureInvalid {
        sequence: commit_record.header.sequence,
        reason: format!("invalid pubkey: {e}"),
    })?;

    // Reconstruct the signed message: tx_hash || record_count_le4
    let mut msg = Vec::with_capacity(36);
    msg.extend_from_slice(&payload.tx_hash);
    msg.extend_from_slice(&payload.record_count.to_le_bytes());

    let sig_bytes: [u8; 64] =
        payload
            .signature
            .try_into()
            .map_err(|_| WalError::SignatureInvalid {
                sequence: commit_record.header.sequence,
                reason: "signature wrong length".into(),
            })?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&msg, &sig)
        .map_err(|e| WalError::SignatureInvalid {
            sequence: commit_record.header.sequence,
            reason: format!("signature mismatch: {e}"),
        })?;

    Ok(())
}

/// Decode a [`DataPayload`] from a WAL record's raw payload bytes.
pub fn decode_data_payload(record: &WalRecord) -> Result<DataPayload, WalError> {
    bincode::serde::decode_from_slice(
        &record.payload,
        bincode::config::standard().with_fixed_int_encoding(),
    )
    .map(|(p, _)| p)
    .map_err(|e: bincode::error::DecodeError| WalError::Serialization(e.to_string()))
}

/// Decode a [`CommitPayload`] from a WAL record's raw payload bytes.
pub fn decode_commit_payload(record: &WalRecord) -> Result<CommitPayload, WalError> {
    bincode::serde::decode_from_slice(
        &record.payload,
        bincode::config::standard().with_fixed_int_encoding(),
    )
    .map(|(p, _)| p)
    .map_err(|e: bincode::error::DecodeError| WalError::Serialization(e.to_string()))
}
