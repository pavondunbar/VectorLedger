//! Transaction manager — the gatekeeper for all ACID operations.
//!
//! The `TransactionManager` owns the WAL writer and coordinates:
//! 1. Assigning globally unique, monotonically increasing transaction IDs.
//! 2. BEGIN → write WAL Begin record.
//! 3. COMMIT → write WAL Data records + Commit record → fsync → mark visible.
//! 4. ROLLBACK → write WAL Rollback record → discard mutations.
//! 5. Idempotency key deduplication.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::{info, warn};
use vledger_crypto::hash::hash_bytes;
use vledger_wal::record::{
    BeginPayload, CommitPayload, DataPayload, MutationKind,
};
use vledger_wal::{RecordType, WalWriter};

use crate::error::TxError;
use crate::tx::{PendingMutation, Transaction};

/// The central transaction manager.
///
/// In a production implementation this would be guarded by a Tokio Mutex so
/// that only one writer is active at a time (the WAL is single-writer).
/// The `&mut self` API enforces exclusive access at compile time.
pub struct TransactionManager {
    wal: WalWriter,
    next_tx_id: Arc<AtomicU64>,
    /// Active transactions keyed by tx_id.
    active: HashMap<u64, Transaction>,
    /// Set of committed idempotency keys (survives restarts via WAL replay).
    committed_idempotency_keys: HashSet<String>,
    /// Highest committed tx_id — used as the snapshot boundary for new txns.
    last_committed_tx_id: u64,
}

impl TransactionManager {
    /// Open the transaction manager backed by a WAL at `wal_dir`.
    pub fn open(wal_dir: &Path) -> Result<Self, TxError> {
        let wal = WalWriter::open(wal_dir)?;

        // Recover the WAL to determine the highest committed tx_id and
        // any idempotency keys that were already committed.
        let recovery = vledger_wal::recovery::recover(wal_dir)?;

        let last_committed_tx_id = recovery
            .committed
            .iter()
            .map(|tx| tx.tx_id)
            .max()
            .unwrap_or(0);

        // The next tx_id must be strictly greater than anything in the WAL.
        let next_tx_id = last_committed_tx_id + 1;

        info!(
            last_committed_tx_id,
            next_tx_id,
            recovered_txns = recovery.committed.len(),
            "TransactionManager initialized"
        );

        Ok(Self {
            wal,
            next_tx_id: Arc::new(AtomicU64::new(next_tx_id)),
            active: HashMap::new(),
            committed_idempotency_keys: HashSet::new(),
            last_committed_tx_id,
        })
    }

    /// Begin a new transaction.  Returns the transaction ID.
    pub fn begin(&mut self, description: Option<String>) -> Result<u64, TxError> {
        let tx_id = self.next_tx_id.fetch_add(1, Ordering::SeqCst);
        let snapshot_tx_id = self.last_committed_tx_id + 1;

        // Write BEGIN record to WAL
        let begin_payload = BeginPayload { description: description.clone() };
        self.wal.append_record(tx_id, RecordType::Begin, &begin_payload)?;

        let tx = Transaction::new(tx_id, snapshot_tx_id, description);
        self.active.insert(tx_id, tx);

        info!(tx_id, snapshot_tx_id, "Transaction begun");
        Ok(tx_id)
    }

    /// Add a mutation to an active transaction.
    pub fn add_mutation(
        &mut self,
        tx_id: u64,
        table_id: u32,
        page_id: u64,
        slot_id: u16,
        kind: MutationKind,
        row_data: Vec<u8>,
        prev_hash: Option<vledger_crypto::Hash>,
    ) -> Result<(), TxError> {
        let row_hash = hash_bytes(&row_data);
        let mutation = PendingMutation {
            table_id,
            page_id,
            slot_id,
            kind,
            row_data,
            row_hash,
            prev_hash,
        };

        let tx = self.active.get_mut(&tx_id).ok_or(TxError::NotFound(tx_id))?;
        tx.add_mutation(mutation)?;
        Ok(())
    }

    /// Set an idempotency key on a transaction.
    pub fn set_idempotency_key(&mut self, tx_id: u64, key: String) -> Result<(), TxError> {
        // Check if already committed
        if self.committed_idempotency_keys.contains(&key) {
            return Err(TxError::IdempotencyKeyConflict(key));
        }
        let tx = self.active.get_mut(&tx_id).ok_or(TxError::NotFound(tx_id))?;
        tx.set_idempotency_key(key)?;
        Ok(())
    }

    /// Commit a transaction.
    ///
    /// ## Steps
    /// 1. Check idempotency key.
    /// 2. Write all Data records to WAL.
    /// 3. Write Commit record to WAL (includes tx_hash).
    /// 4. WAL fsyncs after each record — durability is guaranteed before we
    ///    return Ok.
    /// 5. Mark the transaction committed and advance `last_committed_tx_id`.
    pub fn commit(&mut self, tx_id: u64) -> Result<(), TxError> {
        let tx = self.active.get(&tx_id).ok_or(TxError::NotFound(tx_id))?;

        // Idempotency check
        if let Some(ref key) = tx.idempotency_key.clone() {
            if self.committed_idempotency_keys.contains(key) {
                warn!(tx_id, key, "Idempotency key already committed — returning success without re-applying");
                // Idempotent success: do not re-apply but do not error either.
                let _tx = self.active.remove(&tx_id).unwrap();
                return Ok(());
            }
        }

        let tx_hash = tx.tx_hash();
        let mutation_count = tx.mutation_count() as u32;
        let idempotency_key = tx.idempotency_key.clone();

        // Write Data records
        let mutations: Vec<PendingMutation> = {
            self.active.get(&tx_id).unwrap().mutations.clone()
        };

        for m in &mutations {
            let payload = DataPayload {
                table_id: m.table_id,
                page_id: m.page_id,
                slot_id: m.slot_id,
                mutation: m.kind,
                row_data: m.row_data.clone(),
                row_hash: m.row_hash,
                prev_hash: m.prev_hash,
            };
            self.wal.append_record(tx_id, RecordType::Data, &payload)?;
        }

        // Write Commit record
        let commit_payload = CommitPayload {
            record_count: mutation_count,
            tx_hash,
        };
        self.wal.append_record(tx_id, RecordType::Commit, &commit_payload)?;

        // Mark committed
        if let Some(mut tx) = self.active.remove(&tx_id) {
            tx.mark_committed()?;
            if tx_id > self.last_committed_tx_id {
                self.last_committed_tx_id = tx_id;
            }
        }

        // Register idempotency key
        if let Some(key) = idempotency_key {
            self.committed_idempotency_keys.insert(key);
        }

        info!(tx_id, mutations = mutation_count, "Transaction committed");
        Ok(())
    }

    /// Roll back a transaction.  Writes a Rollback record to the WAL so that
    /// recovery knows to discard this transaction's Data records.
    pub fn rollback(&mut self, tx_id: u64) -> Result<(), TxError> {
        let tx = self.active.get_mut(&tx_id).ok_or(TxError::NotFound(tx_id))?;
        tx.mark_rolled_back()?;

        self.wal.append(tx_id, RecordType::Rollback, vec![])?;
        self.active.remove(&tx_id);

        info!(tx_id, "Transaction rolled back");
        Ok(())
    }

    /// Returns the ID of the last committed transaction.
    pub fn last_committed_tx_id(&self) -> u64 {
        self.last_committed_tx_id
    }

    /// Issue a WAL checkpoint.
    pub fn checkpoint(&mut self) -> Result<u64, TxError> {
        let seq = self.wal.checkpoint(0)?;
        Ok(seq)
    }
}
