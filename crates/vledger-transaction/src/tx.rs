//! Transaction state machine.
//!
//! ```text
//! Active ──commit()──► Committed
//!   │
//!   └──rollback()──► RolledBack
//! ```
//!
//! Transitions are enforced — attempting to commit a rolled-back transaction
//! or vice-versa returns an error.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use vledger_wal::record::MutationKind;

use crate::error::TxError;

/// Lifecycle state of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxState {
    /// Actively accumulating mutations.
    Active,
    /// Successfully committed — mutations are durable and visible.
    Committed,
    /// Rolled back — all mutations discarded.
    RolledBack,
}

/// A single in-flight transaction.
///
/// Mutations are buffered until [`Transaction::commit`] is called, at which
/// point they are written to the WAL as an atomic unit and fsync'd.
#[derive(Debug)]
pub struct Transaction {
    /// Globally unique transaction ID.
    pub tx_id: u64,
    /// Snapshot isolation boundary: this tx only sees rows created by
    /// transactions with `tx_id < snapshot_tx_id`.
    pub snapshot_tx_id: u64,
    /// Current lifecycle state.
    pub state: TxState,
    /// UTC timestamp when this transaction was started.
    pub started_at: DateTime<Utc>,
    /// Optional application-level description for audit logs.
    pub description: Option<String>,
    /// Mutations accumulated since BEGIN (not yet committed).
    pub(crate) mutations: Vec<PendingMutation>,
    /// Running BLAKE3 hash of all mutation data (for CommitPayload::tx_hash).
    hasher: blake3::Hasher,
    /// Idempotency key — if set, the commit is a no-op if this key was
    /// already committed.
    pub idempotency_key: Option<String>,
}

/// A single buffered mutation within an active transaction.
#[derive(Debug, Clone)]
pub struct PendingMutation {
    pub table_id: u32,
    pub page_id: u64,
    pub slot_id: u16,
    pub kind: MutationKind,
    pub row_data: Vec<u8>,
    pub row_hash: vledger_crypto::Hash,
    pub prev_hash: Option<vledger_crypto::Hash>,
}

impl Transaction {
    /// Create a new active transaction.
    pub fn new(tx_id: u64, snapshot_tx_id: u64, description: Option<String>) -> Self {
        Self {
            tx_id,
            snapshot_tx_id,
            state: TxState::Active,
            started_at: Utc::now(),
            description,
            mutations: Vec::new(),
            hasher: blake3::Hasher::new(),
            idempotency_key: None,
        }
    }

    /// Buffer a mutation.  Panics if the transaction is not active.
    pub fn add_mutation(&mut self, mutation: PendingMutation) -> Result<(), TxError> {
        self.ensure_active()?;
        self.hasher.update(&mutation.row_hash);
        self.mutations.push(mutation);
        Ok(())
    }

    /// Set an idempotency key.  The transaction manager will reject a commit
    /// if this key was already committed.
    pub fn set_idempotency_key(&mut self, key: String) -> Result<(), TxError> {
        self.ensure_active()?;
        self.idempotency_key = Some(key);
        Ok(())
    }

    /// Compute the transaction hash (over all mutation row hashes in order).
    pub fn tx_hash(&self) -> vledger_crypto::Hash {
        *self.hasher.clone().finalize().as_bytes()
    }

    /// Mark this transaction as committed.  Called by the transaction manager
    /// after the WAL commit record has been fsynced.
    pub fn mark_committed(&mut self) -> Result<(), TxError> {
        self.ensure_active()?;
        self.state = TxState::Committed;
        Ok(())
    }

    /// Mark this transaction as rolled back.
    pub fn mark_rolled_back(&mut self) -> Result<(), TxError> {
        self.ensure_active()?;
        self.state = TxState::RolledBack;
        self.mutations.clear();
        Ok(())
    }

    /// Number of mutations in this transaction.
    pub fn mutation_count(&self) -> usize {
        self.mutations.len()
    }

    fn ensure_active(&self) -> Result<(), TxError> {
        match self.state {
            TxState::Active => Ok(()),
            TxState::Committed => Err(TxError::AlreadyCommitted(self.tx_id)),
            TxState::RolledBack => Err(TxError::AlreadyRolledBack(self.tx_id)),
        }
    }
}
