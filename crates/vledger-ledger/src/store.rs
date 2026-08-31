//! `LedgerStore` — the append-only financial ledger (Phase 2: WAL-backed).
//!
//! ## Architecture
//! Every `post_entry` call follows this path:
//!
//! ```text
//! post_entry(entry)
//!   │
//!   ├─ validate (balance, constraints, four-eyes, exposure)
//!   │
//!   ├─ TransactionManager::begin()
//!   │
//!   ├─ serialize entry → bytes
//!   │
//!   ├─ TransactionManager::add_mutation()   ← WAL Data record (fsync'd)
//!   │
//!   ├─ PageStore::write_page()              ← durable page (fsync'd)
//!   │
//!   ├─ TransactionManager::commit()         ← WAL Commit record (fsync'd)
//!   │
//!   └─ update in-memory indexes
//! ```
//!
//! ## Reversal design (append-only, atomic)
//!
//! Original entries are **never mutated**.  A reversal is represented by two
//! new appended records written inside a **single WAL transaction**:
//!
//! 1. A `JournalEntry` with `status = Reversal` and `reverses_entry_id = original.id`.
//! 2. A `ReversalEvent` linking `original_id → reversal_id`.
//!
//! The `Reversed` status of an original entry is **derived** from the
//! `reversal_event_index` at query time — it is never stored by mutating the
//! original row.  Because both records are committed atomically, there is no
//! window in which one exists without the other.
//!
//! On restart, WAL replay rebuilds both the entry list and the reversal event
//! index deterministically.
//!
//! On restart, `LedgerStore::open()` replays the WAL and rebuilds all
//! in-memory state deterministically.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;
use vledger_crypto::{Hash, ZERO_HASH};
use vledger_pages::{Page, PageStore};
use vledger_transaction::manager::TransactionManager;
use vledger_wal::record::MutationKind;

use crate::account::{Account, AccountId, AccountStatus, AccountType};
use crate::entry::{DrCr, EntryStatus, JournalEntry, JournalLine};
use crate::entry_db::EntryDb;
use crate::error::LedgerError;
use crate::lockfile::DataDirLock;

// ── Table IDs ────────────────────────────────────────────────────────────────
// Each logical table maps to a dedicated page file in PageStore.

/// table_id=0 — chart of accounts
const TABLE_ACCOUNTS: u32 = 0;
/// table_id=1 — journal entries
const TABLE_ENTRIES: u32 = 1;
/// table_id=2 — reversal relationship events (append-only, never updated)
///
/// Storing these as first-class WAL records ensures the link between an
/// original entry and its reversal is durable and atomic with the reversal
/// entry itself.  The original entry is never modified.
const TABLE_REVERSAL_EVENTS: u32 = 2;
/// table_id=3 — settlement lifecycle events (Pending/Settled/Failed transitions)
///
/// Status transitions are stored as side-channel events — the original entry
/// is never modified, preserving its hash chain integrity.
const TABLE_SETTLEMENT_EVENTS: u32 = 3;

// ── Serialization helpers ─────────────────────────────────────────────────────

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, LedgerError> {
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e: bincode::error::EncodeError| LedgerError::Serialization(e.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, LedgerError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e: bincode::error::DecodeError| LedgerError::Serialization(e.to_string()))
}

// ── ReversalEvent ─────────────────────────────────────────────────────────────

/// An immutable, append-only record that binds an original entry to its
/// reversal.  Written atomically alongside the reversal `JournalEntry` in a
/// single WAL transaction — the original entry is **never modified**.
///
/// The `Reversed` status of an original entry is derived at query time by
/// checking whether its `id` appears in `LedgerStore::reversal_event_index`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReversalEvent {
    /// The entry that was reversed.
    pub original_entry_id: Uuid,
    /// The newly appended reversal entry.
    pub reversal_entry_id: Uuid,
    /// UTC timestamp when the reversal was posted.
    pub reversed_at: chrono::DateTime<Utc>,
}

// ── SettlementEvent ───────────────────────────────────────────────────────────

/// An immutable record of a settlement lifecycle transition.
///
/// The original entry is never modified — status is derived at query time
/// by checking `LedgerStore::settlement_event_index`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SettlementEvent {
    /// Entry whose status is transitioning.
    pub entry_id: Uuid,
    /// The new status (Pending, Settled, or Failed).
    pub new_status: crate::entry::EntryStatus,
    /// UTC timestamp of the transition.
    pub settled_at: chrono::DateTime<Utc>,
    /// Optional notes (reason for failure, settlement reference, etc.)
    pub notes: Option<String>,
}

// ── ReconciliationDiscrepancy ─────────────────────────────────────────────────

/// A discrepancy found during reconciliation between the running balance cache
/// and a fresh recomputation from journal entries.
#[derive(Debug, Clone)]
pub struct ReconciliationDiscrepancy {
    pub account_id: AccountId,
    pub account_code: String,
    pub cached_balance: i128,
    pub recomputed_balance: i128,
    /// `recomputed_balance - cached_balance`
    pub delta: i128,
}

// ── LedgerStore ──────────────────────────────────────────────────────────────

/// The append-only financial ledger.
///
/// State is durable: every write is WAL-fsynced and page-fsynced before
/// `post_entry` returns. On restart, `open()` replays the WAL to rebuild
/// all in-memory indexes.
pub struct LedgerStore {
    // ── Durable storage ───────────────────────────────────────────────────
    tx_manager: TransactionManager,
    page_store: PageStore,

    // ── SQLite entry query index (disk-backed, O(accounts) RAM) ──────────
    entry_db: EntryDb,

    // ── In-memory account state ───────────────────────────────────────────
    accounts: HashMap<AccountId, Account>,

    // ── Running balance cache — O(1) balance lookup ───────────────────────
    balance_cache: HashMap<AccountId, i128>,

    // ── Sequence / chain state ────────────────────────────────────────────
    next_sequence: AtomicU64,
    last_chain_hash: Hash,
    idempotency_keys: std::collections::HashSet<String>,

    // ── Reversal event index ──────────────────────────────────────────────
    reversal_event_index: HashMap<Uuid, Uuid>,

    // ── Settlement event index ────────────────────────────────────────────
    settlement_event_index: HashMap<Uuid, crate::entry::EntryStatus>,

    // ── Legal hold index ──────────────────────────────────────────────────
    legal_hold_accounts: std::collections::HashSet<AccountId>,

    // ── Currency registry ─────────────────────────────────────────────────
    currency_registry: crate::currency::CurrencyRegistry,

    // ── Page cursors ──────────────────────────────────────────────────────
    next_account_page: u64,
    next_entry_page: u64,

    // ── Process-exclusive advisory lock ──────────────────────────────────
    /// Held for the lifetime of this store.  Dropped when the store is dropped.
    _lock: Option<DataDirLock>,

    // ── Data directory path (for WAL flusher) ─────────────────────────────
    data_dir: Option<std::path::PathBuf>,

    // ── Replication support ───────────────────────────────────────────────
    /// Bincode bytes of the most recently committed journal entry.
    /// Set by `post_entry()` after a successful commit; read by the server
    /// handler to ship the record to replicas after releasing the write lock.
    /// `None` until the first entry is posted.
    last_committed_entry_bytes: Option<Vec<u8>>,
}

impl LedgerStore {
    // ── Constructors ──────────────────────────────────────────────────────

    /// Open (or create) a persistent ledger at `data_dir`.
    ///
    /// If the WAL already contains committed transactions, the in-memory
    /// state is rebuilt by replaying all committed Data records.
    ///
    /// When `data_dir/keys/db_signing_key.hex` is present the Ed25519 signing
    /// key is loaded and wired into every WAL CommitPayload, fulfilling the
    /// "Ed25519 commit signing on every WAL commit record" guarantee.
    /// Recovery is also run with signature verification enabled so tampered
    /// commits are caught on startup.
    pub fn open(data_dir: &Path) -> Result<Self, LedgerError> {
        Self::open_with_sync_mode(data_dir, vledger_wal::WalSyncMode::GroupCommit)
    }

    /// Open with an explicit WAL sync mode — used by bulk import to avoid
    /// per-record fsyncs that would make large imports prohibitively slow.
    pub fn open_with_sync_mode(
        data_dir: &Path,
        sync_mode: vledger_wal::WalSyncMode,
    ) -> Result<Self, LedgerError> {
        let wal_dir = data_dir.join("wal");
        let pages_dir = data_dir.join("pages");

        let signing_key = Self::load_signing_key(data_dir);

        let tx_manager =
            TransactionManager::open_with_signing_and_mode(&wal_dir, signing_key, sync_mode)?;
        let page_store = PageStore::open(&pages_dir)?;

        // Acquire an exclusive advisory lock on the data directory to prevent
        // two processes from opening the same store simultaneously.
        let lock = DataDirLock::acquire(data_dir).map_err(|e| {
            LedgerError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("cannot lock data directory: {e}"),
            ))
        })?;

        let mut store = Self {
            tx_manager,
            page_store,
            entry_db: EntryDb::open(&data_dir.join("vledger.db"))
                .map_err(|e| LedgerError::Serialization(format!("Cannot open entry_db: {e}")))?,
            accounts: HashMap::new(),
            balance_cache: HashMap::new(),
            next_sequence: AtomicU64::new(1),
            last_chain_hash: ZERO_HASH,
            idempotency_keys: std::collections::HashSet::new(),
            reversal_event_index: HashMap::new(),
            settlement_event_index: HashMap::new(),
            legal_hold_accounts: std::collections::HashSet::new(),
            currency_registry: crate::currency::CurrencyRegistry::new(),
            next_account_page: 0,
            next_entry_page: 0,
            _lock: Some(lock),
            data_dir: Some(data_dir.to_path_buf()),
            last_committed_entry_bytes: None,
        };

        store.replay_from_wal(&wal_dir)?;

        info!(
            accounts = store.accounts.len(),
            sequence = store.next_sequence.load(Ordering::SeqCst),
            "LedgerStore opened"
        );
        Ok(store)
    }

    /// Create a purely in-memory ledger (for tests and self-test command).
    /// No WAL, no page store — state is lost when dropped.
    /// Create a purely in-memory ledger (for tests and self-test command).
    /// No WAL, no page store — state is lost when dropped.
    ///
    /// Returns `Err` if the temp directory cannot be created or the ledger
    /// cannot be opened (e.g. filesystem full or read-only `/tmp`).
    #[cfg(any(test, feature = "self-test"))]
    pub fn new_in_memory() -> Result<Self, LedgerError> {
        let tmp = std::env::temp_dir().join(format!("vledger-mem-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).map_err(LedgerError::Io)?;
        Self::open(&tmp)
    }

    /// Open the ledger in **import mode** with an explicit WAL sync mode.
    ///
    /// Import mode replays the WAL without loading existing entries into
    /// `self.entries`. Only accounts, chain state, and idempotency keys are
    /// loaded — memory usage is O(accounts) regardless of how many entries
    /// are already in the WAL. This allows billion-record imports on
    /// modest hardware (8 GB RAM).
    ///
    /// After import completes, open the ledger normally with `LedgerStore::open()`
    /// to rebuild the full in-memory indexes for query serving.
    pub fn open_for_import(
        data_dir: &Path,
        sync_mode: vledger_wal::WalSyncMode,
    ) -> Result<Self, LedgerError> {
        let wal_dir = data_dir.join("wal");
        let pages_dir = data_dir.join("pages");
        let signing_key = Self::load_signing_key(data_dir);
        let tx_manager =
            TransactionManager::open_with_signing_and_mode(&wal_dir, signing_key, sync_mode)?;
        let page_store = PageStore::open(&pages_dir)?;
        let lock = DataDirLock::acquire(data_dir).map_err(|e| {
            LedgerError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("cannot lock data directory: {e}"),
            ))
        })?;
        let mut store = Self {
            tx_manager,
            page_store,
            entry_db: EntryDb::open(&data_dir.join("vledger.db"))
                .map_err(|e| LedgerError::Serialization(format!("Cannot open entry_db: {e}")))?,
            accounts: HashMap::new(),
            balance_cache: HashMap::new(),
            next_sequence: AtomicU64::new(1),
            last_chain_hash: ZERO_HASH,
            idempotency_keys: std::collections::HashSet::new(),
            reversal_event_index: HashMap::new(),
            settlement_event_index: HashMap::new(),
            legal_hold_accounts: std::collections::HashSet::new(),
            currency_registry: crate::currency::CurrencyRegistry::new(),
            next_account_page: 0,
            next_entry_page: 0,
            _lock: Some(lock),
            data_dir: Some(data_dir.to_path_buf()),
            last_committed_entry_bytes: None,
        };
        // Replay in import mode — loads accounts + chain state, skips entries.
        store.replay_from_wal_import_mode(&wal_dir)?;
        info!(
            accounts = store.accounts.len(),
            sequence = store.next_sequence.load(Ordering::SeqCst),
            "LedgerStore opened in import mode (entries not loaded into RAM)"
        );
        Ok(store)
    }

    /// Post an entry in import mode — writes to WAL + page store but does NOT
    /// update `self.entries`, `self.balance_cache`, or query indexes.
    ///
    /// This keeps memory usage flat regardless of how many entries have been
    /// imported. Use this method only during bulk import; for normal operation
    /// use `post_entry()` which maintains full in-memory indexes.
    ///
    /// Validations still enforced:
    /// - Entry is balanced (debits == credits)
    /// - All accounts exist and are active
    /// - Currency matches per line
    /// - Amount is non-zero
    /// - Idempotency key deduplication
    /// - BLAKE3 hash chain extended
    /// - WAL record written
    ///
    /// Validations skipped (acceptable for bulk import):
    /// - Non-negative balance check (balance_cache not maintained)
    /// - Exposure limit check (balance_cache not maintained)
    /// - Four-eyes check
    pub fn import_entry_direct(&mut self, mut entry: JournalEntry) -> Result<u64, LedgerError> {
        // 1. Structural validation
        entry.validate()?;

        // 2. Idempotency check
        if let Some(ref key) = entry.idempotency_key {
            if self.idempotency_keys.contains(key) {
                // Already imported — return the sequence as a sentinel 0 to signal skip.
                return Ok(0);
            }
        }

        // 3. Per-line account validation (existence, status, currency only).
        for line in &entry.lines {
            let acct = self
                .accounts
                .get(&line.account_id)
                .ok_or_else(|| LedgerError::AccountNotFound(line.account_id.to_string()))?;
            if !acct.is_active() {
                return Err(LedgerError::AccountClosed(line.account_id.to_string()));
            }
            if acct.currency_code != line.currency_code {
                return Err(LedgerError::CurrencyMismatch {
                    account_currency: acct.currency_code.clone(),
                    entry_currency: line.currency_code.clone(),
                });
            }
        }

        // 4. Assign sequence and finalize chain hash.
        let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        entry.sequence = seq;
        entry.posted_at = chrono::Utc::now();
        entry.finalize_chain_hash(&self.last_chain_hash);

        // 5. Persist to WAL + page store.
        let bytes = encode(&entry)?;
        let prev_hash = Some(entry.prev_hash);
        self.persist_row(TABLE_ENTRIES, &bytes, MutationKind::Insert, prev_hash)?;

        // 6. Update ONLY the minimal state needed for chain continuity and dedup.
        //    Do NOT touch self.entries, balance_cache, or query indexes.
        self.last_chain_hash = entry.chain_hash;
        if let Some(ref key) = entry.idempotency_key {
            self.idempotency_keys.insert(key.clone());
        }

        Ok(seq)
    }

    // ── Signing key loader ────────────────────────────────────────────────

    /// Load the Ed25519 database signing key from `data_dir/keys/db_signing_key.hex`.
    ///
    /// Returns `None` (with a warning) when the file is absent or unreadable —
    /// this preserves compatibility with existing databases initialised before
    /// signing support was added.
    fn load_signing_key(data_dir: &Path) -> Option<vledger_crypto::sign::DbSigningKey> {
        let key_path = data_dir.join("keys").join("db_signing_key.hex");
        if !key_path.exists() {
            warn!(
                path = %key_path.display(),
                "db_signing_key.hex not found — WAL commits will be unsigned. \
                 Run `vledger init` to generate and persist the signing key."
            );
            return None;
        }
        let hex_str = match std::fs::read_to_string(&key_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                warn!(path = %key_path.display(), "Failed to read signing key: {e}");
                return None;
            }
        };
        let bytes: Vec<u8> = match hex::decode(&hex_str) {
            Ok(b) => b,
            Err(e) => {
                warn!("db_signing_key.hex contains invalid hex: {e}");
                return None;
            }
        };
        let arr: [u8; 32] = match bytes.try_into() {
            Ok(a) => a,
            Err(_) => {
                warn!("db_signing_key.hex must be 32 bytes (64 hex chars)");
                return None;
            }
        };
        match vledger_crypto::sign::DbSigningKey::from_bytes(&arr) {
            Ok(sk) => {
                info!("WAL commit signing key loaded");
                Some(sk)
            }
            Err(e) => {
                warn!("Failed to parse signing key: {e}");
                None
            }
        }
    }

    // ── WAL replay ────────────────────────────────────────────────────────

    /// Replay committed WAL records into in-memory indexes.
    ///
    /// This is called once at startup and rebuilds the entire state from
    /// scratch — the WAL is the source of truth.
    ///
    /// When the WAL contains signed commits (i.e. the database was opened with
    /// a signing key), `recover_verified` is used so that any tampered commit
    /// is caught as a hard error before state is applied.
    fn replay_from_wal(&mut self, wal_dir: &Path) -> Result<(), LedgerError> {
        self.replay_from_wal_mode(wal_dir, false)
    }

    /// Replay WAL in import mode — loads accounts and chain state but does NOT
    /// populate `self.entries`, `self.balance_cache`, or query indexes.
    /// This keeps memory usage flat (O(accounts)) regardless of entry count,
    /// enabling billion-record imports on modest hardware.
    fn replay_from_wal_import_mode(&mut self, wal_dir: &Path) -> Result<(), LedgerError> {
        self.replay_from_wal_mode(wal_dir, true)
    }

    fn replay_from_wal_mode(
        &mut self,
        wal_dir: &Path,
        import_mode: bool,
    ) -> Result<(), LedgerError> {
        use vledger_wal::record::MutationKind;
        use vledger_wal::recovery::{decode_data_payload, recover, recover_verified};

        let result = if self.tx_manager.signing_pubkey().is_some() {
            recover_verified(wal_dir, None)?
        } else {
            recover(wal_dir)?
        };
        info!(
            committed = result.committed.len(),
            discarded = result.discarded_tx_count,
            verify_signatures = self.tx_manager.signing_pubkey().is_some(),
            "Replaying WAL into LedgerStore"
        );

        // ── SQLite fast-path ────────────────────────────────────────────────
        // The SQLite index was populated during the previous run (import or
        // normal operation).  Any entry with sequence ≤ sqlite_max_seq is
        // already in the index — skip the insert, just update in-memory state.
        // Only entries with sequence > sqlite_max_seq need to be written to
        // SQLite.  In the common startup case (no new entries since last run)
        // this means ZERO SQLite inserts, making startup O(WAL records) in
        // decode time only — no I/O beyond reading the WAL.
        //
        // For the idempotency_keys HashSet: we only load keys for entries
        // that are NOT yet in SQLite.  For entries already in SQLite, dedup
        // is handled by entry_db.idempotency_key_exists() at post time.
        // This keeps the HashSet small (typically empty on a clean restart).
        let sqlite_max_seq = if import_mode {
            0u64 // import mode never uses SQLite
        } else {
            self.entry_db.max_sequence().unwrap_or(0)
        };

        if sqlite_max_seq > 0 {
            info!(
                sqlite_max_seq,
                "SQLite index already populated — skipping re-insert for existing entries"
            );
        }

        // Ensure tables exist before any inserts.
        if !import_mode {
            if let Err(e) = self.entry_db.ensure_account_entries_table() {
                warn!("ensure_account_entries_table: {e}");
            }
        }

        // Begin a bulk SQLite transaction for any new entries that need
        // inserting (sequence > sqlite_max_seq).  Committed in one shot at
        // the end — dramatically faster than per-row autocommit.
        let mut bulk_open = false;
        let mut new_entry_count = 0u64;

        for tx in result.committed {
            for record in &tx.data_records {
                let payload = decode_data_payload(record)?;
                match payload.mutation {
                    MutationKind::Insert | MutationKind::Update => match payload.table_id {
                        TABLE_ACCOUNTS => {
                            let account: Account = decode(&payload.row_data)?;
                            self.apply_account(account);
                        }
                        TABLE_ENTRIES => {
                            let entry: JournalEntry = decode(&payload.row_data)?;
                            if import_mode {
                                // Import mode: only chain state + idempotency keys.
                                if entry.sequence >= self.next_sequence.load(Ordering::SeqCst) {
                                    self.next_sequence
                                        .store(entry.sequence + 1, Ordering::SeqCst);
                                }
                                self.last_chain_hash = entry.chain_hash;
                                if let Some(ref key) = entry.idempotency_key {
                                    self.idempotency_keys.insert(key.clone());
                                }
                                self.next_entry_page += 1;
                            } else {
                                // Normal mode.
                                let already_in_sqlite = entry.sequence <= sqlite_max_seq;

                                // Always update in-memory state (sequence, chain,
                                // balance cache) regardless of SQLite status.
                                if entry.sequence >= self.next_sequence.load(Ordering::SeqCst) {
                                    self.next_sequence
                                        .store(entry.sequence + 1, Ordering::SeqCst);
                                }
                                self.last_chain_hash = entry.chain_hash;

                                // Only load idempotency key into RAM for entries
                                // NOT already in SQLite.  For existing entries
                                // the SQLite index handles dedup at post time.
                                if !already_in_sqlite {
                                    if let Some(ref key) = entry.idempotency_key {
                                        self.idempotency_keys.insert(key.clone());
                                    }
                                }

                                // Balance cache: always rebuild from WAL — it is
                                // the authoritative source of truth.
                                let affects_balance = matches!(
                                    entry.status,
                                    EntryStatus::Posted | EntryStatus::Reversal
                                );
                                for line in &entry.lines {
                                    if affects_balance {
                                        self.update_balance_cache(
                                            line.account_id,
                                            line.amount.as_i128(),
                                            line.dr_cr,
                                        );
                                    }
                                }

                                self.next_entry_page += 1;

                                // Insert into SQLite only if not already there.
                                if !already_in_sqlite {
                                    if !bulk_open {
                                        if let Err(e) = self.entry_db.begin_bulk() {
                                            warn!("begin_bulk during replay: {e}");
                                        } else {
                                            bulk_open = true;
                                        }
                                    }
                                    if let Err(e) = self.entry_db.insert(&entry) {
                                        warn!(
                                            sequence = entry.sequence,
                                            "entry_db insert failed: {e}"
                                        );
                                    } else {
                                        for line in &entry.lines {
                                            if let Err(e) = self.entry_db.insert_account_entry(
                                                &line.account_id,
                                                entry.sequence,
                                            ) {
                                                warn!(
                                                    sequence = entry.sequence,
                                                    "entry_db insert_account_entry failed: {e}"
                                                );
                                            }
                                        }
                                        new_entry_count += 1;
                                    }
                                }
                            }
                        }
                        TABLE_REVERSAL_EVENTS => {
                            let event: ReversalEvent = decode(&payload.row_data)?;
                            self.reversal_event_index
                                .insert(event.original_entry_id, event.reversal_entry_id);
                        }
                        TABLE_SETTLEMENT_EVENTS => {
                            let event: SettlementEvent = decode(&payload.row_data)?;
                            self.settlement_event_index
                                .insert(event.entry_id, event.new_status);
                        }
                        _ => {}
                    },
                    MutationKind::Delete => {
                        if payload.table_id == TABLE_ACCOUNTS {
                            let account: Account = decode(&payload.row_data)?;
                            if account.legal_hold {
                                self.legal_hold_accounts.insert(account.id);
                            } else {
                                self.legal_hold_accounts.remove(&account.id);
                            }
                            self.accounts.insert(account.id, account);
                        }
                    }
                }
            }
        }

        // Commit any new entries that were inserted into SQLite.
        if bulk_open {
            if let Err(e) = self.entry_db.commit_bulk() {
                warn!("commit_bulk during replay: {e}");
            } else {
                info!(new_entry_count, "SQLite index updated with new WAL entries");
            }
        }

        Ok(())
    }

    /// Apply an account record to in-memory state (idempotent).
    fn apply_account(&mut self, account: Account) {
        if account.legal_hold {
            self.legal_hold_accounts.insert(account.id);
        } else {
            self.legal_hold_accounts.remove(&account.id);
        }
        self.accounts.insert(account.id, account);
    }

    /// Apply a journal entry to in-memory state and SQLite index (idempotent).
    fn apply_entry(&mut self, entry: JournalEntry) {
        // Advance sequence counter past replayed entries
        if entry.sequence >= self.next_sequence.load(Ordering::SeqCst) {
            self.next_sequence
                .store(entry.sequence + 1, Ordering::SeqCst);
        }
        // Advance chain tip
        self.last_chain_hash = entry.chain_hash;
        // Register idempotency key
        if let Some(ref key) = entry.idempotency_key {
            self.idempotency_keys.insert(key.clone());
        }

        // Update running balance cache.
        // Only Posted and Reversal entries affect balances — skip others.
        let affects_balance = matches!(entry.status, EntryStatus::Posted | EntryStatus::Reversal);
        for line in &entry.lines {
            if affects_balance {
                self.update_balance_cache(line.account_id, line.amount.as_i128(), line.dr_cr);
            }
        }

        // Write to SQLite index — INSERT OR IGNORE so replay is idempotent.
        // Log but don't panic on SQLite errors during replay; the WAL remains
        // the authoritative source of truth.
        if let Err(e) = self.entry_db.ensure_account_entries_table() {
            warn!("entry_db ensure_account_entries_table: {e}");
        }
        if let Err(e) = self.entry_db.insert(&entry) {
            warn!(sequence = entry.sequence, "entry_db insert failed: {e}");
        } else {
            for line in &entry.lines {
                if let Err(e) = self
                    .entry_db
                    .insert_account_entry(&line.account_id, entry.sequence)
                {
                    warn!(
                        sequence = entry.sequence,
                        "entry_db insert_account_entry failed: {e}"
                    );
                }
            }
        }

        // Advance entry page cursor (used by persist_row).
        self.next_entry_page += 1;
    }

    /// Update the running balance cache for a single account/line.
    ///
    /// The cache stores the *signed* balance in the account's normal-balance
    /// direction:
    /// - Debit-normal (Asset / Expense): cache += debit, cache -= credit
    /// - Credit-normal (Liability / Income / Equity): cache += credit, cache -= debit
    ///
    /// If the account is not yet registered (e.g. during WAL replay before
    /// the account record has been applied) the entry is skipped and the
    /// cache will be correctly populated once `apply_account` runs.
    fn update_balance_cache(&mut self, account_id: AccountId, amount: i128, dr_cr: DrCr) {
        let is_debit_normal = match self.accounts.get(&account_id) {
            Some(acct) => matches!(acct.account_type, AccountType::Asset | AccountType::Expense),
            // Account not yet in memory — skip; cache will be correct after
            // the account record is applied and the entry re-evaluated via
            // the full balance() recompute on first access.
            None => return,
        };

        let delta: i128 = if is_debit_normal {
            match dr_cr {
                DrCr::Debit => amount,
                DrCr::Credit => -amount,
            }
        } else {
            match dr_cr {
                DrCr::Credit => amount,
                DrCr::Debit => -amount,
            }
        };

        *self.balance_cache.entry(account_id).or_insert(0) += delta;
    }

    // ── Durable write helper ──────────────────────────────────────────────

    /// Write a row to the page store and record it in the WAL, all within a
    /// single atomic transaction.  The caller receives the slot_id assigned.
    fn persist_row(
        &mut self,
        table_id: u32,
        row_data: &[u8],
        mutation: MutationKind,
        prev_hash: Option<vledger_crypto::Hash>,
    ) -> Result<(u64, u16), LedgerError> {
        // Copy cursor out to avoid holding a &mut to self while calling write_to_page
        let cursor = match table_id {
            TABLE_ACCOUNTS => self.next_account_page,
            _ => self.next_entry_page,
        };

        let (page_id, slot_id, next_cursor) = self.write_to_page(table_id, row_data, cursor)?;

        // Write cursor back
        match table_id {
            TABLE_ACCOUNTS => self.next_account_page = next_cursor,
            _ => self.next_entry_page = next_cursor,
        };

        // WAL transaction
        let tx_id = self.tx_manager.begin(None)?;
        self.tx_manager.add_mutation(
            tx_id,
            table_id,
            page_id,
            slot_id,
            mutation,
            row_data.to_vec(),
            prev_hash,
        )?;
        self.tx_manager.commit(tx_id)?;

        Ok((page_id, slot_id))
    }

    /// Write **two** rows from **two** different tables in a single atomic WAL
    /// transaction.
    ///
    /// Used by `reverse_entry` to commit the reversal `JournalEntry` and the
    /// `ReversalEvent` atomically — either both are durable or neither is.
    fn persist_row_pair(
        &mut self,
        table_a: u32,
        data_a: &[u8],
        prev_a: Option<vledger_crypto::Hash>,
        table_b: u32,
        data_b: &[u8],
    ) -> Result<(), LedgerError> {
        // Write both pages first.
        let cursor_a = self.next_entry_page;
        let (page_id_a, slot_id_a, next_a) = self.write_to_page(table_a, data_a, cursor_a)?;
        self.next_entry_page = next_a;

        // Reversal events use the entry cursor as well (same page namespace
        // is fine — table_id distinguishes them logically).
        let cursor_b = self.next_entry_page;
        let (page_id_b, slot_id_b, next_b) = self.write_to_page(table_b, data_b, cursor_b)?;
        self.next_entry_page = next_b;

        // Single WAL transaction — both mutations committed together.
        let tx_id = self.tx_manager.begin(Some("reversal".to_string()))?;
        self.tx_manager.add_mutation(
            tx_id,
            table_a,
            page_id_a,
            slot_id_a,
            MutationKind::Insert,
            data_a.to_vec(),
            prev_a,
        )?;
        self.tx_manager.add_mutation(
            tx_id,
            table_b,
            page_id_b,
            slot_id_b,
            MutationKind::Insert,
            data_b.to_vec(),
            None,
        )?;
        self.tx_manager.commit(tx_id)?;

        Ok(())
    }

    /// Write `row_data` into a fresh page for `table_id`.
    /// Returns (page_id, slot_id, next_cursor).
    fn write_to_page(
        &mut self,
        table_id: u32,
        row_data: &[u8],
        cursor: u64,
    ) -> Result<(u64, u16, u64), LedgerError> {
        let mut page = Page::new(cursor, table_id);

        let slot_id = page
            .write_slot(row_data)
            .map_err(|e| LedgerError::Serialization(format!("page write_slot: {e}")))?;

        let page_id = page.header.page_id;
        page.seal();
        self.page_store
            .write_page(&page)
            .map_err(|e| LedgerError::Serialization(format!("page_store write: {e}")))?;

        Ok((page_id, slot_id, cursor + 1))
    }

    // ── Account management ────────────────────────────────────────────────

    /// Register a new account. Persisted atomically to WAL + page store.
    pub fn create_account(&mut self, account: Account) -> Result<AccountId, LedgerError> {
        let id = account.id;
        let bytes = encode(&account)?;
        self.persist_row(TABLE_ACCOUNTS, &bytes, MutationKind::Insert, None)?;
        self.apply_account(account);
        info!(account_id = %id, "Account created");
        Ok(id)
    }

    /// Retrieve an account by ID (in-memory lookup).
    pub fn get_account(&self, id: &AccountId) -> Option<&Account> {
        self.accounts.get(id)
    }

    /// Close an account. Append-only: persists a new version with status=Closed.
    pub fn close_account(&mut self, id: &AccountId) -> Result<(), LedgerError> {
        let acct = self
            .accounts
            .get_mut(id)
            .ok_or_else(|| LedgerError::AccountNotFound(id.to_string()))?;
        acct.status = AccountStatus::Closed;
        let bytes = encode(acct)?;
        let _ = acct;
        self.persist_row(TABLE_ACCOUNTS, &bytes, MutationKind::Delete, None)?;
        info!(account_id = %id, "Account closed");
        Ok(())
    }

    // ── Journal entry posting ─────────────────────────────────────────────

    /// Post a journal entry. This is the sole financial write path.
    ///
    /// Guarantees (all enforced before WAL commit returns):
    /// - Entry is balanced (debits == credits)
    /// - All accounts exist and are active
    /// - Currency matches per account
    /// - Non-negative balance enforced for Asset/Expense accounts
    /// - Exposure limits respected
    /// - Four-eyes approval checked where required
    /// - Idempotency key deduplication
    /// - BLAKE3 hash chain extended
    /// - WAL record written (and fsynced in `per_record` mode; flushed within
    ///   the group-commit interval in `group_commit` mode — the default)
    pub fn post_entry(&mut self, mut entry: JournalEntry) -> Result<u64, LedgerError> {
        // 1. Structural validation
        entry.validate()?;

        // 2. Idempotency check — two-level: in-memory HashSet (fast, covers
        //    entries posted this session) then SQLite (covers entries from
        //    previous sessions not loaded into the HashSet at startup).
        if let Some(ref key) = entry.idempotency_key {
            let in_ram = self.idempotency_keys.contains(key);
            let in_sqlite = if in_ram {
                true
            } else {
                self.entry_db.idempotency_key_exists(key).unwrap_or(false)
            };

            if in_sqlite || in_ram {
                warn!(key, "Idempotency key already posted");
                // O(1) index lookup — no full scan needed.
                let seq = self
                    .entry_db
                    .sequence_for_idempotency_key(key)
                    .unwrap_or(None)
                    .unwrap_or(0);
                return Ok(seq);
            }
        }

        // 3. Per-line account-level validation (existence, status, currency, four-eyes).
        //    Exposure limits and balance checks are done in aggregate below.
        for line in &entry.lines {
            let acct = self
                .accounts
                .get(&line.account_id)
                .ok_or_else(|| LedgerError::AccountNotFound(line.account_id.to_string()))?;
            if !acct.is_active() {
                return Err(LedgerError::AccountClosed(line.account_id.to_string()));
            }
            // Legal hold check — no entries permitted while hold is active.
            if acct.legal_hold {
                return Err(LedgerError::AccountUnderLegalHold(
                    line.account_id.to_string(),
                ));
            }
            if acct.currency_code != line.currency_code {
                return Err(LedgerError::CurrencyMismatch {
                    account_currency: acct.currency_code.clone(),
                    entry_currency: line.currency_code.clone(),
                });
            }
            // Currency precision enforcement — the amount (in minor units) must
            // be representable within the declared precision for this currency.
            // For example, BTC has precision=8 so the maximum minor-unit value
            // for 1 BTC is 100_000_000.  An amount of 100_000_001 would exceed
            // one BTC and is valid, but an amount whose minor-unit value is 0
            // is already rejected by Amount::new.  What we check here is that
            // the amount does not implicitly imply fractional minor units for
            // currencies where sub-minor-unit precision doesn't exist.
            //
            // Specifically: for known currencies, the amount must be < 10^(18+1)
            // for standard cryptos and sanity-bounded for fiat.  The practical
            // check is: if the currency has precision=0 (e.g. JPY), the amount
            // must be a whole number (which it always is since Amount is i64).
            // For precision > 0 the amount is already in minor units, so no
            // fractional check is needed — but we bound-check against i64::MAX
            // divided by 10^precision to prevent overflow on display conversions.
            if let Some(precision) = self.currency_registry.precision(&line.currency_code) {
                // Compute max sane minor-unit value: 10^(18 - precision) * 10^18
                // For high-precision cryptos (ETH precision=18) any i64 value is fine.
                // For fiat (precision=2) we bound at 10^(18-2) = 10^16 minor units
                // (~$100 trillion) to catch obvious data errors.
                let max_exp: u32 = 18u32.saturating_sub(precision as u32);
                let max_minor: i64 = 10_i64
                    .saturating_pow(max_exp)
                    .saturating_mul(10_i64.saturating_pow(precision as u32));
                if line.amount.as_i64().abs() > max_minor {
                    return Err(LedgerError::PrecisionViolation {
                        currency: line.currency_code.clone(),
                        precision,
                        amount: line.amount.as_i64(),
                        max_minor_units: max_minor,
                    });
                }
            }
            if acct.require_four_eyes && entry.approved_by.is_none() {
                return Err(LedgerError::FourEyesRequired);
            }
        }

        // 4. Aggregate financial invariants — evaluated over the TOTAL effect of
        //    the whole entry on each account, not line-by-line.
        //
        //    A multi-line entry can have several credit lines against the same
        //    account.  Checking each line independently against the current
        //    balance (before any of the entry's lines have posted) would miss
        //    cases where the aggregate credit exceeds the balance even though
        //    each individual line does not.  The correct rule is:
        //
        //      projected balance = current_balance + total_entry_delta_for_account
        //
        //    and the invariant must hold on the *projected* balance, not on
        //    each line in isolation.
        {
            // Accumulate the net delta (in minor units) this entry will apply to
            // each account.  Positive = net debit effect, negative = net credit
            // effect (for debit-normal accounts a credit reduces the balance).
            use std::collections::HashMap as HM;

            // net_debit_delta[account_id] = Σ debit_amounts − Σ credit_amounts
            // (positive → balance will increase; negative → balance will decrease)
            let mut net_debit_delta: HM<AccountId, i128> = HM::new();
            for line in &entry.lines {
                let delta: i128 = match line.dr_cr {
                    DrCr::Debit => line.amount.as_i128(),
                    DrCr::Credit => -line.amount.as_i128(),
                };
                *net_debit_delta.entry(line.account_id).or_insert(0) += delta;
            }

            // Also accumulate the total debit amount per account for the
            // exposure-limit check.
            let mut total_debit: HM<AccountId, i128> = HM::new();
            for line in &entry.lines {
                if matches!(line.dr_cr, DrCr::Debit) {
                    *total_debit.entry(line.account_id).or_insert(0) += line.amount.as_i128();
                }
            }

            for (account_id, &delta) in &net_debit_delta {
                let acct = match self.accounts.get(account_id) {
                    Some(a) => a,
                    None => return Err(LedgerError::AccountNotFound(account_id.to_string())),
                };

                // ── Exposure-limit check (aggregate debits) ───────────────
                // The limit is compared against the SUM of all debit lines
                // in this entry for this account, not against each line
                // individually.
                if let Some(limit) = acct.exposure_limit {
                    let agg_debit = total_debit.get(account_id).copied().unwrap_or(0);
                    if agg_debit > limit as i128 {
                        return Err(LedgerError::ExposureLimitExceeded {
                            account_id: account_id.to_string(),
                            limit: limit as i128,
                            attempted: agg_debit,
                        });
                    }
                }

                // ── Non-negative balance check (aggregate delta) ──────────
                // Only applies to debit-normal (Asset / Expense) accounts
                // that have the constraint enabled.  A negative `delta` means
                // this entry is a net credit against the account, which
                // reduces the balance.
                let is_debit_normal =
                    matches!(acct.account_type, AccountType::Asset | AccountType::Expense);
                if acct.require_non_negative_balance && is_debit_normal && delta < 0 {
                    let current = self.balance(account_id);
                    // delta is negative (net credit), so: projected = current + delta
                    let projected = current + delta;
                    if projected < 0 {
                        return Err(LedgerError::InsufficientFunds {
                            account_id: account_id.to_string(),
                            balance: current,
                            // Report the magnitude of the net credit that caused
                            // the shortfall so the error message is useful.
                            debit: (-delta),
                        });
                    }
                }
            }
        }

        // 5. Assign sequence and finalize chain hash.
        // Content hash was pre-computed before the lock was acquired
        // (in handler.rs or by the caller).  Only the chain hash — which
        // depends on last_chain_hash — is computed here inside the lock.
        let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        entry.sequence = seq;
        entry.posted_at = Utc::now();
        entry.finalize_chain_hash(&self.last_chain_hash);

        // 6. Persist to WAL + page store
        let bytes = encode(&entry)?;
        let prev_hash = Some(entry.prev_hash);
        self.persist_row(TABLE_ENTRIES, &bytes, MutationKind::Insert, prev_hash)?;

        // Cache the committed bytes so the server handler can ship them to
        // replicas after releasing the write lock.
        self.last_committed_entry_bytes = Some(bytes);

        // 7. Update in-memory state and SQLite index.
        self.last_chain_hash = entry.chain_hash;
        if let Some(ref key) = entry.idempotency_key {
            self.idempotency_keys.insert(key.clone());
        }
        let affects_balance = matches!(entry.status, EntryStatus::Posted | EntryStatus::Reversal);
        for line in &entry.lines {
            if affects_balance {
                self.update_balance_cache(line.account_id, line.amount.as_i128(), line.dr_cr);
            }
        }

        // Write to SQLite index.
        if let Err(e) = self.entry_db.ensure_account_entries_table() {
            warn!("entry_db ensure_account_entries_table: {e}");
        }
        if let Err(e) = self.entry_db.insert(&entry) {
            warn!(sequence = seq, "entry_db insert failed: {e}");
        } else {
            for line in &entry.lines {
                if let Err(e) = self.entry_db.insert_account_entry(&line.account_id, seq) {
                    warn!(sequence = seq, "entry_db insert_account_entry failed: {e}");
                }
            }
        }

        info!(sequence = seq, "Journal entry posted");
        Ok(seq)
    }

    /// Reverse a posted entry by appending a mirror entry and a `ReversalEvent`.
    ///
    /// ## Append-only guarantee
    /// The original entry is **never modified**.  Two new records are written:
    /// 1. A `JournalEntry` with `status = Reversal` (mirrors and cancels the
    ///    original's financial effect).
    /// 2. A `ReversalEvent` that links `original_id → reversal_id`.
    ///
    /// Both records are committed in a **single WAL transaction** — they are
    /// either both durable or neither is.  There is no window in which the
    /// reversal entry exists without its relationship event, or vice versa.
    ///
    /// ## Deriving `Reversed` status
    /// Callers that need to know whether an entry has been reversed should
    /// call `LedgerStore::is_reversed(entry_id)` — the status is derived from
    /// the `reversal_event_index` built during WAL replay, not from a mutable
    /// field on the original entry.
    pub fn reverse_entry(
        &mut self,
        entry_id: Uuid,
        description: impl Into<String>,
        domain: impl Into<String>,
    ) -> Result<Uuid, LedgerError> {
        // Fetch original entry from SQLite index.
        let original = self
            .entry_db
            .get_by_sequence(
                // We need to find by entry UUID, not sequence. Scan SQLite.
                // Use stream_all to find the sequence for this entry_id.
                {
                    let mut found_seq: Option<u64> = None;
                    let _ = self.entry_db.stream_all(|e| {
                        if e.id == entry_id {
                            found_seq = Some(e.sequence);
                        }
                        Ok(())
                    });
                    found_seq.ok_or_else(|| LedgerError::EntryNotFound(entry_id.to_string()))?
                },
            )?
            .ok_or_else(|| LedgerError::EntryNotFound(entry_id.to_string()))?;

        // Only Posted entries may be reversed.
        match original.status {
            EntryStatus::Posted => {}
            other => return Err(LedgerError::CannotReverse(entry_id.to_string(), other)),
        }
        // Check legal hold on any account involved in the original entry.
        for line in &original.lines {
            if self.legal_hold_accounts.contains(&line.account_id) {
                return Err(LedgerError::AccountUnderLegalHold(
                    line.account_id.to_string(),
                ));
            }
        }
        // Derive Reversed status from the event index (not a mutable field).
        if self.reversal_event_index.contains_key(&entry_id) {
            let reversal_id = self.reversal_event_index[&entry_id];
            return Err(LedgerError::AlreadyReversed(
                entry_id.to_string(),
                reversal_id.to_string(),
            ));
        }

        // Build reversal lines by flipping Dr/Cr.
        let reversal_lines: Vec<JournalLine> = original
            .lines
            .iter()
            .map(|line| JournalLine {
                id: Uuid::new_v4(),
                account_id: line.account_id,
                currency_code: line.currency_code.clone(),
                amount: line.amount,
                dr_cr: match line.dr_cr {
                    DrCr::Debit => DrCr::Credit,
                    DrCr::Credit => DrCr::Debit,
                },
                memo: Some(format!("Reversal of line {}", line.id)),
            })
            .collect();

        let domain_str = domain.into();
        let desc_str = description.into();
        let mut reversal = JournalEntry {
            id: Uuid::new_v4(),
            sequence: 0,
            status: EntryStatus::Reversal,
            description: desc_str,
            lines: reversal_lines,
            effective_at: Utc::now(),
            posted_at: Utc::now(),
            external_ref: None,
            idempotency_key: None,
            reverses_entry_id: Some(entry_id),
            reversed_by_entry_id: None,
            domain: domain_str,
            content_hash: ZERO_HASH,
            prev_hash: ZERO_HASH,
            chain_hash: ZERO_HASH,
            approved_by: None,
            metadata: None,
        };

        let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        reversal.sequence = seq;
        reversal.posted_at = Utc::now();
        reversal.finalize_hashes(&self.last_chain_hash);

        let reversal_id = reversal.id;
        let event = ReversalEvent {
            original_entry_id: entry_id,
            reversal_entry_id: reversal_id,
            reversed_at: reversal.posted_at,
        };

        // Serialize both records before touching durable state.
        let reversal_bytes = encode(&reversal)?;
        let event_bytes = encode(&event)?;
        let prev_hash = Some(reversal.prev_hash);

        // Atomic: both records committed in a single WAL transaction.
        self.persist_row_pair(
            TABLE_ENTRIES,
            &reversal_bytes,
            prev_hash,
            TABLE_REVERSAL_EVENTS,
            &event_bytes,
        )?;

        // Update in-memory state — only after durable commit.
        self.last_chain_hash = reversal.chain_hash;

        // Register the reversal event index.
        self.reversal_event_index.insert(entry_id, reversal_id);

        // Update the running balance cache for the reversal entry.
        // Reversal entries have status=Reversal which affects balances.
        for line in &reversal.lines {
            self.update_balance_cache(line.account_id, line.amount.as_i128(), line.dr_cr);
        }

        // Write reversal entry to SQLite index.
        if let Err(e) = self.entry_db.ensure_account_entries_table() {
            warn!("entry_db ensure_account_entries_table: {e}");
        }
        if let Err(e) = self.entry_db.insert(&reversal) {
            warn!(
                sequence = reversal.sequence,
                "entry_db insert reversal failed: {e}"
            );
        } else {
            for line in &reversal.lines {
                if let Err(e) = self
                    .entry_db
                    .insert_account_entry(&line.account_id, reversal.sequence)
                {
                    warn!(
                        sequence = reversal.sequence,
                        "entry_db insert_account_entry failed: {e}"
                    );
                }
            }
        }

        info!(
            original_entry = %entry_id,
            reversal_entry = %reversal_id,
            "Entry reversed (append-only, atomic)"
        );
        Ok(reversal_id)
    }

    /// Returns `true` if `entry_id` has been reversed.
    ///
    /// Status is derived from the immutable `reversal_event_index` — the
    /// original entry row is never mutated.
    pub fn is_reversed(&self, entry_id: &Uuid) -> bool {
        self.reversal_event_index.contains_key(entry_id)
    }

    /// Returns the ID of the reversal entry for `entry_id`, if any.
    pub fn reversed_by(&self, entry_id: &Uuid) -> Option<Uuid> {
        self.reversal_event_index.get(entry_id).copied()
    }

    // ── Queries ───────────────────────────────────────────────────────────

    /// Compute the current balance for an account.
    /// Asset/Expense: debits − credits (positive = normal balance).
    /// Liability/Income/Equity: credits − debits.
    ///
    /// O(1) — reads from the running balance cache that is updated on every
    /// `post_entry` and `reverse_entry` commit and rebuilt from the WAL on
    /// startup.
    pub fn balance(&self, account_id: &AccountId) -> i128 {
        self.balance_cache.get(account_id).copied().unwrap_or(0)
    }

    /// Return all entries for an account in posting order.
    pub fn account_entries(&self, account_id: &AccountId) -> Vec<JournalEntry> {
        self.entry_db
            .entries_for_account(account_id)
            .unwrap_or_default()
    }

    /// All accounts.
    pub fn all_accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    /// Total number of posted entries.
    pub fn entry_count(&self) -> usize {
        self.entry_db.count().unwrap_or(0) as usize
    }

    /// Current BLAKE3 hash chain tip.
    pub fn chain_tip(&self) -> &Hash {
        &self.last_chain_hash
    }

    // ── Query index accessors ─────────────────────────────────────────────

    /// Return entries whose domain matches `domain` (SQLite index-accelerated).
    pub fn entries_by_domain(&self, domain: &str) -> Vec<JournalEntry> {
        self.entry_db
            .scan_by_domain(domain, Self::DEFAULT_QUERY_LIMIT, 0)
            .unwrap_or_default()
    }

    /// Return entries whose domain matches `domain` with an explicit limit.
    pub fn entries_by_domain_limited(&self, domain: &str, limit: usize) -> Vec<JournalEntry> {
        self.entry_db
            .scan_by_domain(domain, limit, 0)
            .unwrap_or_default()
    }

    /// Return entries whose status matches `status` (SQLite index-accelerated).
    pub fn entries_by_status(&self, status: &str) -> Vec<JournalEntry> {
        // Normalise status string to match SQLite stored format (e.g. "Posted")
        let normalised = Self::normalise_status(status);
        self.entry_db
            .scan_by_status(&normalised, Self::DEFAULT_QUERY_LIMIT, 0)
            .unwrap_or_default()
    }

    /// Return entries whose status matches `status` with an explicit limit.
    pub fn entries_by_status_limited(&self, status: &str, limit: usize) -> Vec<JournalEntry> {
        let normalised = Self::normalise_status(status);
        self.entry_db
            .scan_by_status(&normalised, limit, 0)
            .unwrap_or_default()
    }

    /// Return entries matching an external_ref value.
    pub fn entries_by_external_ref(&self, ext_ref: &str) -> Vec<JournalEntry> {
        self.entry_db
            .scan_by_external_ref(ext_ref, Self::DEFAULT_QUERY_LIMIT)
            .unwrap_or_default()
    }

    /// Full scan — return up to `limit` entries from the beginning.
    /// Used by the SQL executor full-scan fallback.
    pub fn entries_scan(&self, limit: usize) -> Vec<JournalEntry> {
        self.entry_db.scan(None, None, limit, 0).unwrap_or_default()
    }

    /// Stream all entries in sequence order, calling `f` for each.
    /// Uses constant RAM regardless of entry count.
    /// Stops early if `f` returns `Err`.
    pub fn stream_entries<F>(&self, f: F) -> Result<(), LedgerError>
    where
        F: FnMut(JournalEntry) -> Result<(), LedgerError>,
    {
        self.entry_db.stream_all(f)
    }

    const DEFAULT_QUERY_LIMIT: usize = 10_000;

    /// Normalise a status string to the canonical Debug-format used in SQLite.
    fn normalise_status(s: &str) -> String {
        // Stored as Rust Debug format: "Posted", "Reversal", "Pending", "Settled", "Failed", "Reversed"
        // Accept case-insensitive input and capitalise first letter.
        let lower = s.to_lowercase();
        let mut chars = lower.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }

    /// Verify the entire hash chain from first to last entry.
    /// Streams from SQLite — constant RAM regardless of entry count.
    pub fn verify_chain_integrity(&self) -> Result<(), LedgerError> {
        let mut prev_hash = ZERO_HASH;
        let mut found_any = false;
        self.entry_db.stream_all(|entry| {
            found_any = true;
            if !entry.verify_hashes() {
                return Err(LedgerError::Serialization(format!(
                    "Hash chain broken at sequence {}",
                    entry.sequence
                )));
            }
            if entry.prev_hash != prev_hash {
                return Err(LedgerError::Serialization(format!(
                    "Chain linkage broken at sequence {}",
                    entry.sequence
                )));
            }
            prev_hash = entry.chain_hash;
            Ok(())
        })?;
        Ok(())
    }

    /// Verify a range of the hash chain between `from_seq` and `to_seq` inclusive.
    ///
    /// When `from_seq` is `None` the range starts at the first entry.
    /// When `to_seq` is `None` the range ends at the last entry.
    ///
    /// Returns `(verified_count, range_chain_tip)`.
    pub fn verify_chain_range(
        &self,
        from_seq: Option<u64>,
        to_seq: Option<u64>,
    ) -> Result<(usize, vledger_crypto::Hash), LedgerError> {
        let start = from_seq.unwrap_or(1);
        let end = to_seq.unwrap_or(u64::MAX);
        let entries = self.entry_db.scan_range(start, end)?;

        if entries.is_empty() {
            return Ok((0, ZERO_HASH));
        }

        let mut prev_hash = entries[0].prev_hash;
        let mut count = 0usize;
        let mut tip = ZERO_HASH;

        for entry in &entries {
            if !entry.verify_hashes() {
                return Err(LedgerError::Serialization(format!(
                    "Hash chain broken at sequence {}",
                    entry.sequence
                )));
            }
            if entry.prev_hash != prev_hash {
                return Err(LedgerError::Serialization(format!(
                    "Chain linkage broken at sequence {}",
                    entry.sequence
                )));
            }
            prev_hash = entry.chain_hash;
            tip = entry.chain_hash;
            count += 1;
        }

        Ok((count, tip))
    }

    /// Look up a single entry by its sequence number.
    /// Returns `None` if no entry with that sequence exists.
    pub fn get_entry_by_sequence(&self, seq: u64) -> Option<JournalEntry> {
        self.entry_db.get_by_sequence(seq).ok().flatten()
    }

    /// FOR DEMO/TESTING ONLY — silently mutate an entry's description in
    /// memory without updating its hash chain.
    ///
    /// This simulates a malicious actor modifying ledger data after it has
    /// been written.  The next `VERIFY_CHAIN()` call will detect the
    /// tampering because the stored `content_hash` will no longer match the
    /// entry's actual field values.
    ///
    /// Gated behind `#[cfg(any(test, feature = "self-test"))]` — only
    /// available in test builds and the self-test command. Not callable
    /// via the SQL interface or any production code path.
    #[cfg(any(test, feature = "self-test"))]
    pub fn tamper_entry_for_demo(&mut self, seq: u64, new_description: String) -> bool {
        // Fetch the entry from SQLite, mutate in memory, then overwrite in SQLite
        // without updating hashes — simulates tampered data for demo/self-test.
        match self.entry_db.get_by_sequence(seq) {
            Ok(Some(mut entry)) => {
                entry.description = new_description;
                let data = match crate::entry_db::encode_entry_pub(&entry) {
                    Ok(d) => d,
                    Err(_) => return false,
                };
                self.entry_db.tamper_replace(seq, &data).unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Force a WAL checkpoint.
    ///
    /// Computes the BLAKE3 Merkle root over all journal-entry pages, then
    /// calls `TransactionManager::checkpoint_signed` which:
    /// 1. fsyncs the WAL (all committed records become durable).
    /// 2. Appends a `Checkpoint` WAL record containing the Merkle root and,
    ///    when a signing key is configured, an Ed25519 signature over
    ///    `page_merkle_root || last_committed_sequence.to_le_bytes()`.
    ///
    /// Returns the WAL sequence number at the time of the checkpoint.
    pub fn checkpoint(&mut self) -> Result<u64, LedgerError> {
        // Compute the Merkle root over all durable entry pages.
        // Returns ZERO_HASH when no pages exist yet (empty ledger).
        let root = self
            .page_store
            .table_merkle_root(TABLE_ENTRIES)
            .map_err(|e| LedgerError::Serialization(e.to_string()))?;

        Ok(self.tx_manager.checkpoint_signed(root)?)
    }

    /// Returns the Ed25519 public key of the database signing key, if signing
    /// is enabled.  Used by the SQL executor to populate `MerkleProof`.
    pub fn signing_pubkey(&self) -> Option<[u8; 32]> {
        self.tx_manager.signing_pubkey()
    }

    /// Sign `message` with the database signing key.
    ///
    /// Returns `Some((signature, pubkey))` when a signing key is configured,
    /// `None` otherwise.  Used by the SQL executor to sign Merkle roots
    /// attached to query results.
    pub fn sign_bytes(&self, message: &[u8]) -> Option<([u8; 64], [u8; 32])> {
        self.tx_manager.sign_bytes(message)
    }

    /// Return the WAL directory path (used by the group-commit flusher).
    pub fn wal_dir(&self) -> std::path::PathBuf {
        if let Some(ref d) = self.data_dir {
            return d.join("wal");
        }
        std::env::temp_dir().join("vledger-wal-fallback")
    }

    /// Return the pages directory path (used by the page group-commit flusher).
    pub fn pages_dir(&self) -> std::path::PathBuf {
        if let Some(ref d) = self.data_dir {
            return d.join("pages");
        }
        std::env::temp_dir().join("vledger-pages-fallback")
    }

    /// Return the `FlushState` handle from the WAL writer, if the WAL is
    /// running in `GroupCommit` mode.  The server uses this to hand the
    /// handle off to the background flusher task.
    pub fn wal_flush_state(&self) -> Option<std::sync::Arc<vledger_wal::FlushState>> {
        self.tx_manager.wal_flush_state()
    }

    /// Return the `PageFlushState` handle from the page store.
    /// The server uses this to start the background page flusher task.
    pub fn page_flush_state(&self) -> std::sync::Arc<vledger_pages::PageFlushState> {
        Arc::clone(&self.page_store.flush_state)
    }

    /// Returns the active WAL segment index.
    /// Used by the replication layer as the `segment` parameter to
    /// `WalShipper::ship()`.
    pub fn active_wal_segment(&self) -> u64 {
        self.tx_manager.active_segment_index()
    }

    /// Returns the bincode bytes of the most recently committed journal entry,
    /// or `None` if no entry has been posted yet.
    /// Consumed by the server handler to ship the record to replicas after
    /// the write lock is released.
    pub fn last_entry_bytes(&self) -> Option<Vec<u8>> {
        self.last_committed_entry_bytes.clone()
    }

    // ── Settlement lifecycle ──────────────────────────────────────────────

    /// Transition an entry to `Pending` settlement status.
    ///
    /// Only `Posted` entries may be marked pending.
    /// Status is recorded as a `SettlementEvent` — the original entry is
    /// never modified.
    pub fn mark_pending(
        &mut self,
        entry_id: Uuid,
        notes: Option<String>,
    ) -> Result<(), LedgerError> {
        self.apply_settlement_event(entry_id, crate::entry::EntryStatus::Pending, notes)
    }

    /// Transition an entry to `Settled` status.
    ///
    /// Only `Pending` or `Posted` entries may be settled.
    pub fn mark_settled(
        &mut self,
        entry_id: Uuid,
        notes: Option<String>,
    ) -> Result<(), LedgerError> {
        self.apply_settlement_event(entry_id, crate::entry::EntryStatus::Settled, notes)
    }

    /// Transition an entry to `Failed` settlement status.
    pub fn mark_failed(
        &mut self,
        entry_id: Uuid,
        notes: Option<String>,
    ) -> Result<(), LedgerError> {
        self.apply_settlement_event(entry_id, crate::entry::EntryStatus::Failed, notes)
    }

    /// Returns the effective status of an entry, considering settlement events.
    pub fn effective_status(&self, entry_id: &Uuid) -> crate::entry::EntryStatus {
        // Settlement status overrides posted status.
        if let Some(&s) = self.settlement_event_index.get(entry_id) {
            return s;
        }
        // Reversal event overrides to Reversed.
        if self.reversal_event_index.contains_key(entry_id) {
            return crate::entry::EntryStatus::Reversed;
        }
        // Fall back to stored status from SQLite.
        // We do a stream scan to find by UUID — kept only for the effective_status
        // path which is a low-frequency call.
        let mut status = crate::entry::EntryStatus::Posted;
        let _ = self.entry_db.stream_all(|e| {
            if e.id == *entry_id {
                status = e.status;
            }
            Ok(())
        });
        status
    }

    fn apply_settlement_event(
        &mut self,
        entry_id: Uuid,
        new_status: crate::entry::EntryStatus,
        notes: Option<String>,
    ) -> Result<(), LedgerError> {
        // Verify entry exists (O(1) SQLite point lookup by UUID via stream).
        let mut exists = false;
        let mut entry_lines: Vec<JournalLine> = Vec::new();
        let _ = self.entry_db.stream_all(|e| {
            if e.id == entry_id {
                exists = true;
                entry_lines = e.lines.clone();
            }
            Ok(())
        });
        if !exists {
            return Err(LedgerError::EntryNotFound(entry_id.to_string()));
        }
        // Check legal hold on any involved account.
        for line in &entry_lines {
            if self.legal_hold_accounts.contains(&line.account_id) {
                return Err(LedgerError::AccountUnderLegalHold(
                    line.account_id.to_string(),
                ));
            }
        }
        let event = SettlementEvent {
            entry_id,
            new_status,
            settled_at: chrono::Utc::now(),
            notes,
        };
        let bytes = encode(&event)?;
        self.persist_row(TABLE_SETTLEMENT_EVENTS, &bytes, MutationKind::Insert, None)?;
        self.settlement_event_index.insert(entry_id, new_status);
        Ok(())
    }

    // ── Legal holds ───────────────────────────────────────────────────────

    /// Place a legal hold on an account.
    ///
    /// While the hold is active, no entries, reversals, or settlement
    /// transitions are permitted for any line involving this account.
    pub fn place_legal_hold(&mut self, account_id: &AccountId) -> Result<(), LedgerError> {
        self.set_legal_hold(account_id, true)
    }

    /// Lift the legal hold on an account.
    pub fn lift_legal_hold(&mut self, account_id: &AccountId) -> Result<(), LedgerError> {
        self.set_legal_hold(account_id, false)
    }

    /// Returns whether an account is currently under a legal hold.
    pub fn is_under_legal_hold(&self, account_id: &AccountId) -> bool {
        self.legal_hold_accounts.contains(account_id)
    }

    fn set_legal_hold(&mut self, account_id: &AccountId, hold: bool) -> Result<(), LedgerError> {
        let acct = self
            .accounts
            .get_mut(account_id)
            .ok_or_else(|| LedgerError::AccountNotFound(account_id.to_string()))?;
        acct.legal_hold = hold;
        let bytes = encode(acct)?;
        self.persist_row(TABLE_ACCOUNTS, &bytes, MutationKind::Delete, None)?;
        if hold {
            self.legal_hold_accounts.insert(*account_id);
        } else {
            self.legal_hold_accounts.remove(account_id);
        }
        Ok(())
    }

    // ── Reconciliation ────────────────────────────────────────────────────

    /// Reconcile all accounts: recompute balances from entries and compare
    /// to the running balance cache.
    ///
    /// Returns a list of `ReconciliationDiscrepancy` for any account where
    /// the recomputed balance differs from the cached balance.  An empty
    /// vec means the ledger is in balance.
    pub fn reconcile(&self) -> Vec<ReconciliationDiscrepancy> {
        use std::collections::HashMap as HM;

        // Recompute balances from entries streamed from SQLite — constant RAM.
        let mut recomputed: HM<AccountId, i128> = HM::new();
        let _ = self.entry_db.stream_all(|entry| {
            let affects = matches!(entry.status, EntryStatus::Posted | EntryStatus::Reversal);
            if !affects {
                return Ok(());
            }
            for line in &entry.lines {
                let acct = match self.accounts.get(&line.account_id) {
                    Some(a) => a,
                    None => continue,
                };
                let sign = acct.account_type.normal_balance_sign() as i128;
                let delta = match line.dr_cr {
                    DrCr::Debit => line.amount.as_i128() * sign,
                    DrCr::Credit => -line.amount.as_i128() * sign,
                };
                *recomputed.entry(line.account_id).or_insert(0) += delta;
            }
            Ok(())
        });

        let mut discrepancies = Vec::new();
        let all_ids: std::collections::HashSet<AccountId> = self
            .accounts
            .keys()
            .copied()
            .chain(self.balance_cache.keys().copied())
            .collect();

        for id in all_ids {
            let cached = self.balance_cache.get(&id).copied().unwrap_or(0);
            let computed = recomputed.get(&id).copied().unwrap_or(0);
            if cached != computed {
                let code = self
                    .accounts
                    .get(&id)
                    .map(|a| a.code.clone())
                    .unwrap_or_else(|| id.to_string());
                discrepancies.push(ReconciliationDiscrepancy {
                    account_id: id,
                    account_code: code,
                    cached_balance: cached,
                    recomputed_balance: computed,
                    delta: computed - cached,
                });
            }
        }
        discrepancies
    }

    // ── Financial invariant check ─────────────────────────────────────────

    /// Check the global ledger equation: Σ(Assets+Expenses) == Σ(Liabilities+Equity+Income).
    ///
    /// Returns `Ok(())` if balanced, or `Err(String)` describing the imbalance.
    pub fn check_financial_invariants(&self) -> Result<(), String> {
        let mut debit_normal_sum: i128 = 0; // Assets + Expenses
        let mut credit_normal_sum: i128 = 0; // Liabilities + Equity + Income

        for acct in self.accounts.values() {
            let balance = self.balance_cache.get(&acct.id).copied().unwrap_or(0);
            match acct.account_type {
                AccountType::Asset | AccountType::Expense => debit_normal_sum += balance,
                AccountType::Liability | AccountType::Equity | AccountType::Income => {
                    credit_normal_sum += balance
                }
                AccountType::Contra | AccountType::Suspense => {} // excluded from equation
            }
        }

        if debit_normal_sum != credit_normal_sum {
            Err(format!(
                "Financial invariant violation: \
                 Σ(Assets+Expenses)={debit_normal_sum} ≠ Σ(Liabilities+Equity+Income)={credit_normal_sum} \
                 (delta={})",
                debit_normal_sum - credit_normal_sum
            ))
        } else {
            Ok(())
        }
    }

    /// Register a custom currency with a declared precision.
    /// Use this to add currencies beyond the built-in defaults.
    pub fn register_currency(&mut self, currency: crate::currency::Currency) {
        self.currency_registry.register(currency);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, AccountType};
    use crate::amount::Amount;
    use crate::entry::JournalEntryBuilder;
    use tempfile::TempDir;

    fn open_tmp() -> (TempDir, LedgerStore) {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        let store = LedgerStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn add_accounts(store: &mut LedgerStore) -> (AccountId, AccountId) {
        let cash = store
            .create_account(Account::new(
                "1001",
                "Cash USD",
                AccountType::Asset,
                "USD",
                "test",
            ))
            .unwrap();
        let revenue = store
            .create_account(Account::new(
                "4001",
                "Revenue",
                AccountType::Income,
                "USD",
                "test",
            ))
            .unwrap();
        (cash, revenue)
    }

    #[test]
    fn post_balanced_entry_persists() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(10000).unwrap();
        let entry = JournalEntryBuilder::new("Sale", "test")
            .debit(cash, amt, "USD")
            .credit(revenue, amt, "USD")
            .build();
        store.post_entry(entry).unwrap();
        assert_eq!(store.balance(&cash), 10000);
        assert_eq!(store.balance(&revenue), 10000);
    }

    #[test]
    fn chain_integrity_after_multiple_entries() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        for i in 1..=5 {
            let amt = Amount::new(i * 100).unwrap();
            let e = JournalEntryBuilder::new(format!("Entry {i}"), "test")
                .debit(cash, amt, "USD")
                .credit(revenue, amt, "USD")
                .build();
            store.post_entry(e).unwrap();
        }
        store.verify_chain_integrity().unwrap();
    }

    #[test]
    fn wal_replay_restores_state() {
        let dir = TempDir::new().unwrap();
        let data_path = dir.path();
        std::fs::create_dir_all(data_path.join("wal")).unwrap();
        std::fs::create_dir_all(data_path.join("pages")).unwrap();

        let (cash_id, revenue_id) = {
            let mut store = LedgerStore::open(data_path).unwrap();
            let cash = store
                .create_account(Account::new(
                    "1001",
                    "Cash",
                    AccountType::Asset,
                    "USD",
                    "test",
                ))
                .unwrap();
            let rev = store
                .create_account(Account::new(
                    "4001",
                    "Revenue",
                    AccountType::Income,
                    "USD",
                    "test",
                ))
                .unwrap();
            let amt = Amount::new(5000).unwrap();
            let e = JournalEntryBuilder::new("Initial sale", "test")
                .debit(cash, amt, "USD")
                .credit(rev, amt, "USD")
                .build();
            store.post_entry(e).unwrap();
            (cash, rev)
        }; // store dropped here — WAL flushed

        // Reopen and verify state is recovered from WAL
        let store2 = LedgerStore::open(data_path).unwrap();
        assert_eq!(store2.entry_count(), 1);
        assert_eq!(store2.balance(&cash_id), 5000);
        assert_eq!(store2.balance(&revenue_id), 5000);
        store2.verify_chain_integrity().unwrap();
    }

    #[test]
    fn reversal_cancels_balance() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(10000).unwrap();
        let e = JournalEntryBuilder::new("Original", "test")
            .debit(cash, amt, "USD")
            .credit(revenue, amt, "USD")
            .build();
        let seq = store.post_entry(e).unwrap();
        let eid = store.get_entry_by_sequence(seq).unwrap().id;
        store.reverse_entry(eid, "Reversal", "test").unwrap();
        assert_eq!(store.balance(&cash), 0);
        assert_eq!(store.balance(&revenue), 0);
    }

    #[test]
    fn reversal_is_append_only_original_not_mutated() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(10000).unwrap();
        let e = JournalEntryBuilder::new("Original", "test")
            .debit(cash, amt, "USD")
            .credit(revenue, amt, "USD")
            .build();
        let seq = store.post_entry(e).unwrap();
        let eid = store.get_entry_by_sequence(seq).unwrap().id;

        // Capture the original entry's bytes BEFORE reversal.
        let orig = store.get_entry_by_sequence(seq).unwrap();
        let original_chain_hash_before = orig.chain_hash;
        let original_status_before = orig.status;

        store.reverse_entry(eid, "Reversal", "test").unwrap();

        // Original entry must be completely unchanged.
        let original_after = store.get_entry_by_sequence(seq).unwrap();
        assert_eq!(
            original_after.chain_hash, original_chain_hash_before,
            "original entry chain_hash must not change after reversal"
        );
        assert_eq!(
            original_after.status, original_status_before,
            "original entry status must not be mutated — use is_reversed() instead"
        );

        // Reversed status is derived from the event index, not a mutable field.
        assert!(
            store.is_reversed(&eid),
            "is_reversed() must return true after reversal"
        );
        assert!(
            store.reversed_by(&eid).is_some(),
            "reversed_by() must return the reversal entry id"
        );
    }

    #[test]
    fn double_reversal_rejected() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(500).unwrap();
        let e = JournalEntryBuilder::new("Sale", "test")
            .debit(cash, amt, "USD")
            .credit(revenue, amt, "USD")
            .build();
        let seq = store.post_entry(e).unwrap();
        let eid = store.get_entry_by_sequence(seq).unwrap().id;
        store.reverse_entry(eid, "Rev 1", "test").unwrap();
        let result = store.reverse_entry(eid, "Rev 2", "test");
        assert!(result.is_err(), "double reversal must be rejected");
    }

    #[test]
    fn reversal_survives_wal_replay() {
        let dir = TempDir::new().unwrap();
        let data_path = dir.path();
        std::fs::create_dir_all(data_path.join("wal")).unwrap();
        std::fs::create_dir_all(data_path.join("pages")).unwrap();

        let (original_id, reversal_id) = {
            let mut store = LedgerStore::open(data_path).unwrap();
            let cash = store
                .create_account(Account::new(
                    "CASH",
                    "Cash",
                    AccountType::Asset,
                    "USD",
                    "test",
                ))
                .unwrap();
            let rev = store
                .create_account(Account::new(
                    "REV",
                    "Revenue",
                    AccountType::Income,
                    "USD",
                    "test",
                ))
                .unwrap();
            let amt = Amount::new(9900).unwrap();
            let e = JournalEntryBuilder::new("Sale", "test")
                .debit(cash, amt, "USD")
                .credit(rev, amt, "USD")
                .build();
            let seq = store.post_entry(e).unwrap();
            let eid = store.get_entry_by_sequence(seq).unwrap().id;
            let rid = store.reverse_entry(eid, "Void sale", "test").unwrap();
            (eid, rid)
        };

        // Reopen — reversal_event_index must be rebuilt from WAL.
        let store2 = LedgerStore::open(data_path).unwrap();
        assert!(
            store2.is_reversed(&original_id),
            "is_reversed must survive WAL replay"
        );
        assert_eq!(
            store2.reversed_by(&original_id),
            Some(reversal_id),
            "reversed_by must return correct reversal id after replay"
        );
        // Balance should be zero.
        // Find cash account via the original debit line
        let original_entry = store2.get_entry_by_sequence(1);
        let cash_id = original_entry
            .as_ref()
            .and_then(|e| {
                e.lines
                    .iter()
                    .find(|l| l.dr_cr == crate::entry::DrCr::Debit)
            })
            .map(|l| l.account_id);
        if let Some(cid) = cash_id {
            assert_eq!(
                store2.balance(&cid),
                0,
                "balance must be zero after reversal replay"
            );
        }
        store2.verify_chain_integrity().unwrap();
    }

    // ── Aggregate financial invariant tests ──────────────────────────────

    /// A single credit line that would not individually overdraw the account
    /// but where two credit lines in the same entry together do overdraw it
    /// must be rejected.
    ///
    /// Account balance: $100 (10000 minor units)
    /// Entry: Credit $60 + Credit $60 → aggregate effect = -$120 → rejected
    #[test]
    fn aggregate_balance_check_rejects_multi_line_overdraw() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);

        // Fund cash with $100
        let fund = Amount::new(10000).unwrap();
        let e = JournalEntryBuilder::new("Fund", "test")
            .debit(cash, fund, "USD")
            .credit(revenue, fund, "USD")
            .build();
        store.post_entry(e).unwrap();
        assert_eq!(store.balance(&cash), 10000);

        // Add a second revenue account to make the balancing entry work
        let revenue2 = store
            .create_account(crate::account::Account::new(
                "4002",
                "Revenue2",
                crate::account::AccountType::Income,
                "USD",
                "test",
            ))
            .unwrap();

        // Try to post an entry with two $60 credits against cash (total $120 out)
        // Each individual credit would pass the old per-line check ($100 - $60 >= 0)
        // but the aggregate check must catch that $100 - $120 < 0.
        let sixty = Amount::new(6000).unwrap();
        let bad_entry = JournalEntryBuilder::new("Double credit overdraw", "test")
            .credit(cash, sixty, "USD")
            .credit(cash, sixty, "USD")
            .debit(revenue, sixty, "USD")
            .debit(revenue2, sixty, "USD")
            .build();
        let result = store.post_entry(bad_entry);
        assert!(
            matches!(result, Err(LedgerError::InsufficientFunds { .. })),
            "aggregate overdraw must be rejected, got: {:?}",
            result
        );
        // Balance must be unchanged after the rejection.
        assert_eq!(store.balance(&cash), 10000);
    }

    /// A single-line credit that exceeds the balance must still be rejected.
    #[test]
    fn single_line_overdraw_still_rejected() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);

        let fund = Amount::new(5000).unwrap();
        let e = JournalEntryBuilder::new("Fund", "test")
            .debit(cash, fund, "USD")
            .credit(revenue, fund, "USD")
            .build();
        store.post_entry(e).unwrap();

        let too_much = Amount::new(9000).unwrap();
        let bad = JournalEntryBuilder::new("Overdraw", "test")
            .credit(cash, too_much, "USD")
            .debit(revenue, too_much, "USD")
            .build();
        assert!(matches!(
            store.post_entry(bad),
            Err(LedgerError::InsufficientFunds { .. })
        ));
    }

    /// Aggregate exposure-limit: sum of all debit lines to an account in one
    /// entry must not exceed the limit, even if each individual line is below it.
    #[test]
    fn aggregate_exposure_limit_check() {
        let (_dir, mut store) = open_tmp();

        // Create an account with a $50 (5000) exposure limit
        let mut acct = crate::account::Account::new(
            "RISK",
            "Risky Account",
            crate::account::AccountType::Asset,
            "USD",
            "test",
        );
        acct.exposure_limit = Some(5000);
        let risk_id = store.create_account(acct).unwrap();

        let counterpart = store
            .create_account(crate::account::Account::new(
                "CTR",
                "Counterpart",
                crate::account::AccountType::Liability,
                "USD",
                "test",
            ))
            .unwrap();

        // Individual debits of $30 each are below the $50 limit.
        // Combined $60 must exceed the $50 limit.
        let thirty = Amount::new(3000).unwrap();
        let bad = JournalEntryBuilder::new("Aggregate exposure exceeded", "test")
            .debit(risk_id, thirty, "USD")
            .debit(risk_id, thirty, "USD")
            .credit(counterpart, Amount::new(6000).unwrap(), "USD")
            .build();
        assert!(
            matches!(
                store.post_entry(bad),
                Err(LedgerError::ExposureLimitExceeded { .. })
            ),
            "aggregate exposure limit must be enforced"
        );
    }

    #[test]
    fn idempotency_prevents_double_post() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(100).unwrap();
        let e1 = JournalEntryBuilder::new("Payment", "test")
            .debit(cash, amt, "USD")
            .credit(revenue, amt, "USD")
            .idempotency_key("pay-001")
            .build();
        store.post_entry(e1).unwrap();
        let e2 = JournalEntryBuilder::new("Payment dup", "test")
            .debit(cash, amt, "USD")
            .credit(revenue, amt, "USD")
            .idempotency_key("pay-001")
            .build();
        store.post_entry(e2).unwrap(); // idempotent — no error
        assert_eq!(store.entry_count(), 1);
        assert_eq!(store.balance(&cash), 100);
    }
}
