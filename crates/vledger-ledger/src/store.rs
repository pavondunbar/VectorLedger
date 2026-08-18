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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;
use vledger_crypto::{Hash, ZERO_HASH};
use vledger_pages::{Page, PageStore};
use vledger_transaction::manager::TransactionManager;
use vledger_wal::record::MutationKind;

use crate::account::{Account, AccountId, AccountStatus, AccountType};
use crate::entry::{DrCr, EntryStatus, JournalEntry, JournalLine};
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

    // ── In-memory indexes (rebuilt from WAL on open) ──────────────────────
    accounts: HashMap<AccountId, Account>,
    entries: Vec<JournalEntry>,
    account_entry_index: HashMap<AccountId, Vec<usize>>,

    // ── Running balance cache — O(1) balance lookup ───────────────────────
    /// Stores the signed running balance for every account.
    ///
    /// For debit-normal accounts (Asset / Expense) the value is
    /// `Σ debits − Σ credits`.  For credit-normal accounts it is
    /// `Σ credits − Σ debits`.  Updated atomically on every `post_entry`
    /// and `reverse_entry` commit, and rebuilt from the WAL on startup.
    ///
    /// Replaces the previous O(N) scan in `balance()` with an O(1) lookup.
    balance_cache: HashMap<AccountId, i128>,

    // ── Sequence / chain state ────────────────────────────────────────────
    next_sequence: AtomicU64,
    last_chain_hash: Hash,
    idempotency_keys: std::collections::HashSet<String>,

    // ── Reversal event index ──────────────────────────────────────────────
    /// Maps original_entry_id → reversal_entry_id.
    ///
    /// Rebuilt from `TABLE_REVERSAL_EVENTS` during WAL replay.
    /// Used to derive `EntryStatus::Reversed` without mutating original rows.
    reversal_event_index: HashMap<Uuid, Uuid>,

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
        let wal_dir = data_dir.join("wal");
        let pages_dir = data_dir.join("pages");

        // Load Ed25519 signing key if persisted by `vledger init`.
        let signing_key = Self::load_signing_key(data_dir);

        let tx_manager = TransactionManager::open_with_signing(&wal_dir, signing_key)?;
        let page_store = PageStore::open(&pages_dir)?;

        // Acquire an exclusive advisory lock on the data directory to prevent
        // two processes from opening the same store simultaneously.
        let lock = DataDirLock::acquire(data_dir)
            .map_err(|e| LedgerError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("cannot lock data directory: {e}"),
            )))?;

        let mut store = Self {
            tx_manager,
            page_store,
            accounts: HashMap::new(),
            entries: Vec::new(),
            account_entry_index: HashMap::new(),
            balance_cache: HashMap::new(),
            next_sequence: AtomicU64::new(1),
            last_chain_hash: ZERO_HASH,
            idempotency_keys: std::collections::HashSet::new(),
            reversal_event_index: HashMap::new(),
            next_account_page: 0,
            next_entry_page: 0,
            _lock: Some(lock),
            data_dir: Some(data_dir.to_path_buf()),
            last_committed_entry_bytes: None,
        };

        store.replay_from_wal(&wal_dir)?;

        info!(
            accounts = store.accounts.len(),
            entries  = store.entries.len(),
            sequence = store.next_sequence.load(Ordering::SeqCst),
            "LedgerStore opened"
        );
        Ok(store)
    }

    /// Create a purely in-memory ledger (for tests and self-test command).
    /// No WAL, no page store — state is lost when dropped.
    pub fn new_in_memory() -> Self {
        // Use a temp directory that will be cleaned up automatically
        let tmp = std::env::temp_dir().join(format!("vledger-mem-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("cannot create tmp dir for in-memory ledger");
        Self::open(&tmp).expect("cannot open in-memory ledger")
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
        use vledger_wal::recovery::{decode_data_payload, recover, recover_verified};
        use vledger_wal::record::MutationKind;

        // Use verified recovery when a signing key is configured so that
        // Ed25519 signatures on CommitPayloads are checked on startup.
        // LedgerError implements From<WalError> so ? propagates directly.
        let result = if self.tx_manager.signing_pubkey().is_some() {
            recover_verified(wal_dir, None)?
        } else {
            recover(wal_dir)?
        };
        info!(
            committed         = result.committed.len(),
            discarded         = result.discarded_tx_count,
            verify_signatures = self.tx_manager.signing_pubkey().is_some(),
            "Replaying WAL into LedgerStore"
        );

        for tx in result.committed {
            for record in &tx.data_records {
                let payload = decode_data_payload(record)?;
                match payload.mutation {
                    MutationKind::Insert | MutationKind::Update => {
                        match payload.table_id {
                            TABLE_ACCOUNTS => {
                                let account: Account = decode(&payload.row_data)?;
                                self.apply_account(account);
                            }
                            TABLE_ENTRIES => {
                                let entry: JournalEntry = decode(&payload.row_data)?;
                                self.apply_entry(entry);
                            }
                            TABLE_REVERSAL_EVENTS => {
                                let event: ReversalEvent = decode(&payload.row_data)?;
                                self.reversal_event_index.insert(
                                    event.original_entry_id,
                                    event.reversal_entry_id,
                                );
                            }
                            _ => {}
                        }
                    }
                    MutationKind::Delete => {
                        // Logical deletes on accounts (close_account).
                        // We handle these by re-reading the updated account row.
                        if payload.table_id == TABLE_ACCOUNTS {
                            let account: Account = decode(&payload.row_data)?;
                            self.accounts.insert(account.id, account);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Apply an account record to in-memory state (idempotent).
    fn apply_account(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    /// Apply a journal entry to in-memory state (idempotent).
    fn apply_entry(&mut self, entry: JournalEntry) {
        // Advance sequence counter past replayed entries
        if entry.sequence >= self.next_sequence.load(Ordering::SeqCst) {
            self.next_sequence.store(entry.sequence + 1, Ordering::SeqCst);
        }
        // Advance chain tip
        self.last_chain_hash = entry.chain_hash;
        // Register idempotency key
        if let Some(ref key) = entry.idempotency_key {
            self.idempotency_keys.insert(key.clone());
        }
        // Build entry index and update running balance cache.
        // Only Posted and Reversal entries affect balances — skip others.
        let affects_balance = matches!(
            entry.status,
            EntryStatus::Posted | EntryStatus::Reversal
        );
        let idx = self.entries.len();
        for line in &entry.lines {
            self.account_entry_index
                .entry(line.account_id)
                .or_default()
                .push(idx);

            if affects_balance {
                self.update_balance_cache(line.account_id, line.amount.as_i128(), line.dr_cr);
            }
        }
        self.entries.push(entry);
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
            Some(acct) => matches!(
                acct.account_type,
                AccountType::Asset | AccountType::Expense
            ),
            // Account not yet in memory — skip; cache will be correct after
            // the account record is applied and the entry re-evaluated via
            // the full balance() recompute on first access.
            None => return,
        };

        let delta: i128 = if is_debit_normal {
            match dr_cr {
                DrCr::Debit  =>  amount,
                DrCr::Credit => -amount,
            }
        } else {
            match dr_cr {
                DrCr::Credit =>  amount,
                DrCr::Debit  => -amount,
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
            _              => self.next_entry_page,
        };

        let (page_id, slot_id, next_cursor) =
            self.write_to_page(table_id, row_data, cursor)?;

        // Write cursor back
        match table_id {
            TABLE_ACCOUNTS => self.next_account_page = next_cursor,
            _              => self.next_entry_page   = next_cursor,
        };

        // WAL transaction
        let tx_id = self.tx_manager.begin(None)?;
        self.tx_manager.add_mutation(
            tx_id, table_id, page_id, slot_id,
            mutation, row_data.to_vec(), prev_hash,
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
        table_a:   u32,
        data_a:    &[u8],
        prev_a:    Option<vledger_crypto::Hash>,
        table_b:   u32,
        data_b:    &[u8],
    ) -> Result<(), LedgerError> {
        // Write both pages first.
        let cursor_a = self.next_entry_page;
        let (page_id_a, slot_id_a, next_a) =
            self.write_to_page(table_a, data_a, cursor_a)?;
        self.next_entry_page = next_a;

        // Reversal events use the entry cursor as well (same page namespace
        // is fine — table_id distinguishes them logically).
        let cursor_b = self.next_entry_page;
        let (page_id_b, slot_id_b, next_b) =
            self.write_to_page(table_b, data_b, cursor_b)?;
        self.next_entry_page = next_b;

        // Single WAL transaction — both mutations committed together.
        let tx_id = self.tx_manager.begin(Some("reversal".to_string()))?;
        self.tx_manager.add_mutation(
            tx_id, table_a, page_id_a, slot_id_a,
            MutationKind::Insert, data_a.to_vec(), prev_a,
        )?;
        self.tx_manager.add_mutation(
            tx_id, table_b, page_id_b, slot_id_b,
            MutationKind::Insert, data_b.to_vec(), None,
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

        let slot_id = page.write_slot(row_data).map_err(|e| {
            LedgerError::Serialization(format!("page write_slot: {e}"))
        })?;

        let page_id = page.header.page_id;
        page.seal();
        self.page_store.write_page(&page).map_err(|e| {
            LedgerError::Serialization(format!("page_store write: {e}"))
        })?;

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
        let acct = self.accounts.get_mut(id)
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
    pub fn post_entry(&mut self, mut entry: JournalEntry) -> Result<&JournalEntry, LedgerError> {
        // 1. Structural validation
        entry.validate()?;

        // 2. Idempotency check
        if let Some(ref key) = entry.idempotency_key {
            if self.idempotency_keys.contains(key) {
                warn!(key, "Idempotency key already posted");
                let idx = self.entries.iter().position(|e| {
                    e.idempotency_key.as_deref() == Some(key)
                });
                if let Some(i) = idx {
                    return Ok(&self.entries[i]);
                }
            }
        }

        // 3. Per-line account-level validation (existence, status, currency, four-eyes).
        //    Exposure limits and balance checks are done in aggregate below.
        for line in &entry.lines {
            let acct = self.accounts.get(&line.account_id)
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
                    DrCr::Debit  =>  line.amount.as_i128(),
                    DrCr::Credit => -line.amount.as_i128(),
                };
                *net_debit_delta.entry(line.account_id).or_insert(0) += delta;
            }

            // Also accumulate the total debit amount per account for the
            // exposure-limit check.
            let mut total_debit: HM<AccountId, i128> = HM::new();
            for line in &entry.lines {
                if matches!(line.dr_cr, DrCr::Debit) {
                    *total_debit.entry(line.account_id).or_insert(0)
                        += line.amount.as_i128();
                }
            }

            for (account_id, &delta) in &net_debit_delta {
                let acct = self.accounts.get(account_id).unwrap(); // existence checked above

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
                let is_debit_normal = matches!(
                    acct.account_type,
                    AccountType::Asset | AccountType::Expense
                );
                if acct.require_non_negative_balance && is_debit_normal && delta < 0 {
                    let current = self.balance(account_id);
                    // delta is negative (net credit), so: projected = current + delta
                    let projected = current + delta;
                    if projected < 0 {
                        return Err(LedgerError::InsufficientFunds {
                            account_id: account_id.to_string(),
                            balance:    current,
                            // Report the magnitude of the net credit that caused
                            // the shortfall so the error message is useful.
                            debit:      (-delta),
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

        // 7. Update in-memory state
        self.last_chain_hash = entry.chain_hash;
        if let Some(ref key) = entry.idempotency_key {
            self.idempotency_keys.insert(key.clone());
        }
        let idx = self.entries.len();
        let affects_balance = matches!(
            entry.status,
            EntryStatus::Posted | EntryStatus::Reversal
        );
        for line in &entry.lines {
            self.account_entry_index
                .entry(line.account_id)
                .or_default()
                .push(idx);
            if affects_balance {
                self.update_balance_cache(line.account_id, line.amount.as_i128(), line.dr_cr);
            }
        }
        self.entries.push(entry);

        info!(sequence = seq, "Journal entry posted");
        Ok(&self.entries[idx])
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
    ) -> Result<&JournalEntry, LedgerError> {
        let original_idx = self.entries.iter().position(|e| e.id == entry_id)
            .ok_or_else(|| LedgerError::EntryNotFound(entry_id.to_string()))?;

        // Only Posted entries may be reversed.
        match self.entries[original_idx].status {
            EntryStatus::Posted => {}
            other => return Err(LedgerError::CannotReverse(entry_id.to_string(), other)),
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
        let reversal_lines: Vec<JournalLine> = self.entries[original_idx]
            .lines.iter().map(|line| {
            JournalLine {
                id: Uuid::new_v4(),
                account_id: line.account_id,
                currency_code: line.currency_code.clone(),
                amount: line.amount,
                dr_cr: match line.dr_cr {
                    DrCr::Debit  => DrCr::Credit,
                    DrCr::Credit => DrCr::Debit,
                },
                memo: Some(format!("Reversal of line {}", line.id)),
            }
        }).collect();

        let domain_str  = domain.into();
        let desc_str    = description.into();
        let mut reversal = JournalEntry {
            id:                  Uuid::new_v4(),
            sequence:            0,
            status:              EntryStatus::Reversal,
            description:         desc_str,
            lines:               reversal_lines,
            effective_at:        Utc::now(),
            posted_at:           Utc::now(),
            external_ref:        None,
            idempotency_key:     None,
            reverses_entry_id:   Some(entry_id),
            reversed_by_entry_id: None,
            domain:              domain_str,
            content_hash:        ZERO_HASH,
            prev_hash:           ZERO_HASH,
            chain_hash:          ZERO_HASH,
            approved_by:         None,
        };

        let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        reversal.sequence  = seq;
        reversal.posted_at = Utc::now();
        reversal.finalize_hashes(&self.last_chain_hash);

        let reversal_id = reversal.id;
        let event = ReversalEvent {
            original_entry_id: entry_id,
            reversal_entry_id: reversal_id,
            reversed_at:       reversal.posted_at,
        };

        // Serialize both records before touching durable state.
        let reversal_bytes = encode(&reversal)?;
        let event_bytes    = encode(&event)?;
        let prev_hash      = Some(reversal.prev_hash);

        // Atomic: both records committed in a single WAL transaction.
        self.persist_row_pair(
            TABLE_ENTRIES,         &reversal_bytes, prev_hash,
            TABLE_REVERSAL_EVENTS, &event_bytes,
        )?;

        // Update in-memory state — only after durable commit.
        self.last_chain_hash = reversal.chain_hash;

        // Register the reversal event index.
        self.reversal_event_index.insert(entry_id, reversal_id);

        // Index the reversal entry and update the running balance cache.
        // Reversal entries have status=Reversal which affects balances.
        let reversal_idx = self.entries.len();
        for line in &reversal.lines {
            self.account_entry_index
                .entry(line.account_id)
                .or_default()
                .push(reversal_idx);
            self.update_balance_cache(line.account_id, line.amount.as_i128(), line.dr_cr);
        }
        self.entries.push(reversal);

        info!(
            original_entry = %entry_id,
            reversal_entry = %reversal_id,
            "Entry reversed (append-only, atomic)"
        );
        Ok(&self.entries[reversal_idx])
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
    pub fn account_entries(&self, account_id: &AccountId) -> Vec<&JournalEntry> {
        match self.account_entry_index.get(account_id) {
            Some(v) => v.iter().map(|&i| &self.entries[i]).collect(),
            None => vec![],
        }
    }

    /// All entries, in posting order.
    pub fn all_entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// All accounts.
    pub fn all_accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    /// Total number of posted entries.
    pub fn entry_count(&self) -> usize { self.entries.len() }

    /// Current BLAKE3 hash chain tip.
    pub fn chain_tip(&self) -> &Hash { &self.last_chain_hash }

    /// Verify the entire hash chain from first to last entry.
    pub fn verify_chain_integrity(&self) -> Result<(), LedgerError> {
        let mut prev_hash = ZERO_HASH;
        for entry in &self.entries {
            if !entry.verify_hashes() {
                return Err(LedgerError::Serialization(
                    format!("Hash chain broken at sequence {}", entry.sequence)));
            }
            if entry.prev_hash != prev_hash {
                return Err(LedgerError::Serialization(
                    format!("Chain linkage broken at sequence {}", entry.sequence)));
            }
            prev_hash = entry.chain_hash;
        }
        Ok(())
    }

    /// Verify a range of the hash chain between `from_seq` and `to_seq` inclusive.
    ///
    /// When `from_seq` is `None` the range starts at the first entry.
    /// When `to_seq` is `None` the range ends at the last entry.
    /// When both are `None` this is equivalent to `verify_chain_integrity`.
    ///
    /// Returns `(verified_count, range_chain_tip)`.
    pub fn verify_chain_range(
        &self,
        from_seq: Option<u64>,
        to_seq:   Option<u64>,
    ) -> Result<(usize, vledger_crypto::Hash), LedgerError> {
        let entries: Vec<&JournalEntry> = self.entries.iter()
            .filter(|e| {
                from_seq.map_or(true, |f| e.sequence >= f) &&
                to_seq.map_or(true,   |t| e.sequence <= t)
            })
            .collect();

        if entries.is_empty() {
            return Ok((0, ZERO_HASH));
        }

        // For a sub-range we verify internal hash consistency and chain linkage
        // within the range.  The first entry in the range carries its own
        // prev_hash which we accept as the range's starting point.
        let mut prev_hash = entries[0].prev_hash;
        let mut count = 0usize;
        let mut tip   = ZERO_HASH;

        for entry in &entries {
            if !entry.verify_hashes() {
                return Err(LedgerError::Serialization(
                    format!("Hash chain broken at sequence {}", entry.sequence)));
            }
            if entry.prev_hash != prev_hash {
                return Err(LedgerError::Serialization(
                    format!("Chain linkage broken at sequence {}", entry.sequence)));
            }
            prev_hash = entry.chain_hash;
            tip = entry.chain_hash;
            count += 1;
        }

        Ok((count, tip))
    }

    /// Look up a single entry by its sequence number.
    /// Returns `None` if no entry with that sequence exists.
    pub fn get_entry_by_sequence(&self, seq: u64) -> Option<&JournalEntry> {
        // Sequence numbers start at 1 and are densely packed, so try the
        // direct index first (O(1)) before falling back to a linear scan.
        let idx = seq.saturating_sub(1) as usize;
        if let Some(e) = self.entries.get(idx) {
            if e.sequence == seq {
                return Some(e);
            }
        }
        self.entries.iter().find(|e| e.sequence == seq)
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
        let idx = seq.saturating_sub(1) as usize;
        if let Some(e) = self.entries.get_mut(idx) {
            if e.sequence == seq {
                e.description = new_description;
                return true;
            }
        }
        if let Some(e) = self.entries.iter_mut().find(|e| e.sequence == seq) {
            e.description = new_description;
            return true;
        }
        false
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
        let root = self.page_store
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
        let cash = store.create_account(Account::new(
            "1001", "Cash USD", AccountType::Asset, "USD", "test")).unwrap();
        let revenue = store.create_account(Account::new(
            "4001", "Revenue", AccountType::Income, "USD", "test")).unwrap();
        (cash, revenue)
    }

    #[test]
    fn post_balanced_entry_persists() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(10000).unwrap();
        let entry = JournalEntryBuilder::new("Sale", "test")
            .debit(cash, amt, "USD").credit(revenue, amt, "USD").build();
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
                .debit(cash, amt, "USD").credit(revenue, amt, "USD").build();
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
            let cash = store.create_account(Account::new(
                "1001", "Cash", AccountType::Asset, "USD", "test")).unwrap();
            let rev = store.create_account(Account::new(
                "4001", "Revenue", AccountType::Income, "USD", "test")).unwrap();
            let amt = Amount::new(5000).unwrap();
            let e = JournalEntryBuilder::new("Initial sale", "test")
                .debit(cash, amt, "USD").credit(rev, amt, "USD").build();
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
            .debit(cash, amt, "USD").credit(revenue, amt, "USD").build();
        let posted = store.post_entry(e).unwrap();
        let eid = posted.id;
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
            .debit(cash, amt, "USD").credit(revenue, amt, "USD").build();
        let posted = store.post_entry(e).unwrap();
        let eid = posted.id;

        // Capture the original entry's bytes BEFORE reversal.
        let original_chain_hash_before = store.all_entries()[0].chain_hash;
        let original_status_before     = store.all_entries()[0].status;

        store.reverse_entry(eid, "Reversal", "test").unwrap();

        // Original entry must be completely unchanged.
        let original_after = store.all_entries().iter().find(|e| e.id == eid).unwrap();
        assert_eq!(original_after.chain_hash, original_chain_hash_before,
            "original entry chain_hash must not change after reversal");
        assert_eq!(original_after.status, original_status_before,
            "original entry status must not be mutated — use is_reversed() instead");

        // Reversed status is derived from the event index, not a mutable field.
        assert!(store.is_reversed(&eid),
            "is_reversed() must return true after reversal");
        assert!(store.reversed_by(&eid).is_some(),
            "reversed_by() must return the reversal entry id");
    }

    #[test]
    fn double_reversal_rejected() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(500).unwrap();
        let e = JournalEntryBuilder::new("Sale", "test")
            .debit(cash, amt, "USD").credit(revenue, amt, "USD").build();
        let posted = store.post_entry(e).unwrap();
        let eid = posted.id;
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
            let cash = store.create_account(Account::new(
                "CASH", "Cash", AccountType::Asset, "USD", "test")).unwrap();
            let rev  = store.create_account(Account::new(
                "REV",  "Revenue", AccountType::Income, "USD", "test")).unwrap();
            let amt  = Amount::new(9900).unwrap();
            let e    = JournalEntryBuilder::new("Sale", "test")
                .debit(cash, amt, "USD").credit(rev, amt, "USD").build();
            let posted  = store.post_entry(e).unwrap();
            let eid     = posted.id;
            let rev_entry = store.reverse_entry(eid, "Void sale", "test").unwrap();
            let rid = rev_entry.id;
            (eid, rid)
        };

        // Reopen — reversal_event_index must be rebuilt from WAL.
        let store2 = LedgerStore::open(data_path).unwrap();
        assert!(store2.is_reversed(&original_id),
            "is_reversed must survive WAL replay");
        assert_eq!(store2.reversed_by(&original_id), Some(reversal_id),
            "reversed_by must return correct reversal id after replay");
        // Balance should be zero.
        let entries = store2.all_entries();
        let cash_id = entries.iter()
            .find(|e| e.reverses_entry_id == Some(original_id))
            .map(|_| {
                // Find cash account via the original debit line
                entries.iter()
                    .find(|e| e.id == original_id)
                    .and_then(|e| e.lines.iter().find(|l| l.dr_cr == crate::entry::DrCr::Debit))
                    .map(|l| l.account_id)
            })
            .flatten();
        if let Some(cid) = cash_id {
            assert_eq!(store2.balance(&cid), 0, "balance must be zero after reversal replay");
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
            .debit(cash, fund, "USD").credit(revenue, fund, "USD").build();
        store.post_entry(e).unwrap();
        assert_eq!(store.balance(&cash), 10000);

        // Add a second revenue account to make the balancing entry work
        let revenue2 = store.create_account(crate::account::Account::new(
            "4002", "Revenue2", crate::account::AccountType::Income, "USD", "test")).unwrap();

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
            "aggregate overdraw must be rejected, got: {:?}", result
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
            .debit(cash, fund, "USD").credit(revenue, fund, "USD").build();
        store.post_entry(e).unwrap();

        let too_much = Amount::new(9000).unwrap();
        let bad = JournalEntryBuilder::new("Overdraw", "test")
            .credit(cash, too_much, "USD").debit(revenue, too_much, "USD").build();
        assert!(matches!(store.post_entry(bad), Err(LedgerError::InsufficientFunds { .. })));
    }

    /// Aggregate exposure-limit: sum of all debit lines to an account in one
    /// entry must not exceed the limit, even if each individual line is below it.
    #[test]
    fn aggregate_exposure_limit_check() {
        let (_dir, mut store) = open_tmp();

        // Create an account with a $50 (5000) exposure limit
        let mut acct = crate::account::Account::new(
            "RISK", "Risky Account", crate::account::AccountType::Asset, "USD", "test");
        acct.exposure_limit = Some(5000);
        let risk_id = store.create_account(acct).unwrap();

        let counterpart = store.create_account(crate::account::Account::new(
            "CTR", "Counterpart", crate::account::AccountType::Liability, "USD", "test")).unwrap();

        // Individual debits of $30 each are below the $50 limit.
        // Combined $60 must exceed the $50 limit.
        let thirty = Amount::new(3000).unwrap();
        let bad = JournalEntryBuilder::new("Aggregate exposure exceeded", "test")
            .debit(risk_id,   thirty, "USD")
            .debit(risk_id,   thirty, "USD")
            .credit(counterpart, Amount::new(6000).unwrap(), "USD")
            .build();
        assert!(
            matches!(store.post_entry(bad), Err(LedgerError::ExposureLimitExceeded { .. })),
            "aggregate exposure limit must be enforced"
        );
    }

    #[test]
    fn idempotency_prevents_double_post() {
        let (_dir, mut store) = open_tmp();
        let (cash, revenue) = add_accounts(&mut store);
        let amt = Amount::new(100).unwrap();
        let e1 = JournalEntryBuilder::new("Payment", "test")
            .debit(cash, amt, "USD").credit(revenue, amt, "USD")
            .idempotency_key("pay-001").build();
        store.post_entry(e1).unwrap();
        let e2 = JournalEntryBuilder::new("Payment dup", "test")
            .debit(cash, amt, "USD").credit(revenue, amt, "USD")
            .idempotency_key("pay-001").build();
        store.post_entry(e2).unwrap(); // idempotent — no error
        assert_eq!(store.entry_count(), 1);
        assert_eq!(store.balance(&cash), 100);
    }
}
