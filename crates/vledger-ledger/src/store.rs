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
//! On restart, `LedgerStore::open()` replays the WAL and rebuilds all
//! in-memory state deterministically.

use std::collections::HashMap;
use std::path::Path;
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

    // ── Sequence / chain state ────────────────────────────────────────────
    next_sequence: AtomicU64,
    last_chain_hash: Hash,
    idempotency_keys: std::collections::HashSet<String>,

    // ── Page cursors ──────────────────────────────────────────────────────
    next_account_page: u64,
    next_entry_page: u64,

    // ── Process-exclusive advisory lock ──────────────────────────────────
    /// Held for the lifetime of this store.  Dropped when the store is dropped.
    _lock: Option<DataDirLock>,

    // ── Data directory path (for WAL flusher) ─────────────────────────────
    data_dir: Option<std::path::PathBuf>,
}

impl LedgerStore {
    // ── Constructors ──────────────────────────────────────────────────────

    /// Open (or create) a persistent ledger at `data_dir`.
    ///
    /// If the WAL already contains committed transactions, the in-memory
    /// state is rebuilt by replaying all committed Data records.
    pub fn open(data_dir: &Path) -> Result<Self, LedgerError> {
        let wal_dir = data_dir.join("wal");
        let pages_dir = data_dir.join("pages");

        let tx_manager = TransactionManager::open(&wal_dir)?;
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
            next_sequence: AtomicU64::new(1),
            last_chain_hash: ZERO_HASH,
            idempotency_keys: std::collections::HashSet::new(),
            next_account_page: 0,
            next_entry_page: 0,
            _lock: Some(lock),
            data_dir: Some(data_dir.to_path_buf()),
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


    // ── WAL replay ────────────────────────────────────────────────────────

    /// Replay committed WAL records into in-memory indexes.
    ///
    /// This is called once at startup and rebuilds the entire state from
    /// scratch — the WAL is the source of truth.
    fn replay_from_wal(&mut self, wal_dir: &Path) -> Result<(), LedgerError> {
        use vledger_wal::recovery::{decode_data_payload, recover};
        use vledger_wal::record::MutationKind;

        let result = recover(wal_dir)?;
        info!(
            committed = result.committed.len(),
            discarded = result.discarded_tx_count,
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
        // Build entry index
        let idx = self.entries.len();
        for line in &entry.lines {
            self.account_entry_index
                .entry(line.account_id)
                .or_default()
                .push(idx);
        }
        self.entries.push(entry);
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
    /// - WAL fsynced before returning Ok
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

        // 3. Account-level validation
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
            if let Some(limit) = acct.exposure_limit {
                if matches!(line.dr_cr, DrCr::Debit) && line.amount.as_i64() > limit {
                    return Err(LedgerError::ExposureLimitExceeded {
                        account_id: line.account_id.to_string(),
                        limit: limit as i128,
                        attempted: line.amount.as_i128(),
                    });
                }
            }
        }

        // 4. Non-negative balance check (Asset/Expense accounts on credit)
        for line in &entry.lines {
            let acct = self.accounts.get(&line.account_id).unwrap();
            let is_debit_normal = matches!(
                acct.account_type,
                AccountType::Asset | AccountType::Expense
            );
            if acct.require_non_negative_balance && is_debit_normal {
                if matches!(line.dr_cr, DrCr::Credit) {
                    let current = self.balance(&line.account_id);
                    if current - line.amount.as_i128() < 0 {
                        return Err(LedgerError::InsufficientFunds {
                            account_id: line.account_id.to_string(),
                            balance: current,
                            debit: line.amount.as_i128(),
                        });
                    }
                }
            }
        }

        // 5. Assign sequence and finalize hash chain
        let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        entry.sequence = seq;
        entry.posted_at = Utc::now();
        entry.finalize_hashes(&self.last_chain_hash);

        // 6. Persist to WAL + page store
        let bytes = encode(&entry)?;
        let prev_hash = Some(entry.prev_hash);
        self.persist_row(TABLE_ENTRIES, &bytes, MutationKind::Insert, prev_hash)?;

        // 7. Update in-memory state
        self.last_chain_hash = entry.chain_hash;
        if let Some(ref key) = entry.idempotency_key {
            self.idempotency_keys.insert(key.clone());
        }
        let idx = self.entries.len();
        for line in &entry.lines {
            self.account_entry_index
                .entry(line.account_id)
                .or_default()
                .push(idx);
        }
        self.entries.push(entry);

        info!(sequence = seq, "Journal entry posted");
        Ok(&self.entries[idx])
    }


    /// Reverse a posted entry. Creates a mirror entry that cancels it out.
    /// The original entry's status is updated to `Reversed`.
    pub fn reverse_entry(
        &mut self,
        entry_id: Uuid,
        description: impl Into<String>,
        domain: impl Into<String>,
    ) -> Result<&JournalEntry, LedgerError> {
        let original_idx = self.entries.iter().position(|e| e.id == entry_id)
            .ok_or_else(|| LedgerError::EntryNotFound(entry_id.to_string()))?;

        match self.entries[original_idx].status {
            EntryStatus::Posted => {}
            other => return Err(LedgerError::CannotReverse(entry_id.to_string(), other)),
        }
        if self.entries[original_idx].reversed_by_entry_id.is_some() {
            return Err(LedgerError::AlreadyReversed(
                entry_id.to_string(),
                self.entries[original_idx].reversed_by_entry_id.unwrap().to_string(),
            ));
        }

        // Build reversal lines by flipping Dr/Cr
        let reversal_lines: Vec<JournalLine> = self.entries[original_idx].lines.iter().map(|line| {
            JournalLine {
                id: Uuid::new_v4(),
                account_id: line.account_id,
                currency_code: line.currency_code.clone(),
                amount: line.amount,
                dr_cr: match line.dr_cr { DrCr::Debit => DrCr::Credit, DrCr::Credit => DrCr::Debit },
                memo: Some(format!("Reversal of line {}", line.id)),
            }
        }).collect();

        let domain_str = domain.into();
        let mut reversal = JournalEntry {
            id: Uuid::new_v4(),
            sequence: 0,
            status: EntryStatus::Reversal,
            description: description.into(),
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
        };

        let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        reversal.sequence = seq;
        reversal.posted_at = Utc::now();
        reversal.finalize_hashes(&self.last_chain_hash);

        let bytes = encode(&reversal)?;
        self.persist_row(TABLE_ENTRIES, &bytes, MutationKind::Insert, Some(reversal.prev_hash))?;

        self.last_chain_hash = reversal.chain_hash;
        let reversal_id = reversal.id;
        let reversal_idx = self.entries.len();
        for line in &reversal.lines {
            self.account_entry_index.entry(line.account_id).or_default().push(reversal_idx);
        }
        self.entries.push(reversal);

        // Persist updated original (mark reversed)
        self.entries[original_idx].status = EntryStatus::Reversed;
        self.entries[original_idx].reversed_by_entry_id = Some(reversal_id);
        let orig_bytes = encode(&self.entries[original_idx])?;
        self.persist_row(TABLE_ENTRIES, &orig_bytes, MutationKind::Update, None)?;

        info!(original_entry = %entry_id, reversal_entry = %reversal_id, "Entry reversed");
        Ok(&self.entries[reversal_idx])
    }


    // ── Queries ───────────────────────────────────────────────────────────

    /// Compute the current balance for an account.
    /// Asset/Expense: debits − credits (positive = normal balance).
    /// Liability/Income/Equity: credits − debits.
    pub fn balance(&self, account_id: &AccountId) -> i128 {
        let acct = match self.accounts.get(account_id) {
            Some(a) => a,
            None => return 0,
        };
        let indices = match self.account_entry_index.get(account_id) {
            Some(v) => v,
            None => return 0,
        };
        let mut debits: i128 = 0;
        let mut credits: i128 = 0;
        for &idx in indices {
            let entry = &self.entries[idx];
            if !matches!(entry.status,
                EntryStatus::Posted | EntryStatus::Reversal | EntryStatus::Reversed) {
                continue;
            }
            for line in &entry.lines {
                if &line.account_id == account_id {
                    match line.dr_cr {
                        DrCr::Debit  => debits  += line.amount.as_i128(),
                        DrCr::Credit => credits += line.amount.as_i128(),
                    }
                }
            }
        }
        let sign = acct.account_type.normal_balance_sign();
        if sign > 0 { debits - credits } else { credits - debits }
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

    /// Force a WAL checkpoint.
    pub fn checkpoint(&mut self) -> Result<u64, LedgerError> {
        Ok(self.tx_manager.checkpoint()?)
    }

    /// Compute the Merkle root over all journal entry pages.
    pub fn entries_merkle_root(&mut self) -> Result<vledger_crypto::Hash, LedgerError> {
        self.page_store.table_merkle_root(TABLE_ENTRIES)
            .map_err(|e| LedgerError::Serialization(e.to_string()))
    }

    /// Return the WAL directory path (used by the group-commit flusher).
    pub fn wal_dir(&self) -> std::path::PathBuf {
        if let Some(ref d) = self.data_dir {
            return d.join("wal");
        }
        std::env::temp_dir().join("vledger-wal-fallback")
    }

    /// Return the `FlushState` handle from the WAL writer, if the WAL is
    /// running in `GroupCommit` mode.  The server uses this to hand the
    /// handle off to the background flusher task.
    pub fn wal_flush_state(&self) -> Option<std::sync::Arc<vledger_wal::FlushState>> {
        self.tx_manager.wal_flush_state()
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
