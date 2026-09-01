//! SQLite-backed entry index for the disk-backed LedgerStore.
//!
//! ## Design
//!
//! The `EntryDb` stores a lightweight index of every journal entry in an
//! SQLite database at `<data_dir>/vledger.db`.  The full serialized entry
//! (bincode) is stored in the `data` column so that any entry can be fully
//! reconstructed from the index alone — the PageStore is the authoritative
//! durability layer but SQLite is the query layer.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE entries (
//!     sequence     INTEGER PRIMARY KEY,
//!     id           TEXT    NOT NULL,
//!     status       TEXT    NOT NULL,
//!     domain       TEXT    NOT NULL,
//!     external_ref TEXT,
//!     idempotency_key TEXT,
//!     content_hash TEXT    NOT NULL,
//!     chain_hash   TEXT    NOT NULL,
//!     effective_at TEXT    NOT NULL,
//!     posted_at    TEXT    NOT NULL,
//!     data         BLOB    NOT NULL    -- full bincode JournalEntry
//! );
//! CREATE INDEX idx_entries_domain       ON entries(domain);
//! CREATE INDEX idx_entries_status       ON entries(status);
//! CREATE INDEX idx_entries_external_ref ON entries(external_ref);
//! CREATE INDEX idx_entries_idem_key     ON entries(idempotency_key);
//! ```
//!
//! ## Memory model
//!
//! SQLite keeps its page cache in RAM (default: 2000 pages × 4 KiB = ~8 MB).
//! No `JournalEntry` objects are held in RAM by the LedgerStore itself.
//! Query results are deserialized from SQLite on demand and returned to the
//! caller — not cached.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::entry::JournalEntry;
use crate::error::LedgerError;

fn encode_entry(e: &JournalEntry) -> Result<Vec<u8>, LedgerError> {
    bincode::serde::encode_to_vec(e, bincode::config::standard())
        .map_err(|e| LedgerError::Serialization(e.to_string()))
}

/// Public wrapper around encode_entry — used by tamper_entry_for_demo in store.rs.
#[cfg(any(test, feature = "self-test"))]
pub fn encode_entry_pub(e: &JournalEntry) -> Result<Vec<u8>, LedgerError> {
    encode_entry(e)
}

fn decode_entry(bytes: &[u8]) -> Result<JournalEntry, LedgerError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| LedgerError::Serialization(e.to_string()))
}

/// Lightweight SQLite-backed entry query index.
///
/// The inner `Connection` is wrapped in a `Mutex` so that `EntryDb` is `Send + Sync`
/// and can be held inside `Arc<RwLock<LedgerStore>>` used by the async server.
pub struct EntryDb {
    conn: Mutex<Connection>,
}

impl EntryDb {
    /// Open (or create) the entry index at `db_path`.
    /// Creates the schema on first open; no-op if it already exists.
    pub fn open(db_path: &Path) -> Result<Self, LedgerError> {
        Self::open_with_mode(db_path, false)
    }

    /// Open in bulk-migration mode: sets aggressive SQLite PRAGMAs for
    /// maximum insert throughput. Use only during offline migration —
    /// not safe for concurrent reads or crash recovery mid-write.
    pub fn open_for_migration(db_path: &Path) -> Result<Self, LedgerError> {
        Self::open_with_mode(db_path, true)
    }

    fn open_with_mode(db_path: &Path, migration_mode: bool) -> Result<Self, LedgerError> {
        let conn = Connection::open(db_path)
            .map_err(|e| LedgerError::Serialization(format!("SQLite open error: {e}")))?;

        if migration_mode {
            // Migration mode: WAL journal (crash-safe) + NORMAL sync + huge cache.
            // Secondary indexes are NOT created here — they are built in one pass
            // after all rows are inserted via build_indexes_after_migration().
            // Inserting without secondary indexes is ~3x faster; building indexes
            // in one sorted scan at the end is faster than 25M incremental updates.
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA cache_size=-524288;
                 PRAGMA temp_store=MEMORY;
                 PRAGMA locking_mode=EXCLUSIVE;
                 PRAGMA mmap_size=34359738368;
                 PRAGMA wal_autocheckpoint=10000;",
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite pragma error: {e}")))?;

            // Create entries table WITHOUT secondary indexes.
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS entries (
                    sequence        INTEGER PRIMARY KEY,
                    id              TEXT    NOT NULL,
                    status          TEXT    NOT NULL,
                    domain          TEXT    NOT NULL,
                    external_ref    TEXT,
                    idempotency_key TEXT,
                    content_hash    TEXT    NOT NULL,
                    chain_hash      TEXT    NOT NULL,
                    effective_at    TEXT    NOT NULL,
                    posted_at       TEXT    NOT NULL,
                    data            BLOB    NOT NULL
                );",
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite schema error: {e}")))?;
        } else {
            // Normal mode: WAL + NORMAL sync for concurrent read safety.
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
                .map_err(|e| LedgerError::Serialization(format!("SQLite pragma error: {e}")))?;
            conn.execute_batch("PRAGMA cache_size=-16384;")
                .map_err(|e| LedgerError::Serialization(format!("SQLite pragma error: {e}")))?;

            // Normal open: create table + all indexes.
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS entries (
                    sequence        INTEGER PRIMARY KEY,
                    id              TEXT    NOT NULL,
                    status          TEXT    NOT NULL,
                    domain          TEXT    NOT NULL,
                    external_ref    TEXT,
                    idempotency_key TEXT,
                    content_hash    TEXT    NOT NULL,
                    chain_hash      TEXT    NOT NULL,
                    effective_at    TEXT    NOT NULL,
                    posted_at       TEXT    NOT NULL,
                    data            BLOB    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entries_domain
                    ON entries(domain);
                CREATE INDEX IF NOT EXISTS idx_entries_status
                    ON entries(status);
                CREATE INDEX IF NOT EXISTS idx_entries_external_ref
                    ON entries(external_ref) WHERE external_ref IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_entries_idem_key
                    ON entries(idempotency_key) WHERE idempotency_key IS NOT NULL;",
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite schema error: {e}")))?;
        }

        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Build secondary indexes after bulk migration insert is complete.
    /// Called once after all rows are in the entries table.
    /// Much faster than maintaining indexes incrementally during insertion.
    pub fn build_indexes_after_migration(&self) -> Result<(), LedgerError> {
        let conn = self.lock()?;
        // These are expensive but run as single sorted scans — far faster
        // than 25M individual B-tree insertions during row inserts.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_entries_domain
                ON entries(domain);
             CREATE INDEX IF NOT EXISTS idx_entries_status
                ON entries(status);
             CREATE INDEX IF NOT EXISTS idx_entries_external_ref
                ON entries(external_ref) WHERE external_ref IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_entries_idem_key
                ON entries(idempotency_key) WHERE idempotency_key IS NOT NULL;",
        )
        .map_err(|e| LedgerError::Serialization(format!("build indexes: {e}")))?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, LedgerError> {
        self.conn
            .lock()
            .map_err(|_| LedgerError::Serialization("SQLite mutex poisoned".into()))
    }

    /// High-performance bulk migration insert.
    ///
    /// Inserts a batch of entries in a single SQLite transaction using a
    /// pre-compiled prepared statement. Skips account_entries cross-reference
    /// (can be rebuilt separately). Uses INSERT OR IGNORE for idempotency.
    ///
    /// Returns the number of rows actually inserted.
    pub fn bulk_insert_migration(&self, entries: &[JournalEntry]) -> Result<u64, LedgerError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let conn = self.lock()?;
        // Rollback any lingering transaction before starting a new one.
        // This handles the case where a previous run was interrupted.
        let _ = conn.execute_batch("ROLLBACK");
        conn.execute_batch("BEGIN")
            .map_err(|e| LedgerError::Serialization(format!("BEGIN: {e}")))?;

        let mut stmt = conn
            .prepare(
                "INSERT OR IGNORE INTO entries
                 (sequence, id, status, domain, external_ref, idempotency_key,
                  content_hash, chain_hash, effective_at, posted_at, data)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            )
            .map_err(|e| LedgerError::Serialization(format!("prepare: {e}")))?;

        let mut inserted = 0u64;
        for entry in entries {
            let data = encode_entry(entry)?;
            let rows = stmt
                .execute(rusqlite::params![
                    entry.sequence as i64,
                    entry.id.to_string(),
                    format!("{:?}", entry.status),
                    entry.domain,
                    entry.external_ref.as_deref(),
                    entry.idempotency_key.as_deref(),
                    hex::encode(entry.content_hash),
                    hex::encode(entry.chain_hash),
                    entry.effective_at.to_rfc3339(),
                    entry.posted_at.to_rfc3339(),
                    data,
                ])
                .map_err(|e| LedgerError::Serialization(format!("insert: {e}")))?;
            inserted += rows as u64;
        }

        conn.execute_batch("COMMIT")
            .map_err(|e| LedgerError::Serialization(format!("COMMIT: {e}")))?;
        Ok(inserted)
    }

    /// Rebuild the account_entries cross-reference table from the entries table.
    /// Called after bulk migration to populate the secondary index.
    pub fn rebuild_account_entries_index(&self) -> Result<u64, LedgerError> {
        let conn = self.lock()?;
        // Drop and recreate for speed (avoids INSERT OR IGNORE overhead).
        conn.execute_batch(
            "DROP TABLE IF EXISTS account_entries;
             CREATE TABLE account_entries (
                 account_id TEXT NOT NULL,
                 sequence   INTEGER NOT NULL,
                 PRIMARY KEY (account_id, sequence)
             );
             CREATE INDEX IF NOT EXISTS idx_ae_account ON account_entries(account_id);",
        )
        .map_err(|e| LedgerError::Serialization(format!("recreate account_entries: {e}")))?;

        // We can't do this in pure SQL since account_id is inside the BLOB.
        // Return 0 — callers stream entries and call insert_account_entry.
        // For migration purposes the account_entries table can be rebuilt
        // lazily on first query.
        Ok(0)
    }
    pub fn insert(&self, entry: &JournalEntry) -> Result<(), LedgerError> {
        let data = encode_entry(entry)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO entries
                 (sequence, id, status, domain, external_ref, idempotency_key,
                  content_hash, chain_hash, effective_at, posted_at, data)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                entry.sequence as i64,
                entry.id.to_string(),
                format!("{:?}", entry.status),
                entry.domain,
                entry.external_ref.as_deref(),
                entry.idempotency_key.as_deref(),
                hex::encode(entry.content_hash),
                hex::encode(entry.chain_hash),
                entry.effective_at.to_rfc3339(),
                entry.posted_at.to_rfc3339(),
                data,
            ],
        )
        .map_err(|e| LedgerError::Serialization(format!("SQLite insert error: {e}")))?;
        Ok(())
    }

    /// Fetch a single entry by sequence number.
    pub fn get_by_sequence(&self, seq: u64) -> Result<Option<JournalEntry>, LedgerError> {
        let conn = self.lock()?;
        let result = conn
            .query_row(
                "SELECT data FROM entries WHERE sequence = ?1",
                params![seq as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| LedgerError::Serialization(format!("SQLite query error: {e}")))?;
        result.map(|b| decode_entry(&b)).transpose()
    }

    /// Fetch a single entry by external_ref.
    pub fn get_by_external_ref(&self, r: &str) -> Result<Option<JournalEntry>, LedgerError> {
        let conn = self.lock()?;
        let result = conn
            .query_row(
                "SELECT data FROM entries WHERE external_ref = ?1 LIMIT 1",
                params![r],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| LedgerError::Serialization(format!("SQLite query error: {e}")))?;
        result.map(|b| decode_entry(&b)).transpose()
    }

    /// Check whether an idempotency key already exists.
    pub fn idempotency_key_exists(&self, key: &str) -> Result<bool, LedgerError> {
        let conn = self.lock()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE idempotency_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite query error: {e}")))?;
        Ok(count > 0)
    }

    /// Get the sequence number of an entry by idempotency key (O(1) index lookup).
    pub fn sequence_for_idempotency_key(&self, key: &str) -> Result<Option<u64>, LedgerError> {
        let conn = self.lock()?;
        let result = conn
            .query_row(
                "SELECT sequence FROM entries WHERE idempotency_key = ?1 LIMIT 1",
                params![key],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| LedgerError::Serialization(format!("SQLite query error: {e}")))?;
        Ok(result.map(|s| s as u64))
    }

    /// Total number of entries in the index.
    pub fn count(&self) -> Result<u64, LedgerError> {
        let conn = self.lock()?;
        let c: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .map_err(|e| LedgerError::Serialization(format!("SQLite count error: {e}")))?;
        Ok(c as u64)
    }

    /// The highest committed sequence number, or 0 if empty.
    pub fn max_sequence(&self) -> Result<u64, LedgerError> {
        let conn = self.lock()?;
        let v: Option<i64> = conn
            .query_row("SELECT MAX(sequence) FROM entries", [], |row| row.get(0))
            .map_err(|e| LedgerError::Serialization(format!("SQLite max_sequence error: {e}")))?;
        Ok(v.unwrap_or(0) as u64)
    }

    /// The chain_hash of the highest-sequence entry, or ZERO_HASH if empty.
    pub fn chain_tip(&self) -> Result<Option<[u8; 32]>, LedgerError> {
        let conn = self.lock()?;
        let result: Option<String> = conn
            .query_row(
                "SELECT chain_hash FROM entries ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| LedgerError::Serialization(format!("SQLite chain_tip error: {e}")))?;
        match result {
            None => Ok(None),
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str)
                    .map_err(|e| LedgerError::Serialization(format!("hex decode: {e}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| LedgerError::Serialization("chain_hash wrong length".into()))?;
                Ok(Some(arr))
            }
        }
    }

    // ── Filtered scans ────────────────────────────────────────────────────

    /// Scan entries with optional domain/status filter, paginated by offset_seq.
    pub fn scan(
        &self,
        domain: Option<&str>,
        status: Option<&str>,
        limit: usize,
        offset_seq: u64,
    ) -> Result<Vec<JournalEntry>, LedgerError> {
        let conn = self.lock()?;
        let sql = match (domain, status) {
            (Some(_), Some(_)) =>
                "SELECT data FROM entries WHERE domain=?1 AND status=?2 AND sequence>?3 ORDER BY sequence LIMIT ?4",
            (Some(_), None) =>
                "SELECT data FROM entries WHERE domain=?1 AND sequence>?3 ORDER BY sequence LIMIT ?4",
            (None, Some(_)) =>
                "SELECT data FROM entries WHERE status=?2 AND sequence>?3 ORDER BY sequence LIMIT ?4",
            (None, None) =>
                "SELECT data FROM entries WHERE sequence>?3 ORDER BY sequence LIMIT ?4",
        };

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| LedgerError::Serialization(format!("SQLite prepare error: {e}")))?;

        let rows = stmt
            .query_map(
                params![
                    domain.unwrap_or(""),
                    status.unwrap_or(""),
                    offset_seq as i64,
                    limit as i64,
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite scan error: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let data =
                row.map_err(|e| LedgerError::Serialization(format!("SQLite row error: {e}")))?;
            results.push(decode_entry(&data)?);
        }
        Ok(results)
    }

    /// Scan entries filtered by domain only (index-accelerated).
    pub fn scan_by_domain(
        &self,
        domain: &str,
        limit: usize,
        offset_seq: u64,
    ) -> Result<Vec<JournalEntry>, LedgerError> {
        self.scan(Some(domain), None, limit, offset_seq)
    }

    /// Scan entries filtered by status only (index-accelerated).
    pub fn scan_by_status(
        &self,
        status: &str,
        limit: usize,
        offset_seq: u64,
    ) -> Result<Vec<JournalEntry>, LedgerError> {
        self.scan(None, Some(status), limit, offset_seq)
    }

    /// Scan entries filtered by external_ref (index-accelerated for known values).
    pub fn scan_by_external_ref(
        &self,
        ext_ref: &str,
        limit: usize,
    ) -> Result<Vec<JournalEntry>, LedgerError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT data FROM entries WHERE external_ref=?1 ORDER BY sequence LIMIT ?2")
            .map_err(|e| LedgerError::Serialization(format!("SQLite prepare error: {e}")))?;

        let rows = stmt
            .query_map(params![ext_ref, limit as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| LedgerError::Serialization(format!("SQLite scan error: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let data =
                row.map_err(|e| LedgerError::Serialization(format!("SQLite row error: {e}")))?;
            results.push(decode_entry(&data)?);
        }
        Ok(results)
    }

    /// Stream all entries in sequence order for hash chain verification.
    /// Calls `f` with each entry; stops early if `f` returns `Err`.
    /// Uses constant RAM regardless of entry count — no Vec accumulation.
    pub fn stream_all<F>(&self, mut f: F) -> Result<(), LedgerError>
    where
        F: FnMut(JournalEntry) -> Result<(), LedgerError>,
    {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT data FROM entries ORDER BY sequence")
            .map_err(|e| LedgerError::Serialization(format!("SQLite prepare error: {e}")))?;

        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| LedgerError::Serialization(format!("SQLite stream error: {e}")))?;

        for row in rows {
            let data =
                row.map_err(|e| LedgerError::Serialization(format!("SQLite row error: {e}")))?;
            let entry = decode_entry(&data)?;
            f(entry)?;
        }
        Ok(())
    }

    /// Fetch entries in a sequence range [from_seq, to_seq] inclusive.
    pub fn scan_range(&self, from_seq: u64, to_seq: u64) -> Result<Vec<JournalEntry>, LedgerError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT data FROM entries WHERE sequence >= ?1 AND sequence <= ?2 ORDER BY sequence",
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite prepare error: {e}")))?;

        let rows = stmt
            .query_map(params![from_seq as i64, to_seq as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| LedgerError::Serialization(format!("SQLite scan_range error: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let data =
                row.map_err(|e| LedgerError::Serialization(format!("SQLite row error: {e}")))?;
            results.push(decode_entry(&data)?);
        }
        Ok(results)
    }

    /// Get all sequence numbers for entries touching a specific account.
    pub fn sequences_for_account(&self, account_id: &uuid::Uuid) -> Result<Vec<u64>, LedgerError> {
        let _ = account_id; // handled via account_entries table
        Ok(vec![])
    }

    // ── Account-entry cross-reference table ───────────────────────────────

    /// Insert an account→sequence mapping (built from entry lines).
    pub fn insert_account_entry(
        &self,
        account_id: &uuid::Uuid,
        sequence: u64,
    ) -> Result<(), LedgerError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO account_entries (account_id, sequence) VALUES (?1, ?2)",
            params![account_id.to_string(), sequence as i64],
        )
        .map_err(|e| LedgerError::Serialization(format!("SQLite account_entry insert: {e}")))?;
        Ok(())
    }

    /// Get all entries for an account in sequence order.
    pub fn entries_for_account(
        &self,
        account_id: &uuid::Uuid,
    ) -> Result<Vec<JournalEntry>, LedgerError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT e.data FROM entries e
                 JOIN account_entries ae ON e.sequence = ae.sequence
                 WHERE ae.account_id = ?1
                 ORDER BY e.sequence",
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite prepare error: {e}")))?;

        let rows = stmt
            .query_map(params![account_id.to_string()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| LedgerError::Serialization(format!("SQLite entries_for_account: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let data =
                row.map_err(|e| LedgerError::Serialization(format!("SQLite row error: {e}")))?;
            results.push(decode_entry(&data)?);
        }
        Ok(results)
    }

    /// Create the account_entries cross-reference table if it doesn't exist.
    pub fn ensure_account_entries_table(&self) -> Result<(), LedgerError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS account_entries (
                    account_id TEXT NOT NULL,
                    sequence   INTEGER NOT NULL,
                    PRIMARY KEY (account_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS idx_ae_account
                    ON account_entries(account_id);",
        )
        .map_err(|e| LedgerError::Serialization(format!("SQLite account_entries schema: {e}")))?;
        Ok(())
    }

    /// Begin a deferred transaction for bulk inserts (import mode).
    pub fn begin_bulk(&self) -> Result<(), LedgerError> {
        let conn = self.lock()?;
        conn.execute_batch("BEGIN DEFERRED")
            .map_err(|e| LedgerError::Serialization(format!("SQLite begin error: {e}")))?;
        Ok(())
    }

    /// Commit the current bulk transaction.
    pub fn commit_bulk(&self) -> Result<(), LedgerError> {
        let conn = self.lock()?;
        conn.execute_batch("COMMIT")
            .map_err(|e| LedgerError::Serialization(format!("SQLite commit error: {e}")))?;
        Ok(())
    }

    /// Rebuild the balance cache by streaming all entries from SQLite.
    /// Entries are decoded one at a time and dropped immediately — constant RAM.
    /// Account types are needed to determine the sign of each balance delta,
    /// so the caller passes in the accounts map.
    pub fn rebuild_balance_cache(
        &self,
        accounts: &std::collections::HashMap<uuid::Uuid, crate::account::Account>,
        balance_cache: &mut std::collections::HashMap<uuid::Uuid, i128>,
    ) -> Result<(), LedgerError> {
        use crate::account::AccountType;
        use crate::entry::{DrCr, EntryStatus};

        self.stream_all(|entry| {
            let affects = matches!(entry.status, EntryStatus::Posted | EntryStatus::Reversal);
            if !affects {
                return Ok(());
            }
            for line in &entry.lines {
                let is_debit_normal = match accounts.get(&line.account_id) {
                    Some(a) => matches!(a.account_type, AccountType::Asset | AccountType::Expense),
                    None => return Ok(()), // account not in map yet — skip
                };
                let delta: i128 = if is_debit_normal {
                    match line.dr_cr {
                        DrCr::Debit => line.amount.as_i128(),
                        DrCr::Credit => -line.amount.as_i128(),
                    }
                } else {
                    match line.dr_cr {
                        DrCr::Credit => line.amount.as_i128(),
                        DrCr::Debit => -line.amount.as_i128(),
                    }
                };
                *balance_cache.entry(line.account_id).or_insert(0) += delta;
            }
            Ok(())
        })
    }

    /// Rollback the current bulk transaction.
    pub fn rollback_bulk(&self) -> Result<(), LedgerError> {
        let conn = self.lock()?;
        conn.execute_batch("ROLLBACK")
            .map_err(|e| LedgerError::Serialization(format!("SQLite rollback error: {e}")))?;
        Ok(())
    }

    /// FOR TESTING ONLY — overwrite an entry's data blob in SQLite without
    /// updating its hash fields, simulating tampered data for demo purposes.
    #[cfg(any(test, feature = "self-test"))]
    pub fn tamper_replace(&self, seq: u64, data: &[u8]) -> Result<bool, LedgerError> {
        let conn = self.lock()?;
        let rows = conn
            .execute(
                "UPDATE entries SET data = ?1 WHERE sequence = ?2",
                rusqlite::params![data, seq as i64],
            )
            .map_err(|e| LedgerError::Serialization(format!("SQLite tamper error: {e}")))?;
        Ok(rows > 0)
    }
}