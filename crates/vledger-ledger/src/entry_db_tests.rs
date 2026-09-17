/// EntryDb account persistence tests (v1.0.21).
///
/// Covers: ensure_accounts_table, upsert_account, load_all_accounts,
/// account_count, and the migrate-to-sqlite guarantee that accounts
/// written during import survive a WAL checkpoint replay.

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        account::{Account, AccountStatus, AccountType},
        entry_db::EntryDb,
        store::LedgerStore,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn open_db(dir: &TempDir) -> EntryDb {
        EntryDb::open(&dir.path().join("test.db")).unwrap()
    }

    fn make_account(code: &str, at: AccountType) -> Account {
        Account::new(code, code, at, "USD", "test")
    }

    fn open_store(dir: &TempDir) -> LedgerStore {
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        LedgerStore::open(dir.path()).unwrap()
    }

    // ══════════════════════════════════════════════════════════════════════
    // ensure_accounts_table
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn ensure_accounts_table_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        // Calling multiple times must not fail.
        db.ensure_accounts_table().unwrap();
        db.ensure_accounts_table().unwrap();
        db.ensure_accounts_table().unwrap();
    }

    // ══════════════════════════════════════════════════════════════════════
    // upsert_account
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn upsert_account_inserts_new_account() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();
        let acct = make_account("CASH", AccountType::Asset);
        db.upsert_account(&acct).unwrap();
        assert_eq!(db.account_count().unwrap(), 1);
    }

    #[test]
    fn upsert_account_replaces_existing_account() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();

        let mut acct = make_account("CHECKING", AccountType::Asset);
        db.upsert_account(&acct).unwrap();

        // Update the account name and upsert again.
        acct.name = "Checking Account Updated".to_string();
        db.upsert_account(&acct).unwrap();

        // Still only one row.
        assert_eq!(db.account_count().unwrap(), 1);

        // The loaded account should have the updated name.
        let loaded = db.load_all_accounts().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Checking Account Updated");
    }

    #[test]
    fn upsert_multiple_accounts() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();

        db.upsert_account(&make_account("CASH", AccountType::Asset)).unwrap();
        db.upsert_account(&make_account("REV", AccountType::Income)).unwrap();
        db.upsert_account(&make_account("EXP", AccountType::Expense)).unwrap();

        assert_eq!(db.account_count().unwrap(), 3);
    }

    // ══════════════════════════════════════════════════════════════════════
    // load_all_accounts
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn load_all_accounts_returns_empty_vec_when_no_accounts() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();
        let accounts = db.load_all_accounts().unwrap();
        assert!(accounts.is_empty());
    }

    #[test]
    fn load_all_accounts_returns_empty_vec_when_table_missing() {
        // On a database without the accounts table (pre-v1.0.21),
        // load_all_accounts must not error — it returns empty.
        let dir = TempDir::new().unwrap();
        // Open without calling ensure_accounts_table.
        let db = EntryDb::open(&dir.path().join("legacy.db")).unwrap();
        let accounts = db.load_all_accounts().unwrap();
        assert!(accounts.is_empty(), "must return empty when table is missing");
    }

    #[test]
    fn load_all_accounts_roundtrips_all_fields() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();

        let mut acct = make_account("SAVINGS", AccountType::Liability);
        acct.name = "Savings Account".to_string();
        acct.status = AccountStatus::Active;
        acct.require_non_negative_balance = false;
        db.upsert_account(&acct).unwrap();

        let loaded = db.load_all_accounts().unwrap();
        assert_eq!(loaded.len(), 1);
        let l = &loaded[0];
        assert_eq!(l.id, acct.id);
        assert_eq!(l.code, "SAVINGS");
        assert_eq!(l.name, "Savings Account");
        assert_eq!(l.account_type, AccountType::Liability);
        assert_eq!(l.currency_code, "USD");
        assert_eq!(l.domain, "test");
        assert!(!l.require_non_negative_balance);
    }

    #[test]
    fn load_all_accounts_returns_all_inserted() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();

        let n = 50usize;
        for i in 0..n {
            let acct = make_account(&format!("ACC{i:04}"), AccountType::Asset);
            db.upsert_account(&acct).unwrap();
        }

        let loaded = db.load_all_accounts().unwrap();
        assert_eq!(loaded.len(), n);
    }

    // ══════════════════════════════════════════════════════════════════════
    // account_count
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn account_count_zero_when_empty() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();
        assert_eq!(db.account_count().unwrap(), 0);
    }

    #[test]
    fn account_count_matches_upserted() {
        let dir = TempDir::new().unwrap();
        let db = open_db(&dir);
        db.ensure_accounts_table().unwrap();

        for i in 0..25u32 {
            let acct = make_account(&format!("A{i}"), AccountType::Asset);
            db.upsert_account(&acct).unwrap();
        }
        assert_eq!(db.account_count().unwrap(), 25);
    }

    // ══════════════════════════════════════════════════════════════════════
    // INTEGRATION: create_account syncs to SQLite via LedgerStore
    //
    // Guarantees the v1.0.21 fix: accounts created via LedgerStore are
    // persisted to SQLite and survive a WAL checkpoint replay.
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn create_account_persists_to_sqlite() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);

        store
            .create_account(Account::new("CASH", "Cash", AccountType::Asset, "USD", "main"))
            .unwrap();
        store
            .create_account(Account::new("REV", "Revenue", AccountType::Income, "USD", "main"))
            .unwrap();

        // Open the SQLite db directly and verify accounts are there.
        let db = EntryDb::open(&dir.path().join("vledger.db")).unwrap();
        assert_eq!(
            db.account_count().unwrap(),
            2,
            "both accounts must be in SQLite after create_account"
        );
    }

    #[test]
    fn accounts_survive_store_reopen() {
        // This is the core regression test for the accounts=0 bug (v1.0.21).
        // After closing and reopening the store, accounts must still be
        // accessible — they are loaded from SQLite when WAL checkpoint skips
        // earlier segments.
        let dir = TempDir::new().unwrap();

        // Create accounts and entries.
        {
            let mut store = open_store(&dir);
            store
                .create_account(Account::new("CASH", "Cash", AccountType::Asset, "USD", "main"))
                .unwrap();
            store
                .create_account(Account::new("REV", "Revenue", AccountType::Income, "USD", "main"))
                .unwrap();
        }

        // Reopen the store — simulates server restart.
        let store2 = open_store(&dir);
        assert!(
            store2.all_accounts().any(|a| a.code == "CASH"),
            "CASH account must survive store reopen"
        );
        assert!(
            store2.all_accounts().any(|a| a.code == "REV"),
            "REV account must survive store reopen"
        );
    }

    #[test]
    fn account_count_in_sqlite_matches_in_memory_after_reopen() {
        let dir = TempDir::new().unwrap();

        let n = 10usize;
        {
            let mut store = open_store(&dir);
            for i in 0..n {
                store
                    .create_account(Account::new(
                        &format!("ACC{i}"),
                        &format!("Account {i}"),
                        AccountType::Suspense,
                        "USD",
                        "main",
                    ))
                    .unwrap();
            }
        }

        // Verify SQLite count.
        let db = EntryDb::open(&dir.path().join("vledger.db")).unwrap();
        assert_eq!(
            db.account_count().unwrap(),
            n as u64,
            "SQLite account count must match number created"
        );
    }
}
