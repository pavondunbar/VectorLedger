/// SQL layer tests — parser, planner, executor.
///
/// Covers the full pipeline:
///   SQL text → parse_one → LogicalPlanBuilder::plan → Executor::execute
///
/// Tests every supported statement, every filter variant, error paths,
/// and the read/write split enforcement.

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use vledger_ledger::{Account, AccountType, Amount, JournalEntryBuilder, LedgerStore};

    use crate::{
        executor::{Executor, ReadExecutor},
        parser::parse_one,
        planner::LogicalPlanBuilder,
        result::Value,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn setup() -> (TempDir, LedgerStore) {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        let store = LedgerStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn mk_accounts(store: &mut LedgerStore) -> (uuid::Uuid, uuid::Uuid) {
        let cash = store
            .create_account(Account::new("CASH", "Cash", AccountType::Asset, "USD", "test"))
            .unwrap();
        let rev = store
            .create_account(Account::new("REV", "Revenue", AccountType::Income, "USD", "test"))
            .unwrap();
        (cash, rev)
    }

    fn seed(store: &mut LedgerStore, cash: uuid::Uuid, rev: uuid::Uuid, cents: i64) -> u64 {
        let amt = Amount::new(cents).unwrap();
        let e = JournalEntryBuilder::new("test entry", "main")
            .debit(cash, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        store.post_entry(e).unwrap()
    }

    fn run(store: &mut LedgerStore, sql: &str) -> crate::result::QueryResult {
        let stmt = parse_one(sql).expect("parse failed");
        let plan = LogicalPlanBuilder::plan(stmt).expect("plan failed");
        Executor::new(store).execute(plan).expect("execute failed")
    }

    fn run_read(store: &LedgerStore, sql: &str) -> crate::result::QueryResult {
        let stmt = parse_one(sql).expect("parse failed");
        let plan = LogicalPlanBuilder::plan(stmt).expect("plan failed");
        ReadExecutor::new(store).execute(plan).expect("execute failed")
    }

    // ══════════════════════════════════════════════════════════════════════
    // CREATE ACCOUNT via SQL
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_insert_into_accounts_creates_account() {
        let (_dir, mut store) = setup();
        let result = run(
            &mut store,
            "INSERT INTO accounts (code, name, account_type, currency, domain) \
             VALUES ('CHECKING', 'Checking Account', 'Asset', 'USD', 'main')",
        );
        assert_eq!(result.rows.len(), 1);
        assert!(result.message.contains("created"));
        let row = &result.rows[0];
        let code_val = row.values.iter().zip(row.columns.iter())
            .find(|(_, col)| col.as_str() == "code")
            .map(|(v, _)| v);
        assert!(matches!(code_val, Some(Value::Text(c)) if c == "CHECKING"));
    }

    // ══════════════════════════════════════════════════════════════════════
    // INSERT INTO ledger
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_insert_into_ledger_posts_entry() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let result = run(
            &mut store,
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Test payment', 'CASH', 'REV', 5000, 'USD', 'main')",
        );
        assert_eq!(result.rows.len(), 1);
        assert!(result.message.contains("posted"));
        assert!(result.entry_sequence.is_some());
        assert_eq!(result.rows_affected, 1);
    }

    #[test]
    fn sql_insert_unknown_debit_account_fails() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let stmt = parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Bad', 'UNKNOWN', 'REV', 100, 'USD', 'main')",
        ).unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::new(&mut store).execute(plan);
        assert!(result.is_err());
    }

    #[test]
    fn sql_insert_zero_amount_fails() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let stmt = parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Zero', 'CASH', 'REV', 0, 'USD', 'main')",
        ).unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::new(&mut store).execute(plan);
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════════
    // SELECT FROM ledger
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_select_from_ledger_returns_rows() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 1000);
        seed(&mut store, cash, rev, 2000);
        let result = run_read(&store, "SELECT * FROM ledger");
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn sql_select_from_ledger_where_sequence() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        let seq = seed(&mut store, cash, rev, 9999);
        let result = run_read(
            &store,
            &format!("SELECT * FROM ledger WHERE sequence = {seq}"),
        );
        assert_eq!(result.rows.len(), 1);
        let row = &result.rows[0];
        let seq_val = row.values.iter().zip(row.columns.iter())
            .find(|(_, col)| col.as_str() == "sequence")
            .map(|(v, _)| v);
        assert!(matches!(seq_val, Some(Value::BigInt(s)) if *s == seq as i128));
    }

    #[test]
    fn sql_select_from_ledger_where_domain() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 500);
        let result = run_read(&store, "SELECT * FROM ledger WHERE domain = 'main'");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn sql_select_from_ledger_where_status() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 500);
        let result = run_read(&store, "SELECT * FROM ledger WHERE status = 'Posted'");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn sql_select_from_ledger_limit() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        for _ in 0..10 {
            seed(&mut store, cash, rev, 100);
        }
        let result = run_read(&store, "SELECT * FROM ledger LIMIT 3");
        assert_eq!(result.rows.len(), 3);
    }

    // ══════════════════════════════════════════════════════════════════════
    // SELECT FROM ledger_lines
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_select_from_ledger_lines_returns_two_rows_per_entry() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 750);
        let result = run_read(&store, "SELECT * FROM ledger_lines");
        // 1 entry = 2 lines (debit + credit)
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn sql_select_ledger_lines_where_dr_cr_debit() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 750);
        let result = run_read(&store, "SELECT * FROM ledger_lines WHERE dr_cr = 'Debit'");
        assert_eq!(result.rows.len(), 1);
        let row = &result.rows[0];
        let dr_cr = row.values.iter().zip(row.columns.iter())
            .find(|(_, col)| col.as_str() == "dr_cr")
            .map(|(v, _)| v);
        assert!(matches!(dr_cr, Some(Value::Text(s)) if s == "Debit"));
    }

    #[test]
    fn sql_select_ledger_lines_where_dr_cr_credit() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 750);
        let result = run_read(&store, "SELECT * FROM ledger_lines WHERE dr_cr = 'Credit'");
        assert_eq!(result.rows.len(), 1);
    }

    // ══════════════════════════════════════════════════════════════════════
    // SELECT FROM accounts
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_select_from_accounts_returns_all() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let result = run_read(&store, "SELECT * FROM accounts");
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn sql_select_accounts_where_code() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let result = run_read(&store, "SELECT * FROM accounts WHERE code = 'CASH'");
        assert_eq!(result.rows.len(), 1);
        let row = &result.rows[0];
        let code_val = row.values.iter().zip(row.columns.iter())
            .find(|(_, col)| col.as_str() == "code")
            .map(|(v, _)| v);
        assert!(matches!(code_val, Some(Value::Text(c)) if c == "CASH"));
    }

    #[test]
    fn sql_select_accounts_where_id() {
        let (_dir, mut store) = setup();
        let (cash_id, _) = mk_accounts(&mut store);
        let sql = format!("SELECT * FROM accounts WHERE id = '{cash_id}'");
        let result = run_read(&store, &sql);
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn sql_select_accounts_where_name() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let result = run_read(&store, "SELECT * FROM accounts WHERE name = 'Cash'");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn sql_select_accounts_unknown_code_returns_empty() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let result = run_read(&store, "SELECT * FROM accounts WHERE code = 'UNKNOWN'");
        assert_eq!(result.rows.len(), 0);
    }

    // ══════════════════════════════════════════════════════════════════════
    // SELECT BALANCE
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_select_balance_returns_correct_value() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 12345);
        let result = run_read(&store, "SELECT BALANCE('CASH')");
        assert_eq!(result.rows.len(), 1);
        let bal = result.rows[0].values.iter().zip(result.rows[0].columns.iter())
            .find(|(_, col)| col.as_str() == "balance")
            .map(|(v, _)| v);
        assert!(matches!(bal, Some(Value::BigInt(b)) if *b == 12345));
    }

    #[test]
    fn sql_select_balance_unknown_account_fails() {
        let (_dir, store) = setup();
        let stmt = parse_one("SELECT BALANCE('DOESNOTEXIST')").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = ReadExecutor::new(&store).execute(plan);
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════════
    // SELECT VERIFY_CHAIN
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_verify_chain_ok_on_clean_ledger() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 100);
        seed(&mut store, cash, rev, 200);
        let result = run_read(&store, "SELECT VERIFY_CHAIN()");
        assert_eq!(result.rows.len(), 1);
        let status = result.rows[0].values.iter().zip(result.rows[0].columns.iter())
            .find(|(_, col)| col.as_str() == "status")
            .map(|(v, _)| v);
        assert!(matches!(status, Some(Value::Text(s)) if s == "OK"));
    }

    #[test]
    fn sql_verify_chain_range() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        for _ in 0..5 {
            seed(&mut store, cash, rev, 100);
        }
        let result = run_read(&store, "SELECT VERIFY_CHAIN(1, 3)");
        assert_eq!(result.rows.len(), 1);
        let status = result.rows[0].values.iter().zip(result.rows[0].columns.iter())
            .find(|(_, col)| col.as_str() == "status")
            .map(|(v, _)| v);
        assert!(matches!(status, Some(Value::Text(s)) if s == "OK"));
    }

    #[test]
    fn sql_verify_chain_detects_tamper() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        let seq = seed(&mut store, cash, rev, 999);

        // Use TamperEntry (cfg(test) only) to corrupt the entry.
        let stmt = parse_one(&format!(
            "SELECT TAMPER_ENTRY({seq}, 'tampered description')"
        )).unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        Executor::new(&mut store).execute(plan).unwrap();

        // VERIFY_CHAIN should now fail.
        let result = run_read(&store, "SELECT VERIFY_CHAIN()");
        // Either empty rows (failure path) or status != OK.
        let is_ok = result.rows.first()
            .and_then(|r| r.values.iter().zip(r.columns.iter())
                .find(|(_, col)| col.as_str() == "status")
                .map(|(v, _)| v))
            .map(|v| matches!(v, Value::Text(s) if s == "OK"))
            .unwrap_or(false);
        assert!(!is_ok, "VERIFY_CHAIN must fail after tampering");
    }

    // ══════════════════════════════════════════════════════════════════════
    // COMPATIBILITY CONSTANTS
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_select_1_returns_constant() {
        let (_dir, store) = setup();
        let result = run_read(&store, "SELECT 1");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn sql_select_version_returns_string() {
        let (_dir, store) = setup();
        let result = run_read(&store, "SELECT version()");
        assert_eq!(result.rows.len(), 1);
        let val = &result.rows[0].values[0];
        assert!(matches!(val, Value::Text(s) if s.contains("VectorLedger") || s.contains("PostgreSQL")));
    }

    #[test]
    fn sql_select_current_database_returns_vledger() {
        let (_dir, store) = setup();
        let result = run_read(&store, "SELECT current_database()");
        assert_eq!(result.rows.len(), 1);
        assert!(matches!(&result.rows[0].values[0], Value::Text(s) if s == "vledger"));
    }

    // ══════════════════════════════════════════════════════════════════════
    // UNSUPPORTED STATEMENTS REJECTED
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_update_ledger_rejected_by_planner() {
        let stmt = parse_one("UPDATE ledger SET amount = 999 WHERE sequence = 1").unwrap();
        assert!(LogicalPlanBuilder::plan(stmt).is_err());
    }

    #[test]
    fn sql_delete_from_ledger_rejected_by_planner() {
        let stmt = parse_one("DELETE FROM ledger WHERE sequence = 1").unwrap();
        assert!(LogicalPlanBuilder::plan(stmt).is_err());
    }

    #[test]
    fn sql_drop_table_ledger_rejected_by_planner() {
        let stmt = parse_one("DROP TABLE ledger").unwrap();
        assert!(LogicalPlanBuilder::plan(stmt).is_err());
    }

    #[test]
    fn sql_drop_database_rejected_by_planner() {
        // DROP DATABASE is not valid SQL in sqlparser but the parser/planner must reject it.
        assert!(parse_one("DROP DATABASE vledger").is_err()
            || LogicalPlanBuilder::plan(parse_one("DROP DATABASE vledger").unwrap_or_else(|_| {
                // If parser errors, that's the rejection — test passes.
                panic!("already rejected by parser")
            })).is_err());
    }

    #[test]
    fn sql_write_plan_rejected_by_read_executor() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        use crate::planner::{EntrySpec, LogicalPlan};
        let plan = LogicalPlan::PostEntry(EntrySpec {
            description: "x".into(),
            debit_account: "CASH".into(),
            credit_account: "REV".into(),
            amount: 100,
            currency: "USD".into(),
            external_ref: None,
            idempotency_key: None,
            domain: "main".into(),
        });
        let result = ReadExecutor::new(&store).execute(plan);
        assert!(result.is_err(), "ReadExecutor must reject write plans");
    }

    // ══════════════════════════════════════════════════════════════════════
    // AGGREGATE QUERIES
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_count_from_ledger() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 100);
        seed(&mut store, cash, rev, 200);
        let result = run_read(&store, "SELECT COUNT(sequence) FROM ledger");
        assert_eq!(result.rows.len(), 1);
        let count = &result.rows[0].values[0];
        assert!(matches!(count, Value::BigInt(n) if *n == 2));
    }

    #[test]
    fn sql_sum_amount_from_ledger_lines() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 1000);
        seed(&mut store, cash, rev, 2000);
        // 2 entries × 2 lines each = 4 lines; debit lines sum = 3000
        let result = run_read(
            &store,
            "SELECT SUM(amount) FROM ledger_lines WHERE dr_cr = 'Debit'",
        );
        assert_eq!(result.rows.len(), 1);
        let sum = &result.rows[0].values[0];
        assert!(matches!(sum, Value::BigInt(n) if *n == 3000));
    }

    // ══════════════════════════════════════════════════════════════════════
    // JOIN
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_join_ledger_accounts() {
        let (_dir, mut store) = setup();
        let (cash, rev) = mk_accounts(&mut store);
        seed(&mut store, cash, rev, 500);
        let result = run_read(
            &store,
            "SELECT * FROM ledger JOIN accounts ON ledger.domain = accounts.domain LIMIT 5",
        );
        // Should return rows without panicking
        assert!(result.rows.len() <= 5);
    }

    // ══════════════════════════════════════════════════════════════════════
    // IDEMPOTENCY VIA SQL
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn sql_insert_with_idempotency_key_no_duplicate() {
        let (_dir, mut store) = setup();
        mk_accounts(&mut store);
        let sql = "INSERT INTO ledger \
            (description, debit_account, credit_account, amount, currency, domain, idempotency_key) \
            VALUES ('Idem test', 'CASH', 'REV', 100, 'USD', 'main', 'key-abc-123')";

        // First insert — should succeed.
        let r1 = run(&mut store, sql);
        assert!(r1.entry_sequence.is_some());

        // Second insert with same idempotency key — should return existing, not duplicate.
        let r2 = run(&mut store, sql);
        assert!(r2.entry_sequence.is_some());

        // Only one entry should exist.
        let count = run_read(&store, "SELECT COUNT(sequence) FROM ledger");
        assert!(matches!(count.rows[0].values[0], Value::BigInt(1)));
    }
}
