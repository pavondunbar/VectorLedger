//! Phase 1 — Attack the database layer.
//!
//! Adversarial tests covering:
//!   - SQL parser: malformed, oversized, injection-style, Unicode, binary garbage
//!   - SQL planner: every unsupported path, invalid field types, missing fields
//!   - SQL executor: read/write split enforcement, invalid account refs, bad amounts
//!   - Merkle proofs: tampered leaf, wrong index, empty tree, tampered root

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use vledger_ledger::{Account, AccountType, Amount, JournalEntryBuilder, LedgerStore};

    use crate::{
        executor::{Executor, ReadExecutor},
        parser::parse_one,
        planner::LogicalPlanBuilder,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn setup() -> (TempDir, LedgerStore) {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        let store = LedgerStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn add_accounts(store: &mut LedgerStore) -> (uuid::Uuid, uuid::Uuid) {
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
        (cash, rev)
    }

    // ══════════════════════════════════════════════════════════════════════
    // SQL PARSER ATTACKS
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn parser_empty_string_rejected() {
        assert!(parse_one("").is_err());
    }

    #[test]
    fn parser_only_whitespace_rejected() {
        assert!(parse_one("   \t\n  ").is_err());
    }

    #[test]
    fn parser_only_semicolon_rejected() {
        assert!(parse_one(";").is_err());
    }

    #[test]
    fn parser_multiple_statements_rejected_by_parse_one() {
        let r = parse_one("SELECT * FROM ledger; SELECT * FROM accounts");
        assert!(r.is_err(), "parse_one must reject multi-statement input");
    }

    #[test]
    fn parser_sql_injection_unknown_table_rejected_by_planner() {
        let stmt = parse_one("SELECT * FROM information_schema.tables").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt);
        assert!(plan.is_err(), "planner must reject unknown tables");
    }

    #[test]
    fn parser_drop_table_rejected_by_planner() {
        let stmt = parse_one("DROP TABLE ledger").unwrap();
        assert!(
            LogicalPlanBuilder::plan(stmt).is_err(),
            "DROP TABLE must be rejected"
        );
    }

    #[test]
    fn parser_delete_rejected_by_planner() {
        let stmt = parse_one("DELETE FROM ledger WHERE sequence = 1").unwrap();
        assert!(
            LogicalPlanBuilder::plan(stmt).is_err(),
            "DELETE must be rejected (append-only)"
        );
    }

    #[test]
    fn parser_update_rejected_by_planner() {
        let stmt = parse_one("UPDATE ledger SET description = 'x' WHERE sequence = 1").unwrap();
        assert!(
            LogicalPlanBuilder::plan(stmt).is_err(),
            "UPDATE must be rejected (append-only)"
        );
    }

    #[test]
    fn parser_select_with_no_from_rejected_by_planner() {
        let stmt = parse_one("SELECT 1 + 1").unwrap();
        assert!(LogicalPlanBuilder::plan(stmt).is_err());
    }

    #[test]
    fn parser_insert_into_unknown_table_rejected() {
        let stmt = parse_one("INSERT INTO secret_table (col) VALUES ('x')").unwrap();
        assert!(LogicalPlanBuilder::plan(stmt).is_err());
    }

    #[test]
    fn parser_very_long_string_does_not_panic() {
        let long_val = "x".repeat(1_000_000);
        let sql = format!(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('{long_val}', 'CASH', 'REV', 1000, 'USD', 'test')"
        );
        let _ = parse_one(&sql); // must not panic
    }

    #[test]
    fn parser_null_bytes_in_string_handled() {
        let sql = "SELECT * FROM ledger WHERE domain = '\0\0\0'";
        let _ = parse_one(sql); // must not panic
    }

    // ── SQL parser stack-overflow DoS — FIXED ────────────────────────────
    //
    // Previously ~50 levels of nested subqueries caused sqlparser-rs to
    // overflow the stack (SIGABRT).  The pre-parse nesting-depth guard in
    // parser.rs now intercepts this before the parser is called and returns
    // SqlError::NestingTooDeep.  The process is never at risk.

    #[test]
    fn parser_deeply_nested_subquery_is_rejected_not_stack_overflow() {
        // 50 levels — the former crash vector.  Must return NestingTooDeep
        // (or QueryTooLong if the length guard fires first).
        let mut sql = "SELECT * FROM ledger".to_string();
        for _ in 0..50 {
            sql = format!("SELECT * FROM ({sql}) AS sub");
        }
        match parse_one(&sql) {
            Err(crate::error::SqlError::NestingTooDeep { .. }) => {} // correct
            Err(crate::error::SqlError::QueryTooLong { .. }) => {}   // also acceptable
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("50-level nesting must be rejected"),
        }
    }

    #[test]
    fn parser_moderate_nesting_10_levels_is_rejected_or_handled() {
        // 10 levels is below the nesting limit — guard passes, planner rejects
        // the unknown subquery table.
        let mut sql = "SELECT * FROM ledger".to_string();
        for _ in 0..10 {
            sql = format!("SELECT * FROM ({sql}) AS sub");
        }
        let result = parse_one(&sql);
        if let Ok(stmt) = result {
            let _ = crate::planner::LogicalPlanBuilder::plan(stmt);
        }
        // must not panic
    }

    #[test]
    fn parser_unicode_identifiers_handled() {
        let sql = "SELECT * FROM ledger WHERE domain = '日本語テスト'";
        let _ = parse_one(sql); // must not panic
    }

    #[test]
    fn parser_binary_garbage_does_not_panic() {
        let garbage: Vec<u8> = (0u8..=255u8).collect();
        let s = String::from_utf8_lossy(&garbage).to_string();
        let _ = parse_one(&s); // must not panic
    }

    #[test]
    fn parser_select_balance_with_no_arg_rejected() {
        let stmt = parse_one("SELECT BALANCE()").unwrap();
        assert!(
            LogicalPlanBuilder::plan(stmt).is_err(),
            "BALANCE() with no arg must be rejected"
        );
    }

    #[test]
    fn parser_select_from_unknown_table_rejected() {
        let stmt = parse_one("SELECT * FROM not_a_real_table").unwrap();
        assert!(LogicalPlanBuilder::plan(stmt).is_err());
    }

    // ══════════════════════════════════════════════════════════════════════
    // SQL EXECUTOR ATTACKS
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn executor_insert_non_integer_amount_rejected_by_planner() {
        let stmt = parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('test', 'CASH', 'REV', 'notanumber', 'USD', 'test')",
        )
        .unwrap();
        assert!(
            LogicalPlanBuilder::plan(stmt).is_err(),
            "non-integer amount must fail at planner"
        );
    }

    #[test]
    fn executor_insert_zero_amount_rejected() {
        let (_dir, mut store) = setup();
        add_accounts(&mut store);

        let stmt = parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('test', 'CASH', 'REV', 0, 'USD', 'test')",
        )
        .unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::new(&mut store).execute(plan);
        assert!(result.is_err(), "zero amount must be rejected");
    }

    #[test]
    fn executor_insert_with_nonexistent_account_rejected() {
        let (_dir, mut store) = setup();

        let stmt = parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('test', 'GHOST', 'PHANTOM', 1000, 'USD', 'test')",
        )
        .unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::new(&mut store).execute(plan);
        assert!(result.is_err(), "nonexistent accounts must be rejected");
    }

    #[test]
    fn executor_write_plan_on_read_executor_rejected() {
        let (_dir, mut store) = setup();
        add_accounts(&mut store);

        let stmt = parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('test', 'CASH', 'REV', 1000, 'USD', 'test')",
        )
        .unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = ReadExecutor::new(&store).execute(plan);
        assert!(result.is_err(), "ReadExecutor must reject write plans");
    }

    #[test]
    fn executor_balance_for_unknown_account_does_not_panic() {
        let (_dir, store) = setup();
        let stmt = parse_one("SELECT BALANCE('NONEXISTENT')").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = ReadExecutor::new(&store).execute(plan);
        // Must not panic — result may be Ok(0) or an error
        let _ = result;
    }

    #[test]
    fn executor_verify_chain_on_empty_ledger_succeeds() {
        let (_dir, store) = setup();
        let stmt = parse_one("SELECT VERIFY_CHAIN()").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        assert!(ReadExecutor::new(&store).execute(plan).is_ok());
    }

    #[test]
    fn executor_negative_amount_insert_rejected() {
        let (_dir, mut store) = setup();
        add_accounts(&mut store);

        // Negative integer literals are rejected by the SQL planner
        // (the parser produces an expression like UnaryOp(-,1000) which
        // expr_to_string does not support).  This is the correct behavior —
        // negative amounts must never reach the executor.
        let stmt = parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('test', 'CASH', 'REV', -1000, 'USD', 'test')",
        )
        .unwrap();
        // Negative amounts must be rejected at the planner level
        let plan_result = LogicalPlanBuilder::plan(stmt);
        assert!(
            plan_result.is_err(),
            "negative amount must be rejected by planner (got: {plan_result:?})"
        );
    }

    #[test]
    fn executor_select_limit_zero_does_not_panic() {
        let (_dir, store) = setup();
        let stmt = parse_one("SELECT * FROM ledger LIMIT 0").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let _ = ReadExecutor::new(&store).execute(plan); // must not panic
    }

    #[test]
    fn executor_idempotency_key_deduplication_via_sql() {
        let (_dir, mut store) = setup();
        add_accounts(&mut store);

        let sql = "INSERT INTO ledger \
                   (description, debit_account, credit_account, amount, currency, domain, idempotency_key) \
                   VALUES ('sale', 'CASH', 'REV', 5000, 'USD', 'test', 'idem-sql-001')";

        let plan1 = LogicalPlanBuilder::plan(parse_one(sql).unwrap()).unwrap();
        let plan2 = LogicalPlanBuilder::plan(parse_one(sql).unwrap()).unwrap();

        Executor::new(&mut store).execute(plan1).unwrap();
        let result = Executor::new(&mut store).execute(plan2);
        assert!(
            result.is_ok(),
            "idempotent duplicate must succeed, got: {result:?}"
        );
        assert_eq!(
            store.entry_count(),
            1,
            "must have exactly 1 entry after idempotent post"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // MERKLE PROOF ATTACKS
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn merkle_proof_tampered_leaf_rejected() {
        use vledger_crypto::merkle::{merkle_proof, merkle_root};

        let leaves: Vec<[u8; 32]> = (0u8..8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 3).unwrap();

        // Tamper with the leaf
        let mut bad_leaf = leaves[3];
        bad_leaf[0] ^= 0xFF;

        // Rebuild proof for tampered leaf to attempt verification
        let tampered_proof = vledger_crypto::merkle::MerkleProof {
            leaf_index: proof.leaf_index,
            leaf_hash: vledger_crypto::hash::hash_leaf(&bad_leaf),
            path: proof.path,
            root,
        };
        assert!(
            tampered_proof.verify().is_err(),
            "tampered leaf must fail Merkle proof verification"
        );
    }

    #[test]
    fn merkle_proof_valid_leaf_verifies() {
        use vledger_crypto::merkle::{merkle_proof, merkle_root};
        let leaves: Vec<[u8; 32]> = (0u8..8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 3).unwrap();
        assert_eq!(proof.root, root);
        assert!(proof.verify().is_ok(), "valid proof must verify");
    }

    #[test]
    fn merkle_root_empty_tree_is_zero_hash() {
        use vledger_crypto::merkle::merkle_root;
        let empty: &[[u8; 32]] = &[];
        let root = merkle_root(empty);
        assert_eq!(
            root,
            vledger_crypto::ZERO_HASH,
            "empty Merkle tree must produce ZERO_HASH"
        );
    }

    #[test]
    fn merkle_proof_single_leaf_verifies() {
        use vledger_crypto::merkle::{merkle_proof, merkle_root};
        let leaf: [u8; 32] = [0xABu8; 32];
        let root = merkle_root(&[leaf]);
        let proof = merkle_proof(&[leaf], 0).unwrap();
        assert_eq!(proof.root, root);
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn merkle_tampered_root_rejected() {
        use vledger_crypto::merkle::{merkle_proof, merkle_root};
        let leaves: Vec<[u8; 32]> = (0u8..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 1).unwrap();

        // Create a proof with tampered root
        let mut bad_root = root;
        bad_root[0] ^= 0x01;
        let tampered_proof = vledger_crypto::merkle::MerkleProof {
            leaf_index: proof.leaf_index,
            leaf_hash: proof.leaf_hash,
            path: proof.path,
            root: bad_root, // tampered root
        };
        assert!(
            tampered_proof.verify().is_err(),
            "tampered root must fail verification"
        );
    }

    #[test]
    fn merkle_wrong_index_proof_fails() {
        use vledger_crypto::merkle::{merkle_proof, merkle_root};
        let leaves: Vec<[u8; 32]> = (0u8..8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();
        let root = merkle_root(&leaves);

        // Get proof for leaf[3] — this path is specifically for index 3
        let proof_for_3 = merkle_proof(&leaves, 3).unwrap();

        // Try to use leaf[3]'s hash but with the *path* of index 3 and claim it proves index 4.
        // The leaf_hash of index 4 is different from index 3, so the recomputed root will differ.
        let leaf_hash_of_4 = vledger_crypto::hash::hash_leaf(&leaves[4]);
        let wrong_proof = vledger_crypto::merkle::MerkleProof {
            leaf_index: 4,
            leaf_hash: leaf_hash_of_4, // correct hash for index 4
            path: proof_for_3.path,    // but path designed for index 3
            root,
        };
        // The path for index 3 combined with the leaf_hash of index 4 produces the wrong root
        assert!(
            wrong_proof.verify().is_err(),
            "proof with mismatched path/index must fail"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // WAL RECORD INTEGRITY ATTACKS  (WAL types available via vledger-ledger)
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn wal_tampered_segment_stops_recovery_at_tear() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let data_dir = dir.path();
        let wal_dir = data_dir.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::fs::create_dir_all(data_dir.join("pages")).unwrap();

        // Write one committed entry
        {
            let mut store = LedgerStore::open(data_dir).unwrap();
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
                    "Rev",
                    AccountType::Income,
                    "USD",
                    "test",
                ))
                .unwrap();
            let amt = Amount::new(1000).unwrap();
            let e = JournalEntryBuilder::new("test", "test")
                .debit(cash, amt, "USD")
                .credit(rev, amt, "USD")
                .build();
            store.post_entry(e).unwrap();
        }

        // Corrupt the tail of the segment to simulate a torn write
        let segments: Vec<_> = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "wal"))
            .collect();
        assert!(!segments.is_empty());
        let seg_path = segments[0].path();
        let mut data = std::fs::read(&seg_path).unwrap();
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);
        std::fs::write(&seg_path, &data).unwrap();

        // Re-open: must recover the committed tx and not panic
        let store2 = LedgerStore::open(data_dir);
        assert!(store2.is_ok(), "re-open after torn write must succeed");
        assert_eq!(store2.unwrap().entry_count(), 1);
    }

    #[test]
    fn wal_empty_wal_directory_opens_cleanly() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        let store = LedgerStore::open(dir.path());
        assert!(store.is_ok(), "opening empty data dir must succeed");
        assert_eq!(store.unwrap().entry_count(), 0);
    }

    #[test]
    fn wal_all_valid_record_type_bytes_parse() {
        // Validate that every defined record type byte round-trips correctly
        // (tested via the WAL crate which is a dep of vledger-ledger)
        // We exercise it indirectly: post + reopen validates full WAL round-trip.
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();

        let mut store = LedgerStore::open(dir.path()).unwrap();
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
                "Rev",
                AccountType::Income,
                "USD",
                "test",
            ))
            .unwrap();

        // Post an entry to exercise Begin + Data + Commit record types
        let e = JournalEntryBuilder::new("wal-types-test", "test")
            .debit(cash, Amount::new(777).unwrap(), "USD")
            .credit(rev, Amount::new(777).unwrap(), "USD")
            .build();
        store.post_entry(e).unwrap();
        drop(store);

        // Reopen (exercises recovery which reads all record types)
        let store2 = LedgerStore::open(dir.path()).unwrap();
        assert_eq!(store2.entry_count(), 1);
    }
}
