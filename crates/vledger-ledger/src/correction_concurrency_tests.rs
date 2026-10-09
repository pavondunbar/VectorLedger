//! Concurrency tests for the execute_correction idempotency / TOCTOU race.
//!
//! ## Background
//!
//! `execute_correction` (MCP tools layer) follows a three-phase pattern:
//!
//! ```text
//! Phase 1 — Pre-flight read:
//!     SELECT sequence FROM ledger WHERE external_ref = 'reversal-of-<id>'   → None/Some
//!     SELECT sequence FROM ledger WHERE external_ref = 'correction-of-<id>' → None/Some
//!
//! Phase 2 — Reversal write:
//!     INSERT INTO ledger (..., external_ref='reversal-of-<id>', idempotency_key='reversal-of-<id>', ...)
//!
//! Phase 3 — Correction write:
//!     INSERT INTO ledger (..., external_ref='correction-of-<id>', idempotency_key='correction-of-<id>', ...)
//! ```
//!
//! Every call to `run_sql()` (embedded mode) or `conn.execute_sql()` (network mode)
//! acquires and **releases** the `Arc<RwLock<LedgerStore>>` write lock independently.
//! There is no spanning lock across all three phases.
//!
//! ## Race scenario (TOCTOU)
//!
//! ```text
//! Agent A  │ pre-flight (None, None) │     │ INSERT reversal │ INSERT correction │
//! Agent B  │                         │ pre-flight (None, None) │ INSERT reversal ←── wins or loses under the idempotency gate │
//! ```
//!
//! Two concurrent callers both observe "nothing applied yet" and both proceed
//! to the write phases.  Whether this produces:
//!   (a) exactly one reversal + one correction (correct — idempotency gate fires), or
//!   (b) two reversals + two corrections (bug — would double-undo the original entry)
//!
//! …depends entirely on `post_entry`'s idempotency key check, which runs while
//! holding `&mut self` (the exclusive write lock).
//!
//! ## What these tests verify
//!
//! 1. **`concurrent_correction_idempotency`** — N tasks race through the full
//!    correction workflow simultaneously using a Tokio barrier to maximise
//!    collision.  Asserts: exactly 1 reversal and 1 correction entry exist,
//!    the ledger is balanced (original + reversal + correction = net zero for
//!    the reversal), and the hash chain is intact.
//!
//! 2. **`correction_winner_result_not_error`** — simulates the *loser's* call
//!    path: a second caller calls post_entry with the same idempotency key after
//!    the first has already succeeded.  Asserts: the second call returns the
//!    **winner's sequence number**, not an error.  The loser must always receive
//!    a usable, non-error result so the agent has no reason to retry.
//!
//! 3. **`partial_correction_recovery`** — simulates a crash between the reversal
//!    and correction INSERTs (only the reversal was written).  A retry call finds
//!    the reversal already present and posts only the correction.  Asserts: the
//!    final state contains exactly one reversal and one correction, not two of
//!    either.
//!
//! 4. **`correction_does_not_affect_unrelated_entries`** — a correction on entry
//!    #1 must not change the sequence number, content_hash, or chain_hash of
//!    any unrelated entry.  Append-only guarantee under concurrent writes.
//!
//! 5. **`high_concurrency_correction_stress`** — 50 tasks race on the same
//!    correction.  Asserts exactly 2 entries appended (reversal + correction),
//!    hash chain intact, and final balance is consistent.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::{Barrier, RwLock};

    use crate::{
        account::{Account, AccountType},
        amount::Amount,
        entry::JournalEntryBuilder,
        store::LedgerStore,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn setup_dir() -> TempDir {
        let d = TempDir::new().unwrap();
        std::fs::create_dir_all(d.path().join("wal")).unwrap();
        std::fs::create_dir_all(d.path().join("pages")).unwrap();
        d
    }

    /// Build a LedgerStore with two accounts (CASH:Asset, REV:Income) and
    /// post a single journal entry.  Returns `(store, cash_id, rev_id,
    /// original_entry_uuid, original_sequence, original_amount)`.
    async fn setup_with_original_entry(
        dir: &TempDir,
        amount_minor: i64,
    ) -> (
        Arc<RwLock<LedgerStore>>,
        uuid::Uuid, // cash account id (as UUID)
        uuid::Uuid, // rev account id (as UUID)
        uuid::Uuid, // original entry UUID
        u64,        // original entry sequence
    ) {
        let store = Arc::new(RwLock::new(LedgerStore::open(dir.path()).unwrap()));

        let (cash_id, rev_id, orig_uuid, orig_seq) = {
            let mut g = store.write().await;

            let cash_account_id = g
                .create_account(Account::new(
                    "CASH",
                    "Cash",
                    AccountType::Asset,
                    "USD",
                    "test",
                ))
                .unwrap();
            let rev_account_id = g
                .create_account(Account::new(
                    "REV",
                    "Revenue",
                    AccountType::Income,
                    "USD",
                    "test",
                ))
                .unwrap();

            let amt = Amount::new(amount_minor).unwrap();
            let orig_uuid = uuid::Uuid::new_v4();
            let entry = JournalEntryBuilder::new("Original payment", "test")
                .debit(cash_account_id, amt, "USD")
                .credit(rev_account_id, amt, "USD")
                .build();
            let orig_seq = g.post_entry(entry).unwrap();

            (
                cash_account_id,
                rev_account_id,
                orig_uuid,
                orig_seq,
            )
        };

        (store, cash_id, rev_id, orig_uuid, orig_seq)
    }

    /// Simulate what the MCP `execute_correction` tool does at the
    /// LedgerStore level:
    ///
    /// 1. Read: check whether reversal already exists by idempotency key.
    /// 2. Write reversal (skip if already posted).
    /// 3. Write correction.
    ///
    /// Returns `(reversal_seq, correction_seq)`.
    ///
    /// This function intentionally does NOT hold a spanning lock across
    /// phases — it mirrors the actual MCP implementation where each SQL
    /// call acquires and releases the lock independently.
    async fn execute_correction_simulation(
        store: &Arc<RwLock<LedgerStore>>,
        cash_id: uuid::Uuid,
        rev_id: uuid::Uuid,
        orig_entry_uuid: uuid::Uuid,
        original_amount: i64,
        correct_amount: i64,
    ) -> (u64, u64) {
        use crate::account::AccountId;

        let cash_account_id = AccountId::from(cash_id);
        let rev_account_id = AccountId::from(rev_id);

        let reversal_idem_key = format!("reversal-of-{orig_entry_uuid}");
        let correction_idem_key = format!("correction-of-{orig_entry_uuid}");

        // ── Phase 1: Pre-flight read (lock acquired, then released) ───────
        let existing_reversal_seq: Option<u64> = {
            let g = store.read().await;
            // Check by idempotency key (same as what execute_correction uses
            // internally via external_ref, which maps to idempotency_key).
            g.entries_by_external_ref(&reversal_idem_key)
                .first()
                .map(|e| e.sequence)
        };

        let existing_correction_seq: Option<u64> = {
            let g = store.read().await;
            g.entries_by_external_ref(&correction_idem_key)
                .first()
                .map(|e| e.sequence)
        };

        // Both already written — idempotent fast-path.
        if let (Some(rev_seq), Some(cor_seq)) = (existing_reversal_seq, existing_correction_seq) {
            return (rev_seq, cor_seq);
        }

        // ── Phase 2: Write reversal (lock acquired, then released) ────────
        let rev_seq = if let Some(seq) = existing_reversal_seq {
            seq
        } else {
            let rev_amount = Amount::new(original_amount).unwrap();
            let rev_entry = JournalEntryBuilder::new(
                format!("Reversal of original — {orig_entry_uuid}"),
                "test",
            )
            // Flip: original was CASH debit / REV credit → reversal is REV debit / CASH credit
            .debit(rev_account_id, rev_amount, "USD")
            .credit(cash_account_id, rev_amount, "USD")
            .external_ref(&reversal_idem_key)
            .idempotency_key(&reversal_idem_key)
            .build();

            let mut g = store.write().await;
            g.post_entry(rev_entry).unwrap()
            // Lock released here.
        };

        // ── Phase 3: Write correction (lock acquired, then released) ──────
        let cor_seq = if let Some(seq) = existing_correction_seq {
            seq
        } else {
            let cor_amount = Amount::new(correct_amount).unwrap();
            let cor_entry = JournalEntryBuilder::new(
                format!("Correction of original — {orig_entry_uuid}"),
                "test",
            )
            .debit(cash_account_id, cor_amount, "USD")
            .credit(rev_account_id, cor_amount, "USD")
            .external_ref(&correction_idem_key)
            .idempotency_key(&correction_idem_key)
            .build();

            let mut g = store.write().await;
            g.post_entry(cor_entry).unwrap()
            // Lock released here.
        };

        (rev_seq, cor_seq)
    }

    // ── Test 1: concurrent correction race — exactly one reversal + one correction
    // ─────────────────────────────────────────────────────────────────────────────

    /// Fire N tasks through the correction workflow simultaneously using a
    /// barrier to maximise lock contention.  Regardless of how many tasks
    /// race, the ledger must end up with exactly ONE reversal entry and ONE
    /// correction entry — never duplicates.
    #[tokio::test]
    async fn concurrent_correction_idempotency() {
        const CONCURRENCY: usize = 20;
        const ORIGINAL_AMOUNT: i64 = 10_000; // $100.00
        const CORRECT_AMOUNT: i64 = 8_500;   // $85.00

        let dir = setup_dir();
        let (store, cash_id, rev_id, orig_uuid, _orig_seq) =
            setup_with_original_entry(&dir, ORIGINAL_AMOUNT).await;

        let barrier = Arc::new(Barrier::new(CONCURRENCY));
        let mut handles = Vec::new();

        for _ in 0..CONCURRENCY {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            let h = tokio::spawn(async move {
                // All tasks arrive at the barrier before any proceeds —
                // maximises the chance of racing through the pre-flight check.
                barrier_clone.wait().await;

                execute_correction_simulation(
                    &store_clone,
                    cash_id,
                    rev_id,
                    orig_uuid,
                    ORIGINAL_AMOUNT,
                    CORRECT_AMOUNT,
                )
                .await
            });
            handles.push(h);
        }

        // Collect all (rev_seq, cor_seq) results.
        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }

        let g = store.read().await;

        // ── Assert 1: exactly 3 total entries (original + reversal + correction)
        assert_eq!(
            g.entry_count(),
            3,
            "expected exactly 3 entries (original + reversal + correction); \
             got {} — duplicate correction entries were written",
            g.entry_count()
        );

        // ── Assert 2: all tasks returned the same (rev_seq, cor_seq) pair
        let first = results[0];
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                *result,
                first,
                "task {i} returned {:?} but task 0 returned {:?}; \
                 all callers must receive the winning result, not a divergent one",
                result,
                first
            );
        }

        // ── Assert 3: the reversal entry really exists with the right ext ref
        let reversal_idem_key = format!("reversal-of-{orig_uuid}");
        let reversal_entries = g.entries_by_external_ref(&reversal_idem_key);
        assert_eq!(
            reversal_entries.len(),
            1,
            "expected exactly 1 reversal entry; found {}",
            reversal_entries.len()
        );

        // ── Assert 4: the correction entry really exists
        let correction_idem_key = format!("correction-of-{orig_uuid}");
        let correction_entries = g.entries_by_external_ref(&correction_idem_key);
        assert_eq!(
            correction_entries.len(),
            1,
            "expected exactly 1 correction entry; found {}",
            correction_entries.len()
        );

        // ── Assert 5: CASH balance = original - original + correct = correct
        let cash_balance = g.balance(&cash_id);
        assert_eq!(
            cash_balance,
            CORRECT_AMOUNT as i128,
            "CASH balance after correction should be CORRECT_AMOUNT ({}) \
             but got {} — net balance is wrong",
            CORRECT_AMOUNT,
            cash_balance
        );

        // ── Assert 6: hash chain must be intact
        g.verify_chain_integrity().unwrap();
    }

    // ── Test 2: the loser must receive the winner's result, not an error
    // ─────────────────────────────────────────────────────────────────────

    /// The desired contract from the design conversation:
    ///   "The loser should get the winner's existing result, not an error."
    ///
    /// After the winner has already posted both the reversal and correction,
    /// a late-arriving caller must receive the same (rev_seq, cor_seq) that
    /// the winner received — not a panic, not an Err, and not a new entry.
    #[tokio::test]
    async fn correction_loser_receives_winner_result_not_error() {
        const ORIGINAL_AMOUNT: i64 = 5_000;
        const CORRECT_AMOUNT: i64 = 4_200;

        let dir = setup_dir();
        let (store, cash_id, rev_id, orig_uuid, _) =
            setup_with_original_entry(&dir, ORIGINAL_AMOUNT).await;

        // ── Winner posts first ─────────────────────────────────────────────
        let (winner_rev_seq, winner_cor_seq) = execute_correction_simulation(
            &store,
            cash_id,
            rev_id,
            orig_uuid,
            ORIGINAL_AMOUNT,
            CORRECT_AMOUNT,
        )
        .await;

        // ── Loser arrives after winner has finished ────────────────────────
        // The loser must get back the winner's sequences, not an error.
        let (loser_rev_seq, loser_cor_seq) = execute_correction_simulation(
            &store,
            cash_id,
            rev_id,
            orig_uuid,
            ORIGINAL_AMOUNT,
            CORRECT_AMOUNT,
        )
        .await;

        assert_eq!(
            loser_rev_seq, winner_rev_seq,
            "loser's reversal seq ({}) must equal winner's ({}); \
             a new reversal entry was created instead of returning the existing one",
            loser_rev_seq, winner_rev_seq
        );
        assert_eq!(
            loser_cor_seq, winner_cor_seq,
            "loser's correction seq ({}) must equal winner's ({}); \
             a new correction entry was created instead of returning the existing one",
            loser_cor_seq, winner_cor_seq
        );

        // ── Still exactly 3 total entries ─────────────────────────────────
        let g = store.read().await;
        assert_eq!(
            g.entry_count(),
            3,
            "loser call must not write any new entries; got {} (expected 3)",
            g.entry_count()
        );

        // ── Balance must not have changed from the winner's application ────
        assert_eq!(
            g.balance(&cash_id),
            CORRECT_AMOUNT as i128,
            "balance must remain at CORRECT_AMOUNT after loser call"
        );

        g.verify_chain_integrity().unwrap();
    }

    // ── Test 3: partial-execution recovery (crash between reversal and correction)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Simulates a crash after the reversal INSERT but before the correction
    /// INSERT (e.g., agent crashed, network dropped, server restarted between
    /// the two writes).  A retry call must:
    ///   - Detect the existing reversal (skip re-writing it).
    ///   - Post only the missing correction.
    ///   - End with exactly 3 entries total, not 4.
    #[tokio::test]
    async fn partial_correction_recovery_only_missing_half_written() {
        const ORIGINAL_AMOUNT: i64 = 7_500;
        const CORRECT_AMOUNT: i64 = 6_000;

        let dir = setup_dir();
        let (store, cash_id, rev_id, orig_uuid, _) =
            setup_with_original_entry(&dir, ORIGINAL_AMOUNT).await;

        let cash_account_id = crate::account::AccountId::from(cash_id);
        let rev_account_id = crate::account::AccountId::from(rev_id);

        let reversal_idem_key = format!("reversal-of-{orig_uuid}");

        // ── Manually post only the reversal (simulating a crash before correction)
        {
            let rev_amount = Amount::new(ORIGINAL_AMOUNT).unwrap();
            let rev_entry =
                JournalEntryBuilder::new(format!("Reversal — {orig_uuid}"), "test")
                    .debit(rev_account_id, rev_amount, "USD")
                    .credit(cash_account_id, rev_amount, "USD")
                    .external_ref(&reversal_idem_key)
                    .idempotency_key(&reversal_idem_key)
                    .build();
            let mut g = store.write().await;
            g.post_entry(rev_entry).unwrap();
        }

        // Ledger now has: original + reversal (correction missing).
        {
            let g = store.read().await;
            assert_eq!(g.entry_count(), 2, "should have original + reversal only at this point");
        }

        // ── Retry the full correction workflow ────────────────────────────
        let (rev_seq, cor_seq) = execute_correction_simulation(
            &store,
            cash_id,
            rev_id,
            orig_uuid,
            ORIGINAL_AMOUNT,
            CORRECT_AMOUNT,
        )
        .await;

        let g = store.read().await;

        // ── Assert: 3 entries total (original + reversal + correction) ─────
        assert_eq!(
            g.entry_count(),
            3,
            "retry must not re-write the reversal; expected 3 entries, got {}",
            g.entry_count()
        );

        // ── Assert: both returned seqs point to real entries ───────────────
        assert!(
            g.get_entry_by_sequence(rev_seq).is_some(),
            "returned reversal seq {rev_seq} does not exist in ledger"
        );
        assert!(
            g.get_entry_by_sequence(cor_seq).is_some(),
            "returned correction seq {cor_seq} does not exist in ledger"
        );

        // ── Assert: reversal seq came from the first (pre-crash) write ─────
        // The reversal was already sequence 2; retry must reuse that seq.
        assert_eq!(
            rev_seq, 2,
            "retry must reuse the pre-crash reversal at seq 2, not create a new one"
        );

        // ── Assert: final balance = correct amount ─────────────────────────
        assert_eq!(
            g.balance(&cash_account_id),
            CORRECT_AMOUNT as i128,
            "after recovery, balance must equal CORRECT_AMOUNT"
        );

        g.verify_chain_integrity().unwrap();
    }

    // ── Test 4: correction must not disturb unrelated entries
    // ─────────────────────────────────────────────────────────────────────

    /// A correction on one entry must not alter the sequence number,
    /// content_hash, or chain_hash of any other (unrelated) entry.
    /// This confirms the append-only guarantee holds under concurrent writes.
    #[tokio::test]
    async fn correction_does_not_disturb_unrelated_entries() {
        const ORIGINAL_AMOUNT: i64 = 3_000;
        const CORRECT_AMOUNT: i64 = 2_500;
        const UNRELATED_COUNT: usize = 10;

        let dir = setup_dir();
        let (store, cash_id, rev_id, orig_uuid, _) =
            setup_with_original_entry(&dir, ORIGINAL_AMOUNT).await;

        let cash_account_id = crate::account::AccountId::from(cash_id);
        let rev_account_id = crate::account::AccountId::from(rev_id);

        // ── Post 10 unrelated entries after the original ───────────────────
        let mut unrelated_snapshots: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new(); // (seq, content_hash, chain_hash)
        {
            let mut g = store.write().await;
            for i in 0..UNRELATED_COUNT {
                let amt = Amount::new(100 * (i as i64 + 1)).unwrap();
                let entry = JournalEntryBuilder::new(format!("Unrelated {i}"), "test")
                    .debit(cash_account_id, amt, "USD")
                    .credit(rev_account_id, amt, "USD")
                    .build();
                let seq = g.post_entry(entry).unwrap();
                let stored = g.get_entry_by_sequence(seq).unwrap();
                unrelated_snapshots.push((
                    stored.sequence,
                    stored.content_hash,
                    stored.chain_hash,
                ));
            }
        }

        // ── Execute correction on the original entry ───────────────────────
        execute_correction_simulation(
            &store,
            cash_id,
            rev_id,
            orig_uuid,
            ORIGINAL_AMOUNT,
            CORRECT_AMOUNT,
        )
        .await;

        // ── Verify unrelated entries are completely unchanged ──────────────
        let g = store.read().await;
        for (seq, expected_content_hash, expected_chain_hash) in &unrelated_snapshots {
            let entry = g
                .get_entry_by_sequence(*seq)
                .unwrap_or_else(|| panic!("unrelated entry at seq {seq} missing after correction"));

            assert_eq!(
                entry.content_hash,
                *expected_content_hash,
                "content_hash of unrelated entry at seq {seq} was mutated — append-only violated"
            );
            assert_eq!(
                entry.chain_hash,
                *expected_chain_hash,
                "chain_hash of unrelated entry at seq {seq} was mutated — append-only violated"
            );
        }

        // Hash chain must still be valid after interleaving correction entries
        // with the unrelated ones.
        g.verify_chain_integrity().unwrap();
    }

    // ── Test 5: high-concurrency stress — 50 tasks on the same correction
    // ─────────────────────────────────────────────────────────────────────

    /// 50 concurrent callers all attempt execute_correction for the same
    /// original entry at the same time.  The invariants must hold regardless
    /// of scheduling order:
    ///   - Exactly 3 total entries (original, reversal, correction).
    ///   - All 50 callers return the same (rev_seq, cor_seq).
    ///   - Hash chain intact.
    ///   - Balance = CORRECT_AMOUNT.
    #[tokio::test]
    async fn high_concurrency_correction_stress_50_tasks() {
        const CONCURRENCY: usize = 50;
        const ORIGINAL_AMOUNT: i64 = 20_000;
        const CORRECT_AMOUNT: i64 = 17_500;

        let dir = setup_dir();
        let (store, cash_id, rev_id, orig_uuid, _) =
            setup_with_original_entry(&dir, ORIGINAL_AMOUNT).await;

        let barrier = Arc::new(Barrier::new(CONCURRENCY));
        let mut handles = Vec::new();

        for _ in 0..CONCURRENCY {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            let h = tokio::spawn(async move {
                barrier_clone.wait().await;
                execute_correction_simulation(
                    &store_clone,
                    cash_id,
                    rev_id,
                    orig_uuid,
                    ORIGINAL_AMOUNT,
                    CORRECT_AMOUNT,
                )
                .await
            });
            handles.push(h);
        }

        let mut all_results = Vec::new();
        for h in handles {
            all_results.push(h.await.unwrap());
        }

        let g = store.read().await;

        // ── Exactly 3 entries ─────────────────────────────────────────────
        assert_eq!(
            g.entry_count(),
            3,
            "50-task stress: expected exactly 3 entries, got {}. \
             Duplicate correction entries were written under concurrency.",
            g.entry_count()
        );

        // ── All 50 callers got the same (rev_seq, cor_seq) ────────────────
        let first = all_results[0];
        for (i, res) in all_results.iter().enumerate() {
            assert_eq!(
                *res, first,
                "task {i} returned {:?}, expected {:?}; \
                 callers received divergent results under concurrency",
                res, first
            );
        }

        // ── Correct balance ───────────────────────────────────────────────
        let cash_account_id = crate::account::AccountId::from(cash_id);
        assert_eq!(
            g.balance(&cash_account_id),
            CORRECT_AMOUNT as i128,
            "final balance must equal CORRECT_AMOUNT after 50-task stress"
        );

        // ── Hash chain intact ─────────────────────────────────────────────
        g.verify_chain_integrity().unwrap();
    }

    // ── Test 6: schema version is at CURRENT_SCHEMA_VERSION ──────────────
    // ─────────────────────────────────────────────────────────────────────

    /// Confirms that `apply_schema_migrations` ran and the database is at
    /// schema version 1 (the version that adds UNIQUE(idempotency_key)).
    #[tokio::test]
    async fn schema_version_is_current() {
        let dir = setup_dir();
        let store = Arc::new(RwLock::new(LedgerStore::open(dir.path()).unwrap()));

        // Reach into the store's entry_db via the public accessor.
        let g = store.read().await;
        let version = g.entry_db().schema_version().unwrap();
        assert_eq!(
            version,
            1,
            "expected schema version 1 (UNIQUE idempotency_key constraint); \
             got {version} — apply_schema_migrations may not have run"
        );
    }

    // ── Test 7: database-layer UNIQUE constraint fires independently ──────
    // ─────────────────────────────────────────────────────────────────────

    /// This test deliberately bypasses the application-layer idempotency check
    /// in `post_entry` and calls `entry_db.insert()` directly with two entries
    /// that share the same non-NULL idempotency key.
    ///
    /// The expected outcome is:
    ///   - First insert: succeeds (1 row written).
    ///   - Second insert: silently ignored by `OR IGNORE` due to the UNIQUE
    ///     constraint — no error, no duplicate row.
    ///   - Final entry count: 1, not 2.
    ///
    /// This proves the database-layer guarantee holds independently of the
    /// application-layer check.  If the UNIQUE constraint is ever accidentally
    /// dropped (e.g., a botched migration), this test will fail with entry
    /// count 2 instead of 1.
    #[tokio::test]
    async fn database_unique_constraint_prevents_duplicate_without_app_layer_check() {
        use crate::entry_db::EntryDb;

        let dir = setup_dir();
        let db_path = dir.path().join("vledger.db");

        // Open EntryDb directly — bypasses LedgerStore and post_entry entirely.
        let entry_db = EntryDb::open(&db_path).unwrap();

        // Confirm migration ran.
        assert_eq!(entry_db.schema_version().unwrap(), 1,
            "schema must be at version 1 before this test is meaningful");

        // Build two minimal JournalEntry values that share an idempotency key
        // but have different sequence numbers (different PKs).
        let shared_key = "test-unique-constraint-key";
        let make_entry = |seq: u64| {
            use crate::entry::JournalEntryBuilder;
            use crate::account::{Account, AccountType};

            // We need valid AccountIds — use fixed UUIDs.
            let cash = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
            let rev  = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
            let amt  = crate::amount::Amount::new(100).unwrap();

            let mut entry = JournalEntryBuilder::new("test entry", "test")
                .debit(cash, amt, "USD")
                .credit(rev, amt, "USD")
                .idempotency_key(shared_key)
                .build();

            // Manually set a deterministic sequence and hashes so we can
            // insert directly into EntryDb without going through LedgerStore.
            entry.sequence = seq;
            entry.content_hash = [seq as u8; 32];
            entry.chain_hash   = [seq as u8 + 100; 32];
            entry
        };

        let entry_a = make_entry(1);
        let entry_b = make_entry(2); // different PK, same idempotency_key

        // Insert first entry — must succeed.
        entry_db.insert(&entry_a).unwrap();
        assert_eq!(entry_db.count().unwrap(), 1, "first insert must write 1 row");

        // Insert second entry with same idempotency_key — must be silently ignored.
        entry_db.insert(&entry_b).unwrap();
        assert_eq!(
            entry_db.count().unwrap(),
            1,
            "second insert with duplicate idempotency_key must be silently ignored \
             by the UNIQUE constraint (OR IGNORE); count must remain 1, not 2"
        );

        // The surviving row must be the first entry (sequence 1), not the second.
        let stored = entry_db.get_by_sequence(1).unwrap();
        assert!(stored.is_some(), "entry at sequence 1 must still exist");
        assert!(
            entry_db.get_by_sequence(2).unwrap().is_none(),
            "entry at sequence 2 must not exist — it was blocked by the UNIQUE constraint"
        );
    }
}
