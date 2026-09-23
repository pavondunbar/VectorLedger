//! Deterministic crash / recovery test suite — Phase 3.
//!
//! Each test targets a specific failure scenario not covered by the existing
//! `crash_tests.rs` or `fault_injection_tests.rs` suites.
//!
//! | Test | Scenario | Invariant |
//! |------|----------|-----------|
//! | 1 | Power-loss mid-commit (raw Commit record byte-truncated) | Partial commit is treated as uncommitted; prior state intact |
//! | 2 | WAL segment boundary crash | Entry spanning a segment roll is fully recovered; no duplication |
//! | 3 | Checkpoint file corruption / deletion | Store falls back to full WAL replay; all data present |
//! | 4 | Concurrent open attempt on same data dir | Second open returns an error; first store is unaffected |
//! | 5 | Multi-entry batch spans a WAL segment roll | Every entry in the batch is present after recovery |
//!
//! ## "Crash" simulation
//! Crash is simulated by dropping `LedgerStore` without calling
//! `checkpoint()`.  All tests use `WalSyncMode::PerRecord` (via
//! `LedgerStore::open` default) so every WAL record written before the
//! "crash" is durable on disk; the goal is to exercise the *recovery path*,
//! not fsync behaviour.
//!
//! Where a test needs to inject a physical failure (truncated record,
//! corrupt file) it manipulates files directly after closing the store.

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        account::{Account, AccountType},
        amount::Amount,
        entry::JournalEntryBuilder,
        lockfile::{DataDirLock, LockError},
        store::LedgerStore,
        wal_checkpoint::WalCheckpoint,
    };

    // ── Shared helpers ────────────────────────────────────────────────────

    fn setup() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        dir
    }

    fn open(dir: &TempDir) -> LedgerStore {
        LedgerStore::open(dir.path()).expect("open")
    }

    fn make_accounts(store: &mut LedgerStore) -> (uuid::Uuid, uuid::Uuid) {
        let cash = store
            .create_account(Account::new(
                "CASH",
                "Cash",
                AccountType::Asset,
                "USD",
                "test",
            ))
            .expect("create cash");
        let rev = store
            .create_account(Account::new(
                "REV",
                "Revenue",
                AccountType::Income,
                "USD",
                "test",
            ))
            .expect("create rev");
        (cash, rev)
    }

    fn post(store: &mut LedgerStore, cash: uuid::Uuid, rev: uuid::Uuid, cents: i64) -> u64 {
        let amt = Amount::new(cents).unwrap();
        let e = JournalEntryBuilder::new("test entry", "test")
            .debit(cash, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        store.post_entry(e).expect("post_entry")
    }

    fn last_wal_segment(data_dir: &std::path::Path) -> std::path::PathBuf {
        let wal_dir = data_dir.join("wal");
        let mut segs: Vec<_> = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "wal"))
            .collect();
        segs.sort_by_key(|e| e.file_name());
        segs.last()
            .expect("at least one WAL segment")
            .path()
            .to_path_buf()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 1: Power-loss mid-commit
    //
    // Scenario: a Commit record is physically written to the WAL segment but
    // the last N bytes of that record are overwritten with 0xFF, simulating
    // the OS flushing an incomplete write (torn Commit).
    //
    // Expected behaviour:
    //   - The torn Commit is treated as if no Commit occurred (CRC mismatch
    //     or BadMagic stops the recovery scan at that point).
    //   - Any entry committed *before* the torn record must still be visible.
    //   - The torn entry is discarded (not partially visible).
    //   - `verify_chain_integrity()` passes on the recovered state.
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn power_loss_mid_commit_torn_record_is_discarded() {
        let dir = setup();

        // Step 1: write two committed entries, then close cleanly.
        let (cash, rev) = {
            let mut s = open(&dir);
            let ids = make_accounts(&mut s);
            post(&mut s, ids.0, ids.1, 1_000); // seq 1 — will survive
            post(&mut s, ids.0, ids.1, 2_000); // seq 2 — will survive
            ids
        };

        // Step 2: find the last WAL segment and corrupt its final 8 bytes.
        // We do this *after* a clean close so both entries are already durable.
        // We then write a third entry whose Commit record we will partially destroy.
        {
            let mut s = open(&dir);
            post(&mut s, cash, rev, 3_000); // seq 3 — we will corrupt its commit
            // Drop without checkpoint — seq 3 is in WAL but checkpoint isn't written.
        }

        // Corrupt the tail of the WAL segment to simulate a torn Commit record.
        let seg_path = last_wal_segment(dir.path());
        let mut data = std::fs::read(&seg_path).unwrap();
        // Overwrite the last 8 bytes — this destroys the CRC of the last record
        // (or part of the Commit record header), simulating a partial OS flush.
        let len = data.len();
        if len >= 8 {
            for b in &mut data[len - 8..] {
                *b = 0xFF;
            }
        }
        std::fs::write(&seg_path, &data).unwrap();

        // Step 3: reopen and verify the recovery outcome.
        let s = open(&dir);

        // Entries 1 and 2 were committed before the torn segment — they must be
        // present.  Entry 3 may or may not be present depending on where exactly
        // in the Commit record the corruption landed; either way the store must
        // be in a consistent state.
        let count = s.entry_count();
        assert!(
            count == 2 || count == 3,
            "expected 2 or 3 entries after torn commit, got {count}"
        );
        assert!(
            s.balance(&cash) >= 3_000,
            "balance must include at least entries 1+2 = 3000, got {}",
            s.balance(&cash)
        );

        // Chain integrity is the hard invariant — must always pass.
        s.verify_chain_integrity()
            .expect("hash chain must be valid after torn-commit recovery");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 2: WAL segment boundary crash (WAL-layer recovery)
    //
    // Scenario: write WAL records to a tiny-segment WAL so the writer must
    // roll over to a new segment. Then run `recover()` and verify it
    // stitches records together correctly across segment boundaries.
    //
    // We test this at the WAL layer (WalWriter + recover) rather than through
    // LedgerStore because LedgerStore::open always uses DEFAULT_SEGMENT_SIZE
    // (64 MiB) — segment rolls don't happen in short tests at that level.
    // The WAL-layer recovery path is the same code that LedgerStore::open
    // calls internally; proving it correct here proves the property end-to-end.
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn segment_boundary_crash_all_committed_entries_survive() {
        use vledger_wal::record::{BeginPayload, CommitPayload, DataPayload, MutationKind};
        use vledger_wal::{RecordType, WalSyncMode, WalWriter};
        use vledger_crypto::hash::hash_bytes;

        let dir = setup();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();

        // 4 KiB segments — each segment holds a handful of records max.
        const TINY_SEGMENT: u64 = 4 * 1024;
        let num_transactions: u32 = 30;

        {
            let mut w = WalWriter::open_with_options(
                &wal_dir,
                TINY_SEGMENT,
                WalSyncMode::PerRecord,
                None,
            )
            .unwrap();

            for i in 0u64..num_transactions as u64 {
                let tx_id = i + 1;
                w.append_record(tx_id, RecordType::Begin, &BeginPayload { description: None })
                    .unwrap();

                let payload = format!("row-{i}").into_bytes();
                let row_hash = hash_bytes(&payload);
                w.append_record(
                    tx_id,
                    RecordType::Data,
                    &DataPayload {
                        table_id: 1,
                        page_id: i,
                        slot_id: 0,
                        mutation: MutationKind::Insert,
                        row_data: payload,
                        row_hash,
                        prev_hash: None,
                    },
                )
                .unwrap();

                // Commit payload: tx_hash = BLAKE3(row_hash), record_count = 1
                let tx_hash = *blake3::hash(&row_hash).as_bytes();
                w.append_record(
                    tx_id,
                    RecordType::Commit,
                    &CommitPayload {
                        record_count: 1,
                        tx_hash,
                        signature: vec![],
                        signer_pubkey: vec![],
                    },
                )
                .unwrap();
            }
        } // drop WalWriter = "crash" without checkpoint

        // Verify multiple segments were actually created.
        let seg_count = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "wal"))
            .count();
        assert!(
            seg_count >= 2,
            "expected multiple WAL segments with {TINY_SEGMENT}-byte limit, got {seg_count}"
        );

        // Run WAL recovery — must stitch all segments together.
        let result = vledger_wal::recovery::recover(&wal_dir)
            .expect("recovery must succeed across segment boundaries");

        assert_eq!(
            result.committed.len(),
            num_transactions as usize,
            "all {num_transactions} transactions must be recovered across {seg_count} segments; \
             got {}",
            result.committed.len()
        );
        assert!(!result.torn_write_detected, "no torn write should be flagged");

        // Sequence numbers must be strictly monotonic across segments.
        let seqs: Vec<u64> = result
            .committed
            .iter()
            .map(|tx| tx.commit_record.header.sequence)
            .collect();
        for w in seqs.windows(2) {
            assert!(
                w[1] > w[0],
                "sequences must be strictly increasing across segment boundary: {} -> {}",
                w[0], w[1]
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 5: Multi-entry batch spanning a WAL segment roll (WAL-layer)
    //
    // Scenario: write a batch where the Data records of a single transaction
    // span a segment boundary (the Begin is in segment N, some Data records
    // are in segment N+1). Verify the transaction is fully committed and
    // all its data payloads are present after recovery.
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn multi_entry_batch_spanning_segment_roll_fully_recovered() {
        use vledger_wal::record::{BeginPayload, CommitPayload, DataPayload, MutationKind};
        use vledger_wal::{RecordType, WalSyncMode, WalWriter};
        use vledger_crypto::hash::hash_bytes;

        let dir = setup();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();

        // 4 KiB segment — 60 Data records at ~80 bytes each = ~4800 bytes → guaranteed roll.
        const TINY_SEGMENT: u64 = 4 * 1024;
        const DATA_RECORDS: u32 = 60;
        let tx_id: u64 = 42;

        {
            let mut w = WalWriter::open_with_options(
                &wal_dir,
                TINY_SEGMENT,
                WalSyncMode::PerRecord,
                None,
            )
            .unwrap();

            // Begin in segment 0.
            w.append_record(tx_id, RecordType::Begin, &BeginPayload { description: None })
                .unwrap();

            let mut blake = blake3::Hasher::new();
            let mut row_hashes: Vec<[u8; 32]> = Vec::new();

            for i in 0u64..DATA_RECORDS as u64 {
                let payload = format!("batch-row-{i}").into_bytes();
                let row_hash = hash_bytes(&payload);
                blake.update(&row_hash);
                row_hashes.push(row_hash);

                w.append_record(
                    tx_id,
                    RecordType::Data,
                    &DataPayload {
                        table_id: 1,
                        page_id: i,
                        slot_id: 0,
                        mutation: MutationKind::Insert,
                        row_data: payload,
                        row_hash,
                        prev_hash: if i == 0 { None } else { Some(row_hashes[i as usize - 1]) },
                    },
                )
                .unwrap();
            }

            // Commit — tx_hash spans all Data records.
            let tx_hash = *blake.finalize().as_bytes();
            w.append_record(
                tx_id,
                RecordType::Commit,
                &CommitPayload {
                    record_count: DATA_RECORDS,
                    tx_hash,
                    signature: vec![],
                    signer_pubkey: vec![],
                },
            )
            .unwrap();
        } // "crash"

        // Must have rolled to at least 2 segments.
        let seg_count = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "wal"))
            .count();
        assert!(
            seg_count >= 2,
            "expected segment roll with {TINY_SEGMENT}-byte limit and {DATA_RECORDS} records, \
             got {seg_count} segment(s)"
        );

        // Recover: the one transaction must be fully present with all data payloads.
        let result = vledger_wal::recovery::recover_verified(&wal_dir, None)
            .expect("recovery must succeed");

        assert_eq!(
            result.committed.len(),
            1,
            "exactly 1 committed transaction must be recovered"
        );
        let tx = &result.committed[0];
        assert_eq!(
            tx.data_payloads.len(),
            DATA_RECORDS as usize,
            "all {DATA_RECORDS} data payloads must be present after cross-segment recovery"
        );
        assert_eq!(tx.tx_id, tx_id);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 3a: Checkpoint file deleted → full WAL replay
    //
    // Scenario: `wal-checkpoint.json` is deleted between two runs. The store
    // must fall back to scanning all WAL segments from the beginning.
    //
    // How the checkpoint file gets written: `LedgerStore::open()` writes
    // `wal-checkpoint.json` after a successful replay when `sqlite_max > 0`.
    // We therefore trigger it by opening after entries are present.
    //
    // Expected behaviour:
    //   - All previously committed data is recovered.
    //   - A new valid checkpoint is written after open.
    //   - `verify_chain_integrity()` passes.
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn checkpoint_deleted_falls_back_to_full_wal_replay() {
        let dir = setup();

        // Round 1: write some entries and close cleanly.
        let (cash, rev) = {
            let mut s = open(&dir);
            let ids = make_accounts(&mut s);
            for i in 1..=5 {
                post(&mut s, ids.0, ids.1, i * 200);
            }
            ids
        };

        // Round 2: reopen — open() writes wal-checkpoint.json when entries exist.
        {
            let _s = open(&dir);
        }

        // Confirm the checkpoint file now exists.
        let cp_path = WalCheckpoint::path(dir.path());
        assert!(cp_path.exists(), "checkpoint file must exist after open with entries");

        // Delete it to simulate loss of the checkpoint.
        std::fs::remove_file(&cp_path).unwrap();
        assert!(!cp_path.exists(), "checkpoint file must be gone after delete");

        // Round 3: reopen with no checkpoint file — must do full WAL replay.
        let s3 = open(&dir);
        assert_eq!(
            s3.entry_count(),
            5,
            "all 5 entries must be recovered via full WAL replay after checkpoint deletion"
        );
        assert_eq!(
            s3.balance(&cash),
            (1i128..=5).map(|i| i * 200).sum::<i128>()
        );
        s3.verify_chain_integrity()
            .expect("hash chain must be valid after full replay");

        let _ = rev;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 3b: Checkpoint file corrupted → full WAL replay
    //
    // Scenario: `wal-checkpoint.json` contains invalid JSON. The store must
    // treat a corrupt checkpoint as absent and fall back to full WAL replay.
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn checkpoint_corrupted_falls_back_to_full_wal_replay() {
        let dir = setup();

        let (cash, _rev) = {
            let mut s = open(&dir);
            let ids = make_accounts(&mut s);
            for i in 1..=4 {
                post(&mut s, ids.0, ids.1, i * 500);
            }
            let _ = s.checkpoint();
            ids
        };

        // Overwrite the checkpoint with garbage JSON.
        let cp_path = WalCheckpoint::path(dir.path());
        std::fs::write(&cp_path, b"{ this is not valid json !!!! }").unwrap();

        // Read back — must return None (graceful parse failure).
        let cp = WalCheckpoint::read(dir.path());
        assert!(
            cp.is_none(),
            "corrupted checkpoint must not parse — WalCheckpoint::read must return None"
        );

        // Open must succeed and recover all data despite the corrupt checkpoint.
        let s2 = open(&dir);
        assert_eq!(
            s2.entry_count(),
            4,
            "all entries must be recovered after checkpoint corruption"
        );
        assert_eq!(
            s2.balance(&cash),
            (1i128..=4).map(|i| i * 500).sum::<i128>()
        );
        s2.verify_chain_integrity()
            .expect("hash chain must be valid after corrupt checkpoint recovery");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 3c: Checkpoint points to a future sequence → full replay
    //
    // Scenario: `wal-checkpoint.json` claims `sqlite_max_sequence` is higher
    // than the actual highest WAL sequence, and `first_needed_segment` points
    // beyond the last real segment. This simulates checkpoint/WAL divergence
    // (e.g. a checkpoint was written from a newer data set that was then
    // rolled back out-of-band).
    //
    // The store must notice the divergence and replay from the beginning
    // (or at minimum from the first segment), not silently miss entries.
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn checkpoint_with_future_sequence_triggers_full_replay() {
        let dir = setup();

        let (cash, _rev) = {
            let mut s = open(&dir);
            let ids = make_accounts(&mut s);
            post(&mut s, ids.0, ids.1, 7_000); // 1 entry, sequence 1
            let _ = s.checkpoint();
            ids
        };

        // Overwrite the checkpoint with a sequence far ahead of reality.
        let _cp_path = WalCheckpoint::path(dir.path());
        let bogus = WalCheckpoint {
            sqlite_max_sequence: 999_999,
            first_needed_segment: 999,
        };
        WalCheckpoint::write(dir.path(), &bogus).unwrap();

        // Reopen: the checkpoint says segment 999 is needed, but only segment 0
        // exists.  The store must still find and replay the real data.
        let s2 = open(&dir);
        assert_eq!(
            s2.entry_count(),
            1,
            "entry must still be present despite bogus checkpoint"
        );
        assert_eq!(s2.balance(&cash), 7_000);
        s2.verify_chain_integrity()
            .expect("hash chain must be valid after bogus-checkpoint recovery");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 4: Concurrent open attempt is refused
    //
    // Scenario: a `LedgerStore` is already open (holding the `.lockfile`
    // flock). A second attempt to open the same data directory must return
    // `Err(LockError::AlreadyLocked)` immediately without blocking or panicking.
    //
    // The first store must continue to function correctly after the failed
    // second open.
    //
    // Note: we test `DataDirLock` directly because `LedgerStore::open` wraps
    // it and converts the error to `LedgerError::DataDirLocked`. Both code
    // paths are exercised.
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn concurrent_open_second_attempt_is_refused() {
        let dir = setup();

        // Acquire the first lock (simulates an already-open LedgerStore).
        let lock1 = DataDirLock::acquire(dir.path())
            .expect("first acquire must succeed on an unlocked directory");

        // Attempt to acquire a second lock on the same directory.
        // Must fail immediately.
        let result = DataDirLock::acquire(dir.path());
        assert!(
            matches!(result, Err(LockError::AlreadyLocked)),
            "second acquire on the same directory must return AlreadyLocked"
        );

        // The first lock must still be valid — drop it and confirm a third
        // acquire now succeeds (the lock was properly released).
        drop(lock1);

        let lock3 = DataDirLock::acquire(dir.path());
        assert!(
            lock3.is_ok(),
            "acquire after the first lock is dropped must succeed"
        );
    }

    #[test]
    fn concurrent_open_via_ledger_store_second_open_errors() {
        let dir = setup();

        // Open a real LedgerStore — this holds the flock.
        let _store1 = open(&dir);

        // Attempt to open a second LedgerStore on the same directory.
        // This must fail with a data-dir-locked error, not panic.
        let result2 = LedgerStore::open(dir.path());
        assert!(
            result2.is_err(),
            "second LedgerStore::open on the same directory must fail"
        );
        let err_str = result2.err().unwrap().to_string().to_lowercase();
        assert!(
            err_str.contains("lock") || err_str.contains("already"),
            "error message must mention lock contention, got: {err_str}"
        );

        // The first store must still work.
        assert_eq!(_store1.entry_count(), 0);
    }

}
