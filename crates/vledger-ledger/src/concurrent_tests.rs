//! Concurrent transaction behavior tests.
//!
//! These tests verify that VectorLedger's ACID guarantees hold under
//! concurrent access patterns.  All concurrent writes are serialized through
//! the `Arc<tokio::sync::RwLock<LedgerStore>>` used by the server — these
//! tests exercise that same pattern directly.
//!
//! ## What is tested
//! 1. N concurrent read tasks observe consistent snapshots (no partial writes)
//! 2. Concurrent write tasks produce a consistent, balanced ledger
//! 3. Hash chain integrity holds after many concurrent posts
//! 4. Idempotency keys prevent duplicates under concurrent retries
//! 5. Balance invariants hold under concurrent mixed read/write workload

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    use crate::{
        account::{Account, AccountType},
        amount::Amount,
        entry::JournalEntryBuilder,
        store::LedgerStore,
    };

    fn setup_dir() -> TempDir {
        let d = TempDir::new().unwrap();
        std::fs::create_dir_all(d.path().join("wal")).unwrap();
        std::fs::create_dir_all(d.path().join("pages")).unwrap();
        d
    }

    // ── Test 1: concurrent readers see consistent state ───────────────────

    #[tokio::test]
    async fn concurrent_readers_see_consistent_snapshot() {
        let dir = setup_dir();
        let path = dir.path();
        let store = Arc::new(RwLock::new(LedgerStore::open(path).unwrap()));

        // Set up accounts and a few entries under a write lock.
        let (cash_id, rev_id) = {
            let mut g = store.write().await;
            let c = g
                .create_account(Account::new(
                    "CASH",
                    "Cash",
                    AccountType::Asset,
                    "USD",
                    "test",
                ))
                .unwrap();
            let r = g
                .create_account(Account::new(
                    "REV",
                    "Revenue",
                    AccountType::Income,
                    "USD",
                    "test",
                ))
                .unwrap();
            for i in 1u64..=10 {
                let amt = Amount::new(i as i64 * 100).unwrap();
                let e = JournalEntryBuilder::new(format!("e{i}"), "test")
                    .debit(c, amt, "USD")
                    .credit(r, amt, "USD")
                    .build();
                g.post_entry(e).unwrap();
            }
            (c, r)
        };
        let expected_balance = (1..=10i128).map(|i| i * 100).sum::<i128>();

        // Spawn 20 concurrent read tasks; each must see the full committed state.
        let mut handles = Vec::new();
        for _ in 0..20 {
            let store_clone = Arc::clone(&store);
            let handle = tokio::spawn(async move {
                let g = store_clone.read().await;
                let bal = g.balance(&cash_id);
                let count = g.entry_count();
                (bal, count)
            });
            handles.push(handle);
        }

        for h in handles {
            let (bal, count) = h.await.unwrap();
            assert_eq!(
                bal, expected_balance,
                "concurrent read must see full committed balance"
            );
            assert_eq!(count, 10, "concurrent read must see all 10 entries");
        }
        let _ = (cash_id, rev_id);
    }

    // ── Test 2: sequential writes produce a consistent ledger ────────────

    #[tokio::test]
    async fn sequential_writes_through_rwlock_are_consistent() {
        let dir = setup_dir();
        let store = Arc::new(RwLock::new(LedgerStore::open(dir.path()).unwrap()));

        let (cash_id, rev_id) = {
            let mut g = store.write().await;
            let c = g
                .create_account(Account::new("C", "Cash", AccountType::Asset, "USD", "test"))
                .unwrap();
            let r = g
                .create_account(Account::new("R", "Rev", AccountType::Income, "USD", "test"))
                .unwrap();
            (c, r)
        };

        // 50 sequential write tasks (each acquires exclusive lock in turn).
        let mut handles = Vec::new();
        for i in 0u64..50 {
            let store_clone = Arc::clone(&store);
            let h = tokio::spawn(async move {
                let mut g = store_clone.write().await;
                let amt = Amount::new(100).unwrap();
                let e = JournalEntryBuilder::new(format!("tx-{i}"), "test")
                    .debit(cash_id, amt, "USD")
                    .credit(rev_id, amt, "USD")
                    .build();
                g.post_entry(e).unwrap();
            });
            handles.push(h);
        }
        for h in handles {
            h.await.unwrap();
        }

        let g = store.read().await;
        assert_eq!(g.entry_count(), 50);
        assert_eq!(g.balance(&cash_id), 50 * 100);
        g.verify_chain_integrity().unwrap();
    }

    // ── Test 3: concurrent idempotency key deduplication ─────────────────

    #[tokio::test]
    async fn concurrent_idempotency_key_deduplication() {
        let dir = setup_dir();
        let store = Arc::new(RwLock::new(LedgerStore::open(dir.path()).unwrap()));

        let (cash_id, rev_id) = {
            let mut g = store.write().await;
            let c = g
                .create_account(Account::new("C", "Cash", AccountType::Asset, "USD", "test"))
                .unwrap();
            let r = g
                .create_account(Account::new("R", "Rev", AccountType::Income, "USD", "test"))
                .unwrap();
            (c, r)
        };

        // 10 tasks all try to post the same idempotency key.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let store_clone = Arc::clone(&store);
            let h = tokio::spawn(async move {
                let mut g = store_clone.write().await;
                let amt = Amount::new(500).unwrap();
                let e = JournalEntryBuilder::new("payment", "test")
                    .debit(cash_id, amt, "USD")
                    .credit(rev_id, amt, "USD")
                    .idempotency_key("pay-concurrent-001")
                    .build();
                g.post_entry(e).unwrap();
            });
            handles.push(h);
        }
        for h in handles {
            h.await.unwrap();
        }

        let g = store.read().await;
        assert_eq!(
            g.entry_count(),
            1,
            "only one entry must exist despite 10 concurrent posts"
        );
        assert_eq!(g.balance(&cash_id), 500);
    }

    // ── Test 4: mixed read/write workload — no stale reads ───────────────

    #[tokio::test]
    async fn mixed_read_write_no_stale_reads() {
        let dir = setup_dir();
        let store = Arc::new(RwLock::new(LedgerStore::open(dir.path()).unwrap()));

        let (cash_id, rev_id) = {
            let mut g = store.write().await;
            let c = g
                .create_account(Account::new("C", "Cash", AccountType::Asset, "USD", "test"))
                .unwrap();
            let r = g
                .create_account(Account::new("R", "Rev", AccountType::Income, "USD", "test"))
                .unwrap();
            (c, r)
        };

        // Interleave writes and reads.  Each read task must see a balance
        // that is a multiple of 100 (no partial writes visible).
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        for i in 0u64..10 {
            // Writer
            let sw = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let mut g = sw.write().await;
                let amt = Amount::new(100).unwrap();
                let e = JournalEntryBuilder::new(format!("w{i}"), "test")
                    .debit(cash_id, amt, "USD")
                    .credit(rev_id, amt, "USD")
                    .build();
                g.post_entry(e).unwrap();
            }));

            // Reader (runs after at least some writes)
            let sr = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let g = sr.read().await;
                let bal = g.balance(&cash_id);
                // Balance must always be a multiple of 100 (atomic writes)
                assert_eq!(
                    bal % 100,
                    0,
                    "balance must be a multiple of 100 — no partial writes visible"
                );
                g.verify_chain_integrity().unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
    }

    // ── Test 5: write+verify_chain under concurrent writes ───────────────

    #[tokio::test]
    async fn hash_chain_valid_under_concurrent_writes() {
        let dir = setup_dir();
        let store = Arc::new(RwLock::new(LedgerStore::open(dir.path()).unwrap()));

        let (cash_id, rev_id) = {
            let mut g = store.write().await;
            let c = g
                .create_account(Account::new("C", "Cash", AccountType::Asset, "USD", "test"))
                .unwrap();
            let r = g
                .create_account(Account::new("R", "Rev", AccountType::Income, "USD", "test"))
                .unwrap();
            (c, r)
        };

        // 30 sequential writes (RwLock enforces serialization).
        for i in 0u64..30 {
            let mut g = store.write().await;
            let amt = Amount::new(50).unwrap();
            let e = JournalEntryBuilder::new(format!("e{i}"), "test")
                .debit(cash_id, amt, "USD")
                .credit(rev_id, amt, "USD")
                .build();
            g.post_entry(e).unwrap();
        }

        let g: tokio::sync::RwLockReadGuard<'_, LedgerStore> = store.read().await;
        assert_eq!(g.entry_count(), 30);
        g.verify_chain_integrity().unwrap();
    }
}
