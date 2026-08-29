//! Proptest-driven financial invariant tests.
//!
//! These tests use `proptest` to generate thousands of randomized transaction
//! sequences and verify that core accounting invariants hold for every
//! generated input.  Unlike the deterministic `invariant_tests.rs`, these
//! tests exercise the ledger with inputs the author did not anticipate.
//!
//! ## Invariants verified
//!
//! | ID    | Invariant |
//! |-------|-----------|
//! | P-INV-1 | `SUM(debits) == SUM(credits)` across all entries at all times |
//! | P-INV-2 | `balance(account) == Σ(debit_lines) - Σ(credit_lines)` for every account |
//! | P-INV-3 | Idempotency: posting the same key N times produces exactly 1 entry |
//! | P-INV-4 | Sequence numbers are strictly monotonic with no gaps |
//! | P-INV-5 | BLAKE3 hash chain is valid after any sequence of posts |
//! | P-INV-6 | `original + reversal(original)` nets to zero balance impact |
//! | P-INV-7 | WAL replay from disk reconstructs identical balance and chain tip |
//!
//! ## How to run
//! ```bash
//! cargo test --package vledger-ledger proptest
//! ```
//!
//! By default proptest runs 256 cases per test.  Set `PROPTEST_CASES=10000`
//! to run a longer campaign:
//! ```bash
//! PROPTEST_CASES=10000 cargo test --package vledger-ledger proptest -- --nocapture
//! ```

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use tempfile::TempDir;

    use crate::{
        account::{Account, AccountType},
        amount::Amount,
        entry::JournalEntryBuilder,
        store::LedgerStore,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn open_store(dir: &TempDir) -> LedgerStore {
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        LedgerStore::open(dir.path()).unwrap()
    }

    /// A single randomized transaction: amount in cents, description seed.
    #[derive(Debug, Clone)]
    struct Tx {
        amount_cents: i64,
        desc_seed: u32,
    }

    fn tx_strategy() -> impl Strategy<Value = Tx> {
        (1i64..=1_000_000i64, 0u32..=u32::MAX).prop_map(|(amount_cents, desc_seed)| Tx {
            amount_cents,
            desc_seed,
        })
    }

    fn txs_strategy(min: usize, max: usize) -> impl Strategy<Value = Vec<Tx>> {
        proptest::collection::vec(tx_strategy(), min..=max)
    }

    // ── P-INV-1 + P-INV-2: balanced entries, correct per-account balance ─

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// For any sequence of 1–200 transactions:
        /// - every posted entry must have SUM(debits) == SUM(credits)
        /// - the debit account balance must equal the sum of all posted amounts
        #[test]
        fn p_inv1_p_inv2_entries_balanced_balance_correct(
            txs in txs_strategy(1, 200)
        ) {
            let dir   = TempDir::new().unwrap();
            let mut store = open_store(&dir);

            let cash = store.create_account(
                Account::new("CASH", "Cash", AccountType::Asset, "USD", "test")
            ).unwrap();
            let rev = store.create_account(
                Account::new("REV", "Revenue", AccountType::Income, "USD", "test")
            ).unwrap();

            let mut expected_cash_balance: i128 = 0;
            let mut posted_count = 0usize;

            for tx in &txs {
                let amt = match Amount::new(tx.amount_cents) {
                    Some(a) => a,
                    None    => continue,
                };
                let e = JournalEntryBuilder::new(
                    format!("tx-{}", tx.desc_seed),
                    "test",
                )
                .debit(cash, amt, "USD")
                .credit(rev, amt, "USD")
                .build();

                if store.post_entry(e).is_ok() {
                    expected_cash_balance += tx.amount_cents as i128;
                    posted_count += 1;
                }
            }

            // P-INV-1: every entry must have SUM(debits) == SUM(credits)
            for entry in store.entries_scan(usize::MAX) {
                use crate::entry::DrCr;
                let debits: i128 = entry.lines.iter()
                    .filter(|l| l.dr_cr == DrCr::Debit)
                    .map(|l| l.amount.as_i128())
                    .sum();
                let credits: i128 = entry.lines.iter()
                    .filter(|l| l.dr_cr == DrCr::Credit)
                    .map(|l| l.amount.as_i128())
                    .sum();
                prop_assert_eq!(
                    debits, credits,
                    "entry {} unbalanced: debits={} credits={}",
                    entry.sequence, debits, credits
                );
            }

            // P-INV-2: balance must match sum of posted amounts
            prop_assert_eq!(
                store.balance(&cash), expected_cash_balance,
                "CASH balance mismatch: expected={} got={}",
                expected_cash_balance, store.balance(&cash)
            );

            // Entry count must match posted count
            prop_assert_eq!(
                store.entry_count(), posted_count,
                "entry count mismatch: expected={} got={}",
                posted_count, store.entry_count()
            );
        }

        // ── P-INV-3: idempotency under random retry counts ─────────────────

        /// For any unique key posted between 1 and 20 times, exactly 1 entry
        /// must be recorded and the balance must reflect exactly 1 posting.
        #[test]
        fn p_inv3_idempotency_random_retry_count(
            amount_cents in 1i64..=500_000i64,
            retry_count  in 1usize..=20usize,
            key_seed     in 0u64..=u64::MAX,
        ) {
            let dir   = TempDir::new().unwrap();
            let mut store = open_store(&dir);

            let cash = store.create_account(
                Account::new("CASH", "Cash", AccountType::Asset, "USD", "test")
            ).unwrap();
            let rev = store.create_account(
                Account::new("REV", "Revenue", AccountType::Income, "USD", "test")
            ).unwrap();

            let idem_key = format!("idem-key-{key_seed:016x}");
            let amt = Amount::new(amount_cents).unwrap();

            for _ in 0..retry_count {
                let e = JournalEntryBuilder::new("idem-post", "test")
                    .debit(cash, amt, "USD")
                    .credit(rev, amt, "USD")
                    .idempotency_key(&idem_key)
                    .build();
                // Every call must return Ok (idempotent — no-op on repeat)
                prop_assert!(
                    store.post_entry(e).is_ok(),
                    "idempotent post must always return Ok"
                );
            }

            // Exactly 1 entry must exist regardless of retry count
            prop_assert_eq!(
                store.entry_count(), 1,
                "idempotency: retries must produce exactly 1 entry, got {}",
                store.entry_count()
            );
            prop_assert_eq!(
                store.balance(&cash), amount_cents as i128,
                "balance after idempotent retries must equal one posting"
            );
        }

        // ── P-INV-4: sequence numbers strictly monotonic ───────────────────

        #[test]
        fn p_inv4_sequence_monotonic_no_gaps(
            txs in txs_strategy(1, 100)
        ) {
            let dir   = TempDir::new().unwrap();
            let mut store = open_store(&dir);

            let cash = store.create_account(
                Account::new("CASH", "Cash", AccountType::Asset, "USD", "test")
            ).unwrap();
            let rev = store.create_account(
                Account::new("REV", "Revenue", AccountType::Income, "USD", "test")
            ).unwrap();

            for tx in &txs {
                if let Some(amt) = Amount::new(tx.amount_cents) {
                    let e = JournalEntryBuilder::new(
                        format!("seq-{}", tx.desc_seed), "test",
                    )
                    .debit(cash, amt, "USD")
                    .credit(rev, amt, "USD")
                    .build();
                    let _ = store.post_entry(e);
                }
            }

            let entries = store.entries_scan(usize::MAX);
            let mut prev = 0u64;
            for entry in entries {
                prop_assert!(
                    entry.sequence > prev,
                    "sequence {} must be > previous {}", entry.sequence, prev
                );
                prop_assert_eq!(
                    entry.sequence, prev + 1,
                    "sequence must increment by 1: expected {} got {}",
                    prev + 1, entry.sequence
                );
                prev = entry.sequence;
            }
        }

        // ── P-INV-5: hash chain valid after any sequence of posts ──────────

        #[test]
        fn p_inv5_hash_chain_always_valid(
            txs in txs_strategy(1, 150)
        ) {
            let dir   = TempDir::new().unwrap();
            let mut store = open_store(&dir);

            let cash = store.create_account(
                Account::new("CASH", "Cash", AccountType::Asset, "USD", "test")
            ).unwrap();
            let rev = store.create_account(
                Account::new("REV", "Revenue", AccountType::Income, "USD", "test")
            ).unwrap();

            for tx in &txs {
                if let Some(amt) = Amount::new(tx.amount_cents) {
                    let e = JournalEntryBuilder::new(
                        format!("hash-{}", tx.desc_seed), "test",
                    )
                    .debit(cash, amt, "USD")
                    .credit(rev, amt, "USD")
                    .build();
                    let _ = store.post_entry(e);
                }
            }

            prop_assert!(
                store.verify_chain_integrity().is_ok(),
                "hash chain must be valid after {} transactions", txs.len()
            );

            for entry in store.entries_scan(usize::MAX) {
                prop_assert!(
                    entry.verify_hashes(),
                    "entry {} has invalid hashes", entry.sequence
                );
            }
        }

        // ── P-INV-6: original + reversal nets to zero ─────────────────────

        /// For any transaction amount, posting then reversing must produce
        /// zero net balance impact and keep the hash chain valid.
        #[test]
        fn p_inv6_reversal_nets_to_zero(
            amount_cents in 1i64..=500_000i64,
        ) {
            let dir   = TempDir::new().unwrap();
            let mut store = open_store(&dir);

            let cash = store.create_account(
                Account::new("CASH", "Cash", AccountType::Asset, "USD", "test")
            ).unwrap();
            let rev = store.create_account(
                Account::new("REV", "Revenue", AccountType::Income, "USD", "test")
            ).unwrap();

            // Post original
            let amt = Amount::new(amount_cents).unwrap();
            let e = JournalEntryBuilder::new("original", "test")
                .debit(cash, amt, "USD")
                .credit(rev, amt, "USD")
                .build();
            store.post_entry(e).unwrap();
            let original_id = store.entries_scan(usize::MAX)[0].id;

            prop_assert_eq!(
                store.balance(&cash), amount_cents as i128,
                "balance must equal original amount before reversal"
            );

            // Reverse it
            store.reverse_entry(original_id, "reversal", "test").unwrap();

            prop_assert_eq!(
                store.balance(&cash), 0i128,
                "balance must be 0 after reversal of amount={}", amount_cents
            );
            prop_assert_eq!(
                store.entry_count(), 2usize,
                "must have exactly 2 entries: original + reversal"
            );
            prop_assert!(
                store.verify_chain_integrity().is_ok(),
                "hash chain must be valid after reversal"
            );
        }

        // ── P-INV-7: WAL replay reconstructs identical state ──────────────

        /// For any sequence of posts, closing and reopening the store must
        /// produce identical entry count, balance, and hash chain tip.
        #[test]
        fn p_inv7_wal_replay_reconstructs_identical_state(
            txs in txs_strategy(1, 100)
        ) {
            let dir = TempDir::new().unwrap();

            let (expected_count, expected_balance, expected_tip) = {
                let mut store = open_store(&dir);

                let cash = store.create_account(
                    Account::new("CASH", "Cash", AccountType::Asset, "USD", "test")
                ).unwrap();
                let rev = store.create_account(
                    Account::new("REV", "Revenue", AccountType::Income, "USD", "test")
                ).unwrap();

                let mut balance: i128 = 0;
                for tx in &txs {
                    if let Some(amt) = Amount::new(tx.amount_cents) {
                        let e = JournalEntryBuilder::new(
                            format!("wal-{}", tx.desc_seed), "test",
                        )
                        .debit(cash, amt, "USD")
                        .credit(rev, amt, "USD")
                        .build();
                        if store.post_entry(e).is_ok() {
                            balance += tx.amount_cents as i128;
                        }
                    }
                }

                let entries   = store.entries_scan(usize::MAX);
                let count     = entries.len();
                let chain_tip = entries.last().map(|e| e.chain_hash).unwrap_or([0u8; 32]);
                (count, balance, chain_tip)
            }; // drop = simulate close/crash

            // Reopen — WAL replay
            let store2 = LedgerStore::open(dir.path()).unwrap();

            prop_assert_eq!(
                store2.entry_count(), expected_count,
                "WAL replay: entry count mismatch"
            );

            if expected_count > 0 {
                let cash = store2.all_accounts()
                    .find(|a| a.code == "CASH")
                    .map(|a| a.id);
                if let Some(cash_id) = cash {
                    prop_assert_eq!(
                        store2.balance(&cash_id), expected_balance,
                        "WAL replay: balance mismatch"
                    );
                }
                let replayed_tip = store2.entries_scan(usize::MAX)
                    .last()
                    .map(|e| e.chain_hash)
                    .unwrap_or([0u8; 32]);
                prop_assert_eq!(
                    replayed_tip, expected_tip,
                    "WAL replay: chain hash tip mismatch"
                );
            }

            prop_assert!(
                store2.verify_chain_integrity().is_ok(),
                "WAL replay: hash chain must be valid"
            );
        }

        // ── Global equation: Σdebits == Σcredits across all entries ────────

        /// Regardless of transaction mix, total debits must always equal
        /// total credits across the entire ledger.
        #[test]
        fn p_inv_global_equation_holds(
            txs in txs_strategy(1, 200)
        ) {
            use crate::entry::DrCr;

            let dir   = TempDir::new().unwrap();
            let mut store = open_store(&dir);

            let cash = store.create_account(
                Account::new("CASH", "Cash", AccountType::Asset, "USD", "test")
            ).unwrap();
            let rev = store.create_account(
                Account::new("REV", "Revenue", AccountType::Income, "USD", "test")
            ).unwrap();

            for tx in &txs {
                if let Some(amt) = Amount::new(tx.amount_cents) {
                    let e = JournalEntryBuilder::new(
                        format!("glob-{}", tx.desc_seed), "test",
                    )
                    .debit(cash, amt, "USD")
                    .credit(rev, amt, "USD")
                    .build();
                    let _ = store.post_entry(e);
                }
            }

            let entries = store.entries_scan(usize::MAX);
            let total_debits: i128 = entries.iter()
                .flat_map(|e| e.lines.iter())
                .filter(|l| l.dr_cr == DrCr::Debit)
                .map(|l| l.amount.as_i128())
                .sum();
            let total_credits: i128 = entries.iter()
                .flat_map(|e| e.lines.iter())
                .filter(|l| l.dr_cr == DrCr::Credit)
                .map(|l| l.amount.as_i128())
                .sum();

            prop_assert_eq!(
                total_debits, total_credits,
                "global equation violated: Σdebits={} != Σcredits={}",
                total_debits, total_credits
            );
        }
    }
}
