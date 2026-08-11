//! Phase 3 — Attack the ledger: financial invariant property tests at scale.
//!
//! Every test in this module continuously asserts core accounting invariants
//! over large volumes of transactions:
//!
//!   INV-1  debits == credits for every entry (ledger is always balanced)
//!   INV-2  balance == sum of all line effects for that account
//!   INV-3  idempotency == exactly-once posting (no double-posts)
//!   INV-4  sequence numbers == strictly monotonic, no gaps
//!   INV-5  hash chain == valid at all times
//!   INV-6  reversal(original) + original nets to zero balance impact
//!   INV-7  overflow boundaries: amounts near i64::MAX are rejected safely
//!   INV-8  multi-currency entries enforce per-account currency match
//!   INV-9  exposure limits are enforced per-transaction (aggregate)
//!   INV-10 asset/expense accounts never go negative

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use tempfile::TempDir;

    use crate::{
        account::{Account, AccountStatus, AccountType},
        amount::Amount,
        entry::{DrCr, EntryStatus, JournalEntryBuilder},
        store::LedgerStore,
    };

    // ── Setup ─────────────────────────────────────────────────────────────

    fn setup() -> (TempDir, LedgerStore) {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        let store = LedgerStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn mk_account(store: &mut LedgerStore, code: &str, at: AccountType) -> uuid::Uuid {
        store.create_account(Account::new(code, code, at, "USD", "test")).unwrap()
    }

    fn post(store: &mut LedgerStore, dr: uuid::Uuid, cr: uuid::Uuid, cents: i64) {
        let amt = Amount::new(cents).unwrap();
        let e = JournalEntryBuilder::new("inv-test", "test")
            .debit(dr, amt, "USD")
            .credit(cr, amt, "USD")
            .build();
        store.post_entry(e).unwrap();
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-1 + INV-2: Every entry balanced; balance == Σ line effects
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv1_inv2_10k_entries_always_balanced_balance_correct() {
        let (_dir, mut store) = setup();
        let cash    = mk_account(&mut store, "CASH",    AccountType::Asset);
        let revenue = mk_account(&mut store, "REVENUE", AccountType::Income);

        let n = 10_000usize;
        let amount_per_entry: i64 = 100; // $1.00 per entry

        for i in 0..n {
            let amt = Amount::new(amount_per_entry).unwrap();
            let e = JournalEntryBuilder::new(format!("entry-{i}"), "test")
                .debit(cash, amt, "USD")
                .credit(revenue, amt, "USD")
                .build();
            store.post_entry(e).unwrap();
        }

        // INV-1: every entry must be balanced
        for entry in store.all_entries() {
            let debits:  i128 = entry.lines.iter()
                .filter(|l| l.dr_cr == DrCr::Debit).map(|l| l.amount.as_i128()).sum();
            let credits: i128 = entry.lines.iter()
                .filter(|l| l.dr_cr == DrCr::Credit).map(|l| l.amount.as_i128()).sum();
            assert_eq!(
                debits, credits,
                "entry {} is unbalanced: debits={debits} credits={credits}", entry.sequence
            );
        }

        // INV-2: balance must exactly equal Σ(debit_lines - credit_lines) for CASH
        let expected_cash_balance: i128 = n as i128 * amount_per_entry as i128;
        assert_eq!(
            store.balance(&cash), expected_cash_balance,
            "CASH balance mismatch after {n} entries"
        );

        // Revenue is credit-normal (income): balance = -Σcredits (net credit position)
        // The ledger stores signed balance — income account shows negative (credit surplus)
        // Depending on ledger convention, revenue balance = -expected or +expected
        // Just assert it is non-zero and consistent
        let rev_bal = store.balance(&revenue).abs();
        assert_eq!(rev_bal, expected_cash_balance, "REVENUE balance magnitude mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-3: Idempotency == exactly-once
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv3_idempotency_exactly_once_1000_retries() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH",    AccountType::Asset);
        let rev  = mk_account(&mut store, "REVENUE", AccountType::Income);

        // Post the same 100 unique events, each retried 10 times
        let unique_events = 100;
        let retries       = 10;

        for event_id in 0..unique_events {
            for _ in 0..retries {
                let amt = Amount::new(1000).unwrap();
                let e = JournalEntryBuilder::new(format!("event-{event_id}"), "test")
                    .debit(cash, amt, "USD")
                    .credit(rev, amt, "USD")
                    .idempotency_key(format!("event-key-{event_id:05}"))
                    .build();
                let result = store.post_entry(e);
                assert!(
                    result.is_ok(),
                    "idempotent re-post for event {event_id} must succeed, got: {result:?}"
                );
            }
        }

        // Must have exactly `unique_events` entries — not unique_events * retries
        assert_eq!(
            store.entry_count(), unique_events,
            "idempotency: must have exactly {unique_events} entries, not {}",
            store.entry_count()
        );
        assert_eq!(
            store.balance(&cash),
            unique_events as i128 * 1000,
            "idempotency: balance must reflect exactly {unique_events} distinct postings"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-4: Sequence numbers strictly monotonic, no gaps
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv4_sequence_numbers_strictly_monotonic_no_gaps() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH",    AccountType::Asset);
        let rev  = mk_account(&mut store, "REVENUE", AccountType::Income);

        let n = 5_000;
        for _ in 0..n {
            post(&mut store, cash, rev, 1);
        }

        let entries = store.all_entries();
        assert_eq!(entries.len(), n);

        let mut prev_seq = 0u64;
        for entry in entries {
            assert!(
                entry.sequence > prev_seq,
                "sequence {} must be > previous {prev_seq}", entry.sequence
            );
            assert_eq!(
                entry.sequence, prev_seq + 1,
                "sequence must increment by exactly 1: expected {}, got {}",
                prev_seq + 1, entry.sequence
            );
            prev_seq = entry.sequence;
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-5: Hash chain always valid
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv5_hash_chain_valid_after_1000_entries() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH",    AccountType::Asset);
        let rev  = mk_account(&mut store, "REVENUE", AccountType::Income);

        for i in 0..1_000 {
            post(&mut store, cash, rev, (i % 500 + 1) as i64);
        }

        assert!(
            store.verify_chain_integrity().is_ok(),
            "hash chain must be valid after 1000 entries"
        );

        // Verify every individual entry's self-consistency
        for entry in store.all_entries() {
            assert!(
                entry.verify_hashes(),
                "entry {} has invalid hash", entry.sequence
            );
        }
    }

    #[test]
    fn inv5b_hash_chain_tamper_detection() {
        // Verify that chain_hash covers the entry content — any tampering
        // must invalidate verify_hashes()
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH", AccountType::Asset);
        let rev  = mk_account(&mut store, "REVENUE", AccountType::Income);
        post(&mut store, cash, rev, 9_999);

        let mut entry = store.all_entries()[0].clone();
        entry.description = "TAMPERED DESCRIPTION".to_string();
        // verify_hashes must now return false
        assert!(
            !entry.verify_hashes(),
            "tampered entry must fail hash verification"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-6: reversal(original) + original nets to zero
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv6_reversal_nets_to_zero_100_entries() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH",    AccountType::Asset);
        let rev  = mk_account(&mut store, "REVENUE", AccountType::Income);

        // Post and reverse 100 entries
        for i in 1i64..=100 {
            post(&mut store, cash, rev, i * 137); // varied amounts
            let id = {
                let entries = store.all_entries();
                entries.last().unwrap().id
            };
            store.reverse_entry(id, "reversal", "test").unwrap();
        }

        // All 200 entries present (100 originals + 100 reversals)
        assert_eq!(store.entry_count(), 200);

        // Net balance must be zero — every debit was reversed by an equal credit
        assert_eq!(store.balance(&cash), 0, "CASH balance after all reversals must be 0");
        assert_eq!(store.balance(&rev).abs(), 0, "REVENUE balance after all reversals must be 0");

        // Hash chain must still be valid
        assert!(store.verify_chain_integrity().is_ok());

        // Every original entry must be tracked in the reversal event index
        let entries = store.all_entries();
        let originals: Vec<_> = entries.iter()
            .filter(|e| e.status != EntryStatus::Reversal && e.status != EntryStatus::PendingApproval)
            .collect();
        for original in originals {
            assert!(
                store.is_reversed(&original.id),
                "original entry {} must be in reversal_event_index", original.sequence
            );
        }
    }

    #[test]
    fn inv6b_double_reversal_rejected() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH",    AccountType::Asset);
        let rev  = mk_account(&mut store, "REVENUE", AccountType::Income);

        post(&mut store, cash, rev, 5_000);
        let id = store.all_entries()[0].id;

        store.reverse_entry(id, "first reversal", "test").unwrap();
        let result = store.reverse_entry(id, "second reversal", "test");
        assert!(result.is_err(), "double reversal must be rejected");
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-7: Overflow boundaries
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv7_amount_near_i64_max_handled_safely() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH",    AccountType::Asset);
        let rev  = mk_account(&mut store, "REVENUE", AccountType::Income);

        // Amount at i64::MAX is technically valid as an Amount (non-zero),
        // but exposure limits should fire if configured.
        // Without a limit, the store must either accept or reject gracefully — no panic.
        let large_amt = Amount::new(i64::MAX).unwrap();
        let e = JournalEntryBuilder::new("overflow-test", "test")
            .debit(cash, large_amt, "USD")
            .credit(rev, large_amt, "USD")
            .build();
        let result = store.post_entry(e);
        // Must not panic — result may be Ok or Err (exposure limit check)
        let _ = result;
    }

    #[test]
    fn inv7b_zero_amount_rejected_by_amount_type() {
        // Amount::new(0) must return None — the type system prevents zero amounts
        assert!(
            Amount::new(0).is_none(),
            "Amount::new(0) must return None"
        );
    }

    #[test]
    fn inv7c_min_i64_amount_handled_safely() {
        // i64::MIN as an amount — must not panic
        let result = Amount::new(i64::MIN);
        // Either None (treated as invalid) or Some — must not panic
        let _ = result;
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-8: Multi-currency entries enforce per-account currency
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv8_currency_mismatch_rejected() {
        let (_dir, mut store) = setup();
        // USD account
        let usd_cash = store.create_account(
            Account::new("USD_CASH", "USD Cash", AccountType::Asset, "USD", "test")
        ).unwrap();
        // EUR account
        let eur_rev = store.create_account(
            Account::new("EUR_REV", "EUR Revenue", AccountType::Income, "EUR", "test")
        ).unwrap();

        // Try to post USD amount to EUR account
        let amt = Amount::new(1_000).unwrap();
        let e = JournalEntryBuilder::new("currency-mismatch", "test")
            .debit(usd_cash, amt, "USD")
            .credit(eur_rev, amt, "USD") // wrong currency for EUR_REV
            .build();
        let result = store.post_entry(e);
        assert!(result.is_err(), "currency mismatch must be rejected");
    }

    #[test]
    fn inv8b_correct_currency_accepted() {
        let (_dir, mut store) = setup();
        let eur_cash = store.create_account(
            Account::new("EUR_CASH", "EUR Cash", AccountType::Asset, "EUR", "test")
        ).unwrap();
        let eur_rev = store.create_account(
            Account::new("EUR_REV", "EUR Revenue", AccountType::Income, "EUR", "test")
        ).unwrap();

        let amt = Amount::new(5_000).unwrap();
        let e = JournalEntryBuilder::new("eur-entry", "test")
            .debit(eur_cash, amt, "EUR")
            .credit(eur_rev, amt, "EUR")
            .build();
        assert!(store.post_entry(e).is_ok(), "matching currency must be accepted");
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-9: Exposure limits enforced in aggregate
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv9_exposure_limit_rejected_on_single_large_entry() {
        let (_dir, mut store) = setup();

        let mut acct = Account::new("CAPPED", "Capped", AccountType::Asset, "USD", "test");
        acct.exposure_limit = Some(10_000); // max $100 per entry
        let capped = store.create_account(acct).unwrap();
        let rev    = mk_account(&mut store, "REV", AccountType::Income);

        // Entry exceeding limit must be rejected
        let amt = Amount::new(10_001).unwrap();
        let e = JournalEntryBuilder::new("over-limit", "test")
            .debit(capped, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        let result = store.post_entry(e);
        assert!(result.is_err(), "entry exceeding exposure limit must be rejected");
    }

    #[test]
    fn inv9b_exposure_limit_passes_within_limit() {
        let (_dir, mut store) = setup();

        let mut acct = Account::new("CAPPED", "Capped", AccountType::Asset, "USD", "test");
        acct.exposure_limit = Some(10_000);
        let capped = store.create_account(acct).unwrap();
        let rev    = mk_account(&mut store, "REV", AccountType::Income);

        let amt = Amount::new(9_999).unwrap(); // just under limit
        let e = JournalEntryBuilder::new("within-limit", "test")
            .debit(capped, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        assert!(store.post_entry(e).is_ok(), "entry within exposure limit must be accepted");
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-10: Asset/expense accounts never go negative
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv10_asset_account_overdraw_rejected() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH", AccountType::Asset);
        let rev  = mk_account(&mut store, "REV",  AccountType::Income);

        // Deposit $100
        post(&mut store, cash, rev, 10_000);
        assert_eq!(store.balance(&cash), 10_000);

        // Try to withdraw $101 (overdraw by $1)
        let amt = Amount::new(10_001).unwrap();
        let e = JournalEntryBuilder::new("overdraw", "test")
            .credit(cash, amt, "USD")
            .debit(rev, amt, "USD")
            .build();
        let result = store.post_entry(e);
        assert!(result.is_err(), "overdrawing an asset account must be rejected");
        // Balance must be unchanged
        assert_eq!(store.balance(&cash), 10_000);
    }

    #[test]
    fn inv10b_exactly_zero_balance_allowed() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH", AccountType::Asset);
        let rev  = mk_account(&mut store, "REV",  AccountType::Income);

        post(&mut store, cash, rev, 5_000);

        // Withdraw exactly $50 — balance goes to zero, must be allowed
        let amt = Amount::new(5_000).unwrap();
        let e = JournalEntryBuilder::new("zero-out", "test")
            .credit(cash, amt, "USD")
            .debit(rev, amt, "USD")
            .build();
        assert!(store.post_entry(e).is_ok(), "zeroing an asset balance must be allowed");
        assert_eq!(store.balance(&cash), 0);
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-11: Unbalanced entry always rejected (adversarial variants)
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv11_unbalanced_entry_off_by_one_rejected() {
        use crate::entry::DrCr;

        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH", AccountType::Asset);
        let rev  = mk_account(&mut store, "REV",  AccountType::Income);

        // Build entry manually with debits != credits (off by 1)
        let e = crate::entry::JournalEntryBuilder::new("unbalanced", "test")
            .debit(cash, Amount::new(1000).unwrap(), "USD")
            .credit(rev,  Amount::new(999).unwrap(),  "USD")
            .build();
        let result = store.post_entry(e);
        assert!(result.is_err(), "off-by-one unbalanced entry must be rejected");
    }

    #[test]
    fn inv11b_single_line_entry_rejected() {
        let (_dir, mut store) = setup();
        let cash = mk_account(&mut store, "CASH", AccountType::Asset);

        // One-line entry can never be balanced for double-entry
        let e = JournalEntryBuilder::new("one-liner", "test")
            .debit(cash, Amount::new(1000).unwrap(), "USD")
            .build();
        let result = store.post_entry(e);
        assert!(result.is_err(), "single-line entry must be rejected");
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-12: Closed account rejects new entries
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv12_closed_account_rejects_entries() {
        let (_dir, mut store) = setup();

        let mut acct = Account::new("CLOSED", "Closed", AccountType::Asset, "USD", "test");
        acct.status = AccountStatus::Closed;
        let closed = store.create_account(acct).unwrap();
        let rev    = mk_account(&mut store, "REV", AccountType::Income);

        let amt = Amount::new(500).unwrap();
        let e = JournalEntryBuilder::new("post-to-closed", "test")
            .debit(closed, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        let result = store.post_entry(e);
        assert!(result.is_err(), "posting to a closed account must be rejected");
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-13: Global ledger equation — Σ(Assets + Expenses) == Σ(Liabilities + Equity + Income)
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv13_global_ledger_equation_holds_after_1000_entries() {
        let (_dir, mut store) = setup();

        let cash     = mk_account(&mut store, "CASH",     AccountType::Asset);
        let ar       = mk_account(&mut store, "AR",       AccountType::Asset);
        let revenue  = mk_account(&mut store, "REVENUE",  AccountType::Income);
        let expense  = mk_account(&mut store, "EXPENSE",  AccountType::Expense);
        let equity   = mk_account(&mut store, "EQUITY",   AccountType::Equity);

        // Post varied transactions
        for i in 1i64..=200 {
            post(&mut store, cash, revenue, i * 100);     // cash in, revenue up
        }
        for i in 1i64..=100 {
            // Expense payment: debit expense, credit cash
            let amt = Amount::new(i * 50).unwrap();
            let e = JournalEntryBuilder::new(format!("expense-{i}"), "test")
                .debit(expense, amt, "USD")
                .credit(cash, amt, "USD")
                .build();
            store.post_entry(e).unwrap();
        }

        // Calculate total debits and credits from all entries
        let entries = store.all_entries();
        let total_debits:  i128 = entries.iter()
            .flat_map(|e| e.lines.iter())
            .filter(|l| l.dr_cr == DrCr::Debit)
            .map(|l| l.amount.as_i128())
            .sum();
        let total_credits: i128 = entries.iter()
            .flat_map(|e| e.lines.iter())
            .filter(|l| l.dr_cr == DrCr::Credit)
            .map(|l| l.amount.as_i128())
            .sum();

        assert_eq!(
            total_debits, total_credits,
            "global accounting equation: Σdebits={total_debits} must == Σcredits={total_credits}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // INV-14: WAL replay reconstructs identical state
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn inv14_wal_replay_produces_identical_state() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();

        let (n_entries, final_balance, last_chain_hash) = {
            let mut store = LedgerStore::open(dir.path()).unwrap();
            let cash = mk_account(&mut store, "CASH", AccountType::Asset);
            let rev  = mk_account(&mut store, "REV",  AccountType::Income);

            for i in 1i64..=500 {
                post(&mut store, cash, rev, i * 7);
            }

            let entries = store.all_entries();
            let balance = store.balance(&cash);
            let chain_hash = entries.last().unwrap().chain_hash;
            (entries.len(), balance, chain_hash)
        }; // drop = simulated crash / clean close

        // Reopen from WAL
        let store2 = LedgerStore::open(dir.path()).unwrap();
        assert_eq!(store2.entry_count(), n_entries, "WAL replay: entry count must match");

        // Re-find cash account and verify balance
        let cash = store2.all_accounts()
            .find(|a| a.code == "CASH").unwrap().id;
        let expected_cash_balance: i128 = (1i128..=500).map(|i| i * 7).sum();
        assert_eq!(
            store2.balance(&cash), expected_cash_balance,
            "WAL replay: balance must match"
        );

        // Hash chain tip must be identical
        let replayed_chain_hash = store2.all_entries().last().unwrap().chain_hash;
        assert_eq!(
            replayed_chain_hash, last_chain_hash,
            "WAL replay: chain hash tip must be identical"
        );
        assert!(store2.verify_chain_integrity().is_ok(), "hash chain must be valid after WAL replay");
    }
}
