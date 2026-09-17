/// Regression tests for financial correctness guarantees.
///
/// These tests turn real-world workflows into permanent product guarantees
/// that must pass on every release. Adding a test here means the behaviour
/// is contractually guaranteed and cannot regress silently.

#[cfg(test)]
mod tests {

    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{
        account::{Account, AccountType},
        amount::Amount,
        entry::{DrCr, EntryStatus, JournalEntryBuilder},
        store::LedgerStore,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn setup() -> (TempDir, LedgerStore) {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        let store = LedgerStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn mk_account(store: &mut LedgerStore, code: &str, at: AccountType) -> Uuid {
        store
            .create_account(Account::new(code, code, at, "USD", "test"))
            .unwrap()
    }

    /// Seed an Asset account with a starting balance.
    /// Asset accounts are debit-normal — balance increases on debit.
    /// We debit the asset account and credit a no-constraint suspense account.
    fn seed_balance(store: &mut LedgerStore, asset_account: Uuid, cents: i64) {
        let mut suspense_acct = Account::new(
            &format!("SUSPENSE-{}", uuid::Uuid::new_v4()),
            "Suspense",
            AccountType::Suspense,
            "USD",
            "test",
        );
        suspense_acct.require_non_negative_balance = false;
        let suspense = store.create_account(suspense_acct).unwrap();
        let amt = Amount::new(cents).unwrap();
        // Debit the asset account to give it a positive balance.
        let entry = JournalEntryBuilder::new("seed balance", "test")
            .debit(asset_account, amt, "USD")
            .credit(suspense, amt, "USD")
            .build();
        store.post_entry(entry).unwrap();
    }

    fn post(
        store: &mut LedgerStore,
        dr: Uuid,
        cr: Uuid,
        cents: i64,
        description: &str,
    ) -> (u64, Uuid) {
        let amt = Amount::new(cents).unwrap();
        let entry = JournalEntryBuilder::new(description, "test")
            .debit(dr, amt, "USD")
            .credit(cr, amt, "USD")
            .build();
        let seq = store.post_entry(entry).unwrap();
        let id = store
            .entries_scan(usize::MAX)
            .into_iter()
            .find(|e| e.sequence == seq)
            .unwrap()
            .id;
        (seq, id)
    }

    fn assert_entry_balanced(store: &LedgerStore, seq: u64) {
        let entry = store
            .entries_scan(usize::MAX)
            .into_iter()
            .find(|e| e.sequence == seq)
            .unwrap_or_else(|| panic!("entry with sequence {seq} not found"));
        let debits: i128 = entry
            .lines
            .iter()
            .filter(|l| l.dr_cr == DrCr::Debit)
            .map(|l| l.amount.as_i128())
            .sum();
        let credits: i128 = entry
            .lines
            .iter()
            .filter(|l| l.dr_cr == DrCr::Credit)
            .map(|l| l.amount.as_i128())
            .sum();
        assert_eq!(
            debits, credits,
            "entry {seq} is unbalanced: debits={debits} credits={credits}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // REGRESSION: test_reversal_correction_preserves_chain_integrity
    //
    // Scenario from production (2026-09-17):
    //   - Original payment: $42.61
    //   - Reversal:        -$42.61  (cancels original)
    //   - Correction:       $35.00  (re-posts correct amount)
    //
    // This test permanently guarantees the reversal+correction workflow
    // produces a valid, auditable, chain-intact ledger.
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reversal_correction_preserves_chain_integrity() {
        let (_dir, mut store) = setup();

        // ── Accounts ──────────────────────────────────────────────────────
        let sender = mk_account(&mut store, "SENDER", AccountType::Asset);
        let receiver = mk_account(&mut store, "RECEIVER", AccountType::Asset);

        // Seed both accounts so non-negative constraint is satisfied.
        seed_balance(&mut store, sender, 100_000);
        seed_balance(&mut store, receiver, 100_000);

        let balance_sender_before = store.balance(&sender);
        let balance_receiver_before = store.balance(&receiver);

        // ── Step 1: Post original entry ($42.61 = 4261 cents) ─────────────
        let original_cents: i64 = 4261;
        let (original_seq, original_id) = post(
            &mut store,
            sender,
            receiver,
            original_cents,
            "Payment to Housni Royer",
        );

        // Capture original entry state before any reversal.
        let original_entry = store
            .entries_scan(usize::MAX)
            .into_iter()
            .find(|e| e.sequence == original_seq)
            .expect("original entry must exist");
        let original_content_hash = original_entry.content_hash;
        let original_chain_hash = original_entry.chain_hash;

        // ── Step 2: Post reversal ($42.61, flipped) ───────────────────────
        // reverse_entry flips all lines and records a ReversalEvent atomically.
        let reversal_id = store
            .reverse_entry(
                original_id,
                "Reversal of Payment to Housni Royer - Overpayment",
                "test",
            )
            .unwrap();

        // Find the reversal entry by its ID.
        let reversal_entry = store
            .entries_scan(usize::MAX)
            .into_iter()
            .find(|e| e.id == reversal_id)
            .expect("reversal entry must exist");
        let reversal_seq = reversal_entry.sequence;

        // ── Step 3: Post correction ($35.00 = 3500 cents) ─────────────────
        let correction_cents: i64 = 3500;
        let (correction_seq, _correction_id) = post(
            &mut store,
            sender,
            receiver,
            correction_cents,
            "Corrected Payment to Housni Royer",
        );

        // ══════════════════════════════════════════════════════════════════
        // ASSERTIONS
        // ══════════════════════════════════════════════════════════════════

        // 1. Original entry is unchanged.
        let original_after = store
            .entries_scan(usize::MAX)
            .into_iter()
            .find(|e| e.sequence == original_seq)
            .expect("original entry must still exist after reversal and correction");
        assert_eq!(
            original_after.content_hash, original_content_hash,
            "original content_hash must not change after reversal"
        );
        assert_eq!(
            original_after.chain_hash, original_chain_hash,
            "original chain_hash must not change after reversal"
        );
        assert_eq!(
            original_after.id, original_id,
            "original entry UUID must not change"
        );
        assert_eq!(
            original_after.lines.len(),
            2,
            "original entry must still have exactly 2 lines"
        );

        // 2. Reversal is appended at original_seq + 1.
        assert_eq!(
            reversal_seq,
            original_seq + 1,
            "reversal must be the immediately next sequence after the original"
        );

        // 3. Correction is appended at original_seq + 2.
        assert_eq!(
            correction_seq,
            original_seq + 2,
            "correction must be the immediately next sequence after the reversal"
        );

        // 4. Sequence numbers are strictly monotonic (no gaps, no duplicates).
        let seqs: Vec<u64> = store
            .entries_scan(usize::MAX)
            .iter()
            .map(|e| e.sequence)
            .collect();
        for window in seqs.windows(2) {
            assert_eq!(
                window[1],
                window[0] + 1,
                "sequence numbers must be strictly monotonic: found {} then {}",
                window[0],
                window[1]
            );
        }

        // 5. Double-entry is balanced for every entry individually.
        for entry in store.entries_scan(usize::MAX) {
            assert_entry_balanced(&store, entry.sequence);
        }

        // 6. Reversal lines are the exact mirror of the original lines.
        //    Original: sender Debit, receiver Credit
        //    Reversal: receiver Debit, sender Credit
        let reversal_debit_line = reversal_entry
            .lines
            .iter()
            .find(|l| l.dr_cr == DrCr::Debit)
            .expect("reversal must have a debit line");
        let reversal_credit_line = reversal_entry
            .lines
            .iter()
            .find(|l| l.dr_cr == DrCr::Credit)
            .expect("reversal must have a credit line");
        assert_eq!(
            reversal_debit_line.account_id, receiver,
            "reversal debit must be the original credit account (receiver)"
        );
        assert_eq!(
            reversal_credit_line.account_id, sender,
            "reversal credit must be the original debit account (sender)"
        );
        assert_eq!(
            reversal_debit_line.amount.as_i64(),
            original_cents,
            "reversal debit amount must equal original amount"
        );
        assert_eq!(
            reversal_credit_line.amount.as_i64(),
            original_cents,
            "reversal credit amount must equal original amount"
        );

        // 7. Reversal entry status is Reversal.
        assert_eq!(
            reversal_entry.status,
            EntryStatus::Reversal,
            "reversal entry must have status Reversal"
        );

        // 8. Net balance effect: sender balance increased by correction amount
        //    (debit-normal: balance increases on debit)
        //    original debit+4261, reversal credit-4261, correction debit+3500
        //    net = +3500 from balance_sender_before.
        let expected_sender_balance = balance_sender_before + correction_cents as i128;
        let expected_receiver_balance = balance_receiver_before - correction_cents as i128;
        assert_eq!(
            store.balance(&sender),
            expected_sender_balance,
            "sender balance after reversal+correction must reflect only the correction amount"
        );
        assert_eq!(
            store.balance(&receiver),
            expected_receiver_balance,
            "receiver balance after reversal+correction must reflect only the correction amount"
        );

        // 9. VERIFY_CHAIN() = OK across all entries.
        store
            .verify_chain_integrity()
            .expect("VERIFY_CHAIN must pass after reversal and correction");
    }

    // ══════════════════════════════════════════════════════════════════════
    // REGRESSION: test_reversal_only_preserves_chain_integrity
    //
    // A reversal without a correction is also a valid accounting operation.
    // Guarantees the simpler case works correctly too.
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reversal_only_preserves_chain_integrity() {
        let (_dir, mut store) = setup();

        let sender = mk_account(&mut store, "SENDER", AccountType::Asset);
        let receiver = mk_account(&mut store, "RECEIVER", AccountType::Asset);

        // Seed balances.
        seed_balance(&mut store, sender, 100_000);
        seed_balance(&mut store, receiver, 100_000);

        let balance_sender_before = store.balance(&sender);
        let balance_receiver_before = store.balance(&receiver);

        // Post original.
        let cents: i64 = 4261;
        let (original_seq, original_id) = post(&mut store, sender, receiver, cents, "Payment");

        // Reverse only — no correction.
        let reversal_id = store
            .reverse_entry(original_id, "Reversal of Payment", "test")
            .unwrap();

        let reversal_entry = store
            .entries_scan(usize::MAX)
            .into_iter()
            .find(|e| e.id == reversal_id)
            .expect("reversal entry must exist");

        // Reversal is at original + 1.
        assert_eq!(reversal_entry.sequence, original_seq + 1);

        // Net balance effect: zero — reversal cancels original completely.
        assert_eq!(
            store.balance(&sender),
            balance_sender_before,
            "sender balance must be unchanged after reversal with no correction"
        );
        assert_eq!(
            store.balance(&receiver),
            balance_receiver_before,
            "receiver balance must be unchanged after reversal with no correction"
        );

        // Double-entry balanced for all entries.
        for entry in store.entries_scan(usize::MAX) {
            assert_entry_balanced(&store, entry.sequence);
        }

        // VERIFY_CHAIN = OK.
        store
            .verify_chain_integrity()
            .expect("VERIFY_CHAIN must pass after reversal-only");
    }

    // ══════════════════════════════════════════════════════════════════════
    // REGRESSION: test_double_reversal_rejected
    //
    // Guarantees that reversing an already-reversed entry is rejected.
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_double_reversal_rejected() {
        let (_dir, mut store) = setup();

        let sender = mk_account(&mut store, "SENDER", AccountType::Asset);
        let receiver = mk_account(&mut store, "RECEIVER", AccountType::Asset);

        seed_balance(&mut store, sender, 100_000);
        seed_balance(&mut store, receiver, 100_000);

        let (_seq, original_id) = post(&mut store, sender, receiver, 4261, "Payment");

        // First reversal — must succeed.
        store
            .reverse_entry(original_id, "Reversal 1", "test")
            .expect("first reversal must succeed");

        // Second reversal of the same entry — must be rejected.
        let result = store.reverse_entry(original_id, "Reversal 2", "test");
        assert!(
            result.is_err(),
            "reversing an already-reversed entry must return an error"
        );

        // Chain must still be intact after the rejected double-reversal.
        store
            .verify_chain_integrity()
            .expect("VERIFY_CHAIN must pass even after a rejected double-reversal attempt");
    }
}
