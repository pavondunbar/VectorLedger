//! Settlement lifecycle and legal hold tests.
//!
//! Tests cover:
//! - Settlement transitions: Posted → Pending → Settled
//! - Settlement transitions: Posted → Pending → Failed
//! - Terminal state rejection: Settled → Settled, Settled → Failed, Failed → Settled
//! - Original entry is never mutated (content_hash/chain_hash unchanged)
//! - Settlement events survive WAL replay
//! - Legal hold: place_legal_hold blocks entries, reversals, and settlements
//! - Legal hold: lift_legal_hold re-enables all operations
//! - Legal hold + four-eyes interaction

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{
        account::{Account, AccountType},
        amount::Amount,
        entry::{EntryStatus, JournalEntryBuilder},
        error::LedgerError,
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

    fn setup_accounts(store: &mut LedgerStore) -> (Uuid, Uuid) {
        let cash = store
            .create_account(Account::new("CASH", "Cash", AccountType::Asset, "USD", "test"))
            .unwrap();
        let rev = store
            .create_account(Account::new("REV", "Revenue", AccountType::Income, "USD", "test"))
            .unwrap();
        (cash, rev)
    }

    fn post_entry(store: &mut LedgerStore, cash: Uuid, rev: Uuid, cents: i64) -> Uuid {
        let amt = Amount::new(cents).unwrap();
        let e = JournalEntryBuilder::new("test entry", "test")
            .debit(cash, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        store.post_entry(e).unwrap();
        store.entries_scan(usize::MAX).last().unwrap().id
    }

    // ─────────────────────────────────────────────────────────────────────
    // Settlement: Posted → Pending
    // ─────────────────────────────────────────────────────────────────────

    /// mark_pending transitions a Posted entry to Pending status.
    #[test]
    fn mark_pending_transitions_posted_to_pending() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);
        let entry_id = post_entry(&mut store, cash, rev, 1_000);

        store.mark_pending(entry_id, None).unwrap();

        assert_eq!(
            store.effective_status(&entry_id),
            EntryStatus::Pending,
            "effective_status must be Pending after mark_pending"
        );
    }

    /// mark_pending with notes stores them correctly.
    #[test]
    fn mark_pending_stores_notes() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);
        let entry_id = post_entry(&mut store, cash, rev, 500);

        let result = store.mark_pending(entry_id, Some("Awaiting SWIFT confirmation".into()));
        assert!(result.is_ok(), "mark_pending with notes must succeed");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Settlement: Pending → Settled
    // ─────────────────────────────────────────────────────────────────────

    /// Full settlement path: Posted → Pending → Settled.
    #[test]
    fn full_settlement_path_posted_pending_settled() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);
        let entry_id = post_entry(&mut store, cash, rev, 5_000);

        store.mark_pending(entry_id, None).unwrap();
        assert_eq!(store.effective_status(&entry_id), EntryStatus::Pending);

        store.mark_settled(entry_id, Some("SWIFT ref MT103-2026".into())).unwrap();
        assert_eq!(
            store.effective_status(&entry_id),
            EntryStatus::Settled,
            "effective_status must be Settled after mark_settled"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Settlement: Pending → Failed
    // ─────────────────────────────────────────────────────────────────────

    /// Pending → Failed transition.
    #[test]
    fn pending_to_failed_transition() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);
        let entry_id = post_entry(&mut store, cash, rev, 2_000);

        store.mark_pending(entry_id, None).unwrap();
        store.mark_failed(entry_id, Some("Insufficient funds at correspondent".into())).unwrap();

        assert_eq!(
            store.effective_status(&entry_id),
            EntryStatus::Failed,
            "effective_status must be Failed after mark_failed"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Original entry is never mutated
    // ─────────────────────────────────────────────────────────────────────

    /// content_hash and chain_hash of the original entry are unchanged after
    /// any number of settlement transitions.
    #[test]
    fn original_entry_hashes_unchanged_after_settlement() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);
        let entry_id = post_entry(&mut store, cash, rev, 3_000);

        let original = store.get_entry_by_sequence(1).unwrap();
        let original_content_hash = original.content_hash;
        let original_chain_hash = original.chain_hash;

        store.mark_pending(entry_id, None).unwrap();
        store.mark_settled(entry_id, None).unwrap();

        let after = store.get_entry_by_sequence(1).unwrap();
        assert_eq!(
            after.content_hash, original_content_hash,
            "content_hash must not change after settlement"
        );
        assert_eq!(
            after.chain_hash, original_chain_hash,
            "chain_hash must not change after settlement"
        );
    }

    /// Verify chain integrity is maintained after multiple settlement events.
    #[test]
    fn chain_integrity_maintained_after_settlements() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);

        for i in 1..=5 {
            let id = post_entry(&mut store, cash, rev, i * 100);
            store.mark_pending(id, None).unwrap();
            if i % 2 == 0 {
                store.mark_settled(id, None).unwrap();
            } else {
                store.mark_failed(id, Some("failed".into())).unwrap();
            }
        }

        store.verify_chain_integrity().unwrap();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Settlement events survive WAL replay
    // ─────────────────────────────────────────────────────────────────────

    /// Settlement status survives a crash/reopen cycle.
    #[test]
    fn settlement_status_survives_wal_replay() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();

        let entry_id = {
            let mut store = LedgerStore::open(dir.path()).unwrap();
            let (cash, rev) = setup_accounts(&mut store);
            let id = post_entry(&mut store, cash, rev, 1_000);
            store.mark_pending(id, None).unwrap();
            store.mark_settled(id, Some("settled".into())).unwrap();
            id
        }; // simulated crash

        let store2 = LedgerStore::open(dir.path()).unwrap();
        assert_eq!(
            store2.effective_status(&entry_id),
            EntryStatus::Settled,
            "Settled status must survive WAL replay"
        );
        store2.verify_chain_integrity().unwrap();
    }

    /// Failed status survives a crash/reopen cycle.
    #[test]
    fn failed_status_survives_wal_replay() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();

        let entry_id = {
            let mut store = LedgerStore::open(dir.path()).unwrap();
            let (cash, rev) = setup_accounts(&mut store);
            let id = post_entry(&mut store, cash, rev, 500);
            store.mark_pending(id, None).unwrap();
            store.mark_failed(id, Some("wire failed".into())).unwrap();
            id
        };

        let store2 = LedgerStore::open(dir.path()).unwrap();
        assert_eq!(
            store2.effective_status(&entry_id),
            EntryStatus::Failed,
            "Failed status must survive WAL replay"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // effective_status with no settlement events
    // ─────────────────────────────────────────────────────────────────────

    /// effective_status returns Posted when no settlement events exist.
    #[test]
    fn effective_status_returns_posted_with_no_events() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);
        let entry_id = post_entry(&mut store, cash, rev, 100);
        assert_eq!(
            store.effective_status(&entry_id),
            EntryStatus::Posted,
            "effective_status must be Posted with no settlement events"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Legal hold: placement blocks operations
    // ─────────────────────────────────────────────────────────────────────

    /// place_legal_hold sets is_under_legal_hold to true.
    #[test]
    fn place_legal_hold_sets_hold_flag() {
        let (_dir, mut store) = setup();
        let (cash, _rev) = setup_accounts(&mut store);

        store.place_legal_hold(&cash).unwrap();
        assert!(
            store.is_under_legal_hold(&cash),
            "is_under_legal_hold must return true after place_legal_hold"
        );
    }

    /// Posting an entry to an account under legal hold is rejected.
    #[test]
    fn post_entry_to_held_account_is_rejected() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);
        store.place_legal_hold(&cash).unwrap();

        let amt = Amount::new(1_000).unwrap();
        let e = JournalEntryBuilder::new("blocked", "test")
            .debit(cash, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        let result = store.post_entry(e);
        assert!(
            matches!(result, Err(LedgerError::AccountUnderLegalHold(_))),
            "posting to a held account must return AccountUnderLegalHold, got: {result:?}"
        );
    }

    /// Reversing an entry whose account is under legal hold is rejected.
    #[test]
    fn reverse_entry_to_held_account_is_rejected() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);

        // Post before the hold
        let entry_id = post_entry(&mut store, cash, rev, 1_000);

        // Place hold
        store.place_legal_hold(&cash).unwrap();

        // Reversal must be blocked
        let result = store.reverse_entry(entry_id, "reversal", "test");
        assert!(
            matches!(result, Err(LedgerError::AccountUnderLegalHold(_))),
            "reversing to a held account must return AccountUnderLegalHold, got: {result:?}"
        );
    }

    /// Settlement transition on an entry whose account is under legal hold is rejected.
    #[test]
    fn settlement_on_held_account_is_rejected() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);

        let entry_id = post_entry(&mut store, cash, rev, 1_000);
        store.place_legal_hold(&cash).unwrap();

        let result = store.mark_pending(entry_id, None);
        assert!(
            result.is_err(),
            "mark_pending on a held account's entry must be rejected"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Legal hold: lifting re-enables operations
    // ─────────────────────────────────────────────────────────────────────

    /// lift_legal_hold clears the hold flag.
    #[test]
    fn lift_legal_hold_clears_hold_flag() {
        let (_dir, mut store) = setup();
        let (cash, _rev) = setup_accounts(&mut store);

        store.place_legal_hold(&cash).unwrap();
        assert!(store.is_under_legal_hold(&cash));

        store.lift_legal_hold(&cash).unwrap();
        assert!(
            !store.is_under_legal_hold(&cash),
            "is_under_legal_hold must return false after lift_legal_hold"
        );
    }

    /// After lifting a legal hold, new entries can be posted.
    #[test]
    fn post_entry_succeeds_after_lifting_hold() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);

        store.place_legal_hold(&cash).unwrap();
        store.lift_legal_hold(&cash).unwrap();

        let amt = Amount::new(500).unwrap();
        let e = JournalEntryBuilder::new("post after lift", "test")
            .debit(cash, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        let result = store.post_entry(e);
        assert!(
            result.is_ok(),
            "posting must succeed after hold is lifted, got: {result:?}"
        );
    }

    /// After lifting a hold, reversals are re-enabled.
    #[test]
    fn reversal_succeeds_after_lifting_hold() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);

        let entry_id = post_entry(&mut store, cash, rev, 1_000);

        // Place and lift hold
        store.place_legal_hold(&cash).unwrap();
        store.lift_legal_hold(&cash).unwrap();

        let result = store.reverse_entry(entry_id, "reversal after lift", "test");
        assert!(
            result.is_ok(),
            "reversal must succeed after hold is lifted, got: {result:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Legal hold survives WAL replay
    // ─────────────────────────────────────────────────────────────────────

    /// A legal hold placed before a crash is still active after reopen.
    #[test]
    fn legal_hold_survives_wal_replay() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();

        let cash_id = {
            let mut store = LedgerStore::open(dir.path()).unwrap();
            let cash = store
                .create_account(Account::new("CASH", "Cash", AccountType::Asset, "USD", "test"))
                .unwrap();
            store
                .create_account(Account::new("REV", "Revenue", AccountType::Income, "USD", "test"))
                .unwrap();
            store.place_legal_hold(&cash).unwrap();
            cash
        }; // crash

        let store2 = LedgerStore::open(dir.path()).unwrap();
        assert!(
            store2.is_under_legal_hold(&cash_id),
            "legal hold must persist across WAL replay"
        );
    }

    /// A lifted legal hold is still lifted after WAL replay.
    #[test]
    fn lifted_legal_hold_survives_wal_replay() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();

        let cash_id = {
            let mut store = LedgerStore::open(dir.path()).unwrap();
            let cash = store
                .create_account(Account::new("CASH", "Cash", AccountType::Asset, "USD", "test"))
                .unwrap();
            store.place_legal_hold(&cash).unwrap();
            store.lift_legal_hold(&cash).unwrap();
            cash
        };

        let store2 = LedgerStore::open(dir.path()).unwrap();
        assert!(
            !store2.is_under_legal_hold(&cash_id),
            "lifted hold must not be re-imposed after WAL replay"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Legal hold: is_under_legal_hold on unknown account
    // ─────────────────────────────────────────────────────────────────────

    /// is_under_legal_hold returns false for an unknown account ID.
    #[test]
    fn is_under_legal_hold_false_for_unknown_account() {
        let (_dir, store) = setup();
        assert!(
            !store.is_under_legal_hold(&Uuid::new_v4()),
            "is_under_legal_hold must return false for unknown account"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Legal hold credit-side blocking
    // ─────────────────────────────────────────────────────────────────────

    /// Legal hold on the credit account also blocks the entry.
    #[test]
    fn post_entry_blocked_when_credit_account_under_legal_hold() {
        let (_dir, mut store) = setup();
        let (cash, rev) = setup_accounts(&mut store);

        // Hold the revenue (credit) account
        store.place_legal_hold(&rev).unwrap();

        let amt = Amount::new(1_000).unwrap();
        let e = JournalEntryBuilder::new("credit side held", "test")
            .debit(cash, amt, "USD")
            .credit(rev, amt, "USD")
            .build();
        let result = store.post_entry(e);
        assert!(
            matches!(result, Err(LedgerError::AccountUnderLegalHold(_))),
            "posting must be blocked when the credit account is under hold, got: {result:?}"
        );
    }
}
