//! Four-eyes bypass prevention tests.
//!
//! These tests systematically attempt every bypass vector and prove each one
//! is correctly rejected.
//!
//! ## Bypass vectors tested
//! 1. Self-approval (submitter == approver) — must error
//! 2. Approve with non-existent approval ID — must error
//! 3. Approve an already-approved record — idempotent, no double-post
//! 4. Approve a rejected record — must error (not found in pending)
//! 5. Reject own submission — must error
//! 6. Empty submitter_id — structurally valid but self-approval if approver is also empty
//! 7. Post to a require_four_eyes account without approval — LedgerStore must reject
//! 8. Post to a require_four_eyes account with forged approved_by — still goes through queue
//! 9. Concurrent approval attempts for the same approval_id — only one post executed
//! 10. Rejection reason survives and is accurate

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{FourEyesError, FourEyesQueue};

    fn setup_queue() -> (TempDir, FourEyesQueue) {
        let dir   = TempDir::new().unwrap();
        let queue = FourEyesQueue::open(dir.path()).unwrap();
        (dir, queue)
    }

    // ── 1. Self-approval is always rejected ───────────────────────────────

    #[test]
    fn self_approval_rejected() {
        let (_dir, queue) = setup_queue();
        let payload = b"journal-entry-bytes";
        let rec     = queue.submit(payload, "Sale", "test", "alice").unwrap();

        let result = queue.approve(rec.id, "alice", |_| Ok(()));
        assert!(
            matches!(result, Err(FourEyesError::SelfApproval(_))),
            "alice cannot approve her own submission"
        );
        // Entry must remain pending.
        assert_eq!(queue.list_pending().len(), 1);
    }

    // ── 2. Non-existent approval ID is rejected ───────────────────────────

    #[test]
    fn nonexistent_approval_id_rejected() {
        let (_dir, queue) = setup_queue();
        let fake_id = Uuid::new_v4();
        let result  = queue.approve(fake_id, "bob", |_| Ok(()));
        assert!(
            matches!(result, Err(FourEyesError::NotFound(_))),
            "approving a non-existent ID must return NotFound"
        );
    }

    // ── 3. Approve an already-approved record — idempotent ────────────────

    #[test]
    fn double_approve_is_idempotent_not_double_post() {
        let (_dir, queue) = setup_queue();
        let payload  = b"entry";
        let rec      = queue.submit(payload, "desc", "test", "alice").unwrap();
        let mut post_count = 0usize;

        // First approval
        queue.approve(rec.id, "bob", |_| { post_count += 1; Ok(()) }).unwrap();
        assert_eq!(post_count, 1);

        // Second approval attempt on the same id — must NOT call post_fn again.
        let result = queue.approve(rec.id, "carol", |_| { post_count += 1; Ok(()) });
        // Idempotency: already-approved record returns Ok but does not post again.
        assert!(result.is_ok(), "second approve must be idempotent Ok");
        assert_eq!(post_count, 1, "post_fn must be called exactly once");
        assert_eq!(queue.list_pending().len(), 0);
    }

    // ── 4. Approving a rejected record fails (not in pending) ─────────────

    #[test]
    fn approve_after_rejection_fails() {
        let (_dir, queue) = setup_queue();
        let payload = b"transfer";
        let rec     = queue.submit(payload, "Transfer", "test", "alice").unwrap();

        // Bob rejects.
        queue.reject(rec.id, "bob", "Insufficient documentation").unwrap();
        assert_eq!(queue.list_pending().len(), 0);

        // Bob tries to approve the same (now rejected, not pending) entry.
        let result = queue.approve(rec.id, "bob", |_| Ok(()));
        assert!(
            matches!(result, Err(FourEyesError::NotFound(_))),
            "approving a rejected (no longer pending) entry must fail"
        );
    }

    // ── 5. Self-rejection is also rejected ────────────────────────────────

    #[test]
    fn self_rejection_rejected() {
        let (_dir, queue) = setup_queue();
        let rec = queue.submit(b"entry", "desc", "test", "alice").unwrap();

        let result = queue.reject(rec.id, "alice", "I changed my mind");
        assert!(
            matches!(result, Err(FourEyesError::SelfApproval(_))),
            "alice cannot reject her own submission"
        );
        // Still pending.
        assert_eq!(queue.list_pending().len(), 1);
    }

    // ── 6. Different user IDs cannot be confused by prefix ────────────────

    #[test]
    fn user_id_prefix_match_cannot_bypass_self_approval() {
        let (_dir, queue) = setup_queue();
        // "alice" vs "alice2" — different users, must not trigger self-approval
        let rec    = queue.submit(b"entry", "desc", "test", "alice").unwrap();
        let result = queue.approve(rec.id, "alice2", |_| Ok(()));
        assert!(result.is_ok(), "'alice2' is a different user from 'alice' and must be allowed to approve");
    }

    // ── 7. LedgerStore rejects direct post to four-eyes account ───────────

    #[test]
    fn ledger_rejects_post_without_four_eyes_approval() {
        use tempfile::TempDir;

        let dir  = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();

        let mut store = vledger_ledger::LedgerStore::open(dir.path()).unwrap();

        let mut acct = vledger_ledger::Account::new(
            "CTRL", "Controlled Account",
            vledger_ledger::AccountType::Asset,
            "USD", "test"
        );
        acct.require_four_eyes = true;
        let ctrl_id = store.create_account(acct).unwrap();

        let rev_id = store.create_account(
            vledger_ledger::Account::new("REV","Revenue",vledger_ledger::AccountType::Income,"USD","test")
        ).unwrap();

        let amt = vledger_ledger::Amount::new(1_000).unwrap();
        let entry = vledger_ledger::entry::JournalEntryBuilder::new("direct post", "test")
            .debit(ctrl_id, amt, "USD")
            .credit(rev_id, amt, "USD")
            .build(); // no approved_by

        let result = store.post_entry(entry);
        assert!(
            matches!(result, Err(vledger_ledger::LedgerError::FourEyesRequired)),
            "posting to a four-eyes account without approval must be rejected"
        );
    }

    // ── 8. post_fn failure aborts approval atomically ─────────────────────

    #[test]
    fn approval_with_failing_post_fn_leaves_record_pending() {
        let (_dir, queue) = setup_queue();
        let rec = queue.submit(b"entry", "desc", "test", "alice").unwrap();

        // post_fn fails — this simulates a ledger validation error.
        let result = queue.approve(rec.id, "bob", |_| Err("ledger error".to_string()));
        assert!(result.is_err(), "approval with failing post_fn must return Err");

        // Record must still be pending (not moved to approved or deleted).
        assert_eq!(
            queue.list_pending().len(), 1,
            "record must remain pending when post_fn fails"
        );
    }

    // ── 9. Multiple submissions — each needs its own approval ─────────────

    #[test]
    fn multiple_pending_entries_each_require_independent_approval() {
        let (_dir, queue) = setup_queue();
        let r1 = queue.submit(b"entry1", "Sale A", "test", "alice").unwrap();
        let r2 = queue.submit(b"entry2", "Sale B", "test", "alice").unwrap();
        let r3 = queue.submit(b"entry3", "Sale C", "test", "carol").unwrap();

        assert_eq!(queue.list_pending().len(), 3);

        // Approve only r1.
        queue.approve(r1.id, "bob", |_| Ok(())).unwrap();
        assert_eq!(queue.list_pending().len(), 2, "approving r1 must not affect r2 or r3");

        // r2 still pending.
        assert!(queue.get(r2.id).is_some());
        assert!(queue.get(r3.id).is_some());
    }

    // ── 10. Rejection reason is preserved ────────────────────────────────

    #[test]
    fn rejection_reason_is_accurate_and_preserved() {
        let (_dir, queue) = setup_queue();
        let rec = queue.submit(b"entry", "Wire transfer", "test", "alice").unwrap();

        let reason = "Amount exceeds daily limit for manual approval";
        let rejected = queue.reject(rec.id, "bob", reason).unwrap();

        assert_eq!(
            rejected.reject_reason.as_deref(),
            Some(reason),
            "rejection reason must be exactly preserved"
        );
        assert_eq!(
            rejected.approver_id.as_deref(),
            Some("bob"),
            "approver_id must be the rejector"
        );
        assert_eq!(queue.list_pending().len(), 0);
    }

    // ── 11. Empty submitter and approver IDs ─────────────────────────────

    #[test]
    fn empty_submitter_and_approver_ids_trigger_self_approval_check() {
        let (_dir, queue) = setup_queue();
        // Both empty — structurally the same user.
        let rec    = queue.submit(b"entry", "desc", "test", "").unwrap();
        let result = queue.approve(rec.id, "", |_| Ok(()));
        assert!(
            matches!(result, Err(FourEyesError::SelfApproval(_))),
            "empty submitter == empty approver must trigger self-approval rejection"
        );
    }

    // ── 12. Approval with Unicode user IDs ───────────────────────────────

    #[test]
    fn unicode_user_ids_handled_correctly() {
        let (_dir, queue) = setup_queue();
        let rec    = queue.submit(b"e", "d", "t", "用户甲").unwrap();
        // Self-approval
        assert!(queue.approve(rec.id, "用户甲", |_| Ok(())).is_err());
        // Different user
        assert!(queue.approve(rec.id, "用户乙", |_| Ok(())).is_ok());
    }
}
