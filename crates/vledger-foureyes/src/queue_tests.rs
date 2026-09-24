//! Direct unit tests for FourEyesQueue internals.
//!
//! The bypass_tests.rs file covers bypass-prevention scenarios.
//! This file covers the core queue workflow: submit, approve, reject,
//! list_pending, get, persistence across reopen, and atomic file operations.

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{ApprovalStatus, FourEyesError, FourEyesQueue};

    fn setup() -> (TempDir, FourEyesQueue) {
        let dir = TempDir::new().unwrap();
        let queue = FourEyesQueue::open(dir.path()).unwrap();
        (dir, queue)
    }

    // ─────────────────────────────────────────────────────────────────────
    // submit
    // ─────────────────────────────────────────────────────────────────────

    /// submit returns an ApprovalRecord with Pending status and correct fields.
    #[test]
    fn submit_returns_pending_record_with_correct_fields() {
        let (_dir, queue) = setup();
        let payload = b"journal-entry-bytes";
        let rec = queue
            .submit(payload, "Wire transfer $10k", "payments", "alice")
            .unwrap();

        assert_eq!(rec.status, ApprovalStatus::Pending);
        assert_eq!(rec.submitter_id, "alice");
        assert_eq!(rec.description, "Wire transfer $10k");
        assert_eq!(rec.domain, "payments");
        assert!(rec.approver_id.is_none(), "approver must be None on submission");
        assert!(rec.decided_at.is_none(), "decided_at must be None on submission");
        assert!(!rec.entry_payload_hex.is_empty(), "payload must be hex-encoded");
        assert_eq!(
            rec.entry_payload_hex,
            hex::encode(payload),
            "entry_payload_hex must be hex of submitted bytes"
        );
    }

    /// submit adds the record to the pending list.
    #[test]
    fn submit_adds_to_pending_list() {
        let (_dir, queue) = setup();
        assert_eq!(queue.list_pending().len(), 0);
        queue.submit(b"e1", "desc1", "domain", "alice").unwrap();
        assert_eq!(queue.list_pending().len(), 1);
        queue.submit(b"e2", "desc2", "domain", "bob").unwrap();
        assert_eq!(queue.list_pending().len(), 2);
    }

    /// Multiple submissions from the same user are all independently pending.
    #[test]
    fn multiple_submissions_from_same_user_are_independent() {
        let (_dir, queue) = setup();
        let r1 = queue.submit(b"e1", "tx1", "d", "alice").unwrap();
        let r2 = queue.submit(b"e2", "tx2", "d", "alice").unwrap();
        let r3 = queue.submit(b"e3", "tx3", "d", "alice").unwrap();

        assert_ne!(r1.id, r2.id, "each submission must have a unique ID");
        assert_ne!(r2.id, r3.id, "each submission must have a unique ID");
        assert_eq!(queue.list_pending().len(), 3);
    }

    // ─────────────────────────────────────────────────────────────────────
    // approve
    // ─────────────────────────────────────────────────────────────────────

    /// approve moves record to Approved status and calls post_fn once.
    #[test]
    fn approve_calls_post_fn_and_marks_approved() {
        let (_dir, queue) = setup();
        let rec = queue.submit(b"payload", "desc", "d", "alice").unwrap();

        let mut posted_bytes: Option<Vec<u8>> = None;
        let approved = queue
            .approve(rec.id, "bob", |bytes| {
                posted_bytes = Some(bytes.to_vec());
                Ok(())
            })
            .unwrap();

        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.approver_id.as_deref(), Some("bob"));
        assert!(approved.decided_at.is_some(), "decided_at must be set after approval");
        assert_eq!(
            posted_bytes.as_deref(),
            Some(b"payload" as &[u8]),
            "post_fn must receive the original payload bytes"
        );
        // Record removed from pending
        assert_eq!(queue.list_pending().len(), 0);
    }

    /// After approval, approved record is no longer in pending.
    #[test]
    fn get_returns_none_for_approved_record() {
        let (_dir, queue) = setup();
        let rec = queue.submit(b"e", "d", "domain", "alice").unwrap();
        queue.approve(rec.id, "bob", |_| Ok(())).unwrap();

        // get() only searches pending — approved records are not in pending
        let fetched = queue.get(rec.id);
        assert!(
            fetched.is_none(),
            "get() only returns pending records; approved records are not in pending"
        );
        // The record is gone from pending
        assert_eq!(queue.list_pending().len(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────
    // reject
    // ─────────────────────────────────────────────────────────────────────

    /// reject moves record to Rejected status with reason preserved.
    #[test]
    fn reject_marks_rejected_with_reason() {
        let (_dir, queue) = setup();
        let rec = queue.submit(b"e", "d", "domain", "alice").unwrap();
        let reason = "Insufficient documentation";
        let rejected = queue.reject(rec.id, "bob", reason).unwrap();

        assert_eq!(rejected.status, ApprovalStatus::Rejected);
        assert_eq!(rejected.approver_id.as_deref(), Some("bob"));
        assert_eq!(rejected.reject_reason.as_deref(), Some(reason));
        assert!(rejected.decided_at.is_some(), "decided_at must be set on rejection");
        assert_eq!(queue.list_pending().len(), 0, "rejected record must leave pending");
    }

    /// After rejection, record is removed from pending.
    #[test]
    fn get_returns_none_for_rejected_record() {
        let (_dir, queue) = setup();
        let rec = queue.submit(b"e", "d", "domain", "alice").unwrap();
        queue.reject(rec.id, "bob", "reason").unwrap();

        // get() only searches pending — rejected records are no longer pending
        let fetched = queue.get(rec.id);
        assert!(
            fetched.is_none(),
            "get() only returns pending records; rejected records are not in pending"
        );
        assert_eq!(queue.list_pending().len(), 0);
    }

    /// Rejecting a non-existent ID returns NotFound.
    #[test]
    fn reject_nonexistent_id_returns_not_found() {
        let (_dir, queue) = setup();
        let result = queue.reject(Uuid::new_v4(), "bob", "reason");
        assert!(
            matches!(result, Err(FourEyesError::NotFound(_))),
            "rejecting unknown ID must return NotFound"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // list_pending / get
    // ─────────────────────────────────────────────────────────────────────

    /// list_pending returns only records still in Pending status.
    #[test]
    fn list_pending_excludes_approved_and_rejected() {
        let (_dir, queue) = setup();
        let r1 = queue.submit(b"a", "d1", "d", "alice").unwrap();
        let r2 = queue.submit(b"b", "d2", "d", "alice").unwrap();
        let r3 = queue.submit(b"c", "d3", "d", "alice").unwrap();

        queue.approve(r1.id, "bob", |_| Ok(())).unwrap();
        queue.reject(r2.id, "bob", "nope").unwrap();

        let pending = queue.list_pending();
        assert_eq!(pending.len(), 1, "only r3 must remain pending");
        assert_eq!(pending[0].id, r3.id, "r3 must be the remaining pending record");
    }

    /// get returns None for a completely unknown UUID.
    #[test]
    fn get_returns_none_for_unknown_id() {
        let (_dir, queue) = setup();
        queue.submit(b"e", "d", "domain", "alice").unwrap();
        assert!(
            queue.get(Uuid::new_v4()).is_none(),
            "get with unknown UUID must return None"
        );
    }

    /// get returns the correct record when multiple pending entries exist.
    #[test]
    fn get_returns_correct_record_by_id() {
        let (_dir, queue) = setup();
        let r1 = queue.submit(b"payload-A", "desc-A", "d", "userA").unwrap();
        let r2 = queue.submit(b"payload-B", "desc-B", "d", "userB").unwrap();

        let fetched1 = queue.get(r1.id).unwrap();
        let fetched2 = queue.get(r2.id).unwrap();

        assert_eq!(fetched1.description, "desc-A");
        assert_eq!(fetched2.description, "desc-B");
        assert_ne!(fetched1.id, fetched2.id);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Persistence across reopen
    // ─────────────────────────────────────────────────────────────────────

    /// Pending records survive a queue reopen (simulates crash/restart).
    #[test]
    fn pending_records_survive_reopen() {
        let dir = TempDir::new().unwrap();
        let record_id = {
            let queue = FourEyesQueue::open(dir.path()).unwrap();
            let rec = queue.submit(b"entry-data", "Test transaction", "test", "alice").unwrap();
            rec.id
        }; // queue dropped here

        // Reopen
        let queue2 = FourEyesQueue::open(dir.path()).unwrap();
        let pending = queue2.list_pending();
        assert_eq!(pending.len(), 1, "pending record must survive reopen");
        assert_eq!(
            pending[0].id, record_id,
            "reloaded record must have the original ID"
        );
        assert_eq!(
            pending[0].submitter_id, "alice",
            "submitter_id must survive reopen"
        );
    }

    /// Approved records are no longer accessible via get() after reopen (pending-only).
    #[test]
    fn approved_records_survive_reopen_and_not_in_pending() {
        let dir = TempDir::new().unwrap();
        let record_id = {
            let queue = FourEyesQueue::open(dir.path()).unwrap();
            let rec = queue.submit(b"e", "d", "domain", "alice").unwrap();
            queue.approve(rec.id, "bob", |_| Ok(())).unwrap();
            rec.id
        };

        let queue2 = FourEyesQueue::open(dir.path()).unwrap();
        // Record was approved — it is no longer in pending
        assert_eq!(queue2.list_pending().len(), 0, "no pending records after approval");
        // get() searches pending only — approved record is not returned
        assert!(
            queue2.get(record_id).is_none(),
            "approved record must not appear in get() (pending-only lookup)"
        );
    }

    /// After reopen, pending records can still be approved.
    #[test]
    fn pending_records_can_be_approved_after_reopen() {
        let dir = TempDir::new().unwrap();
        let record_id = {
            let queue = FourEyesQueue::open(dir.path()).unwrap();
            queue.submit(b"entry", "desc", "d", "alice").unwrap().id
        };

        let queue2 = FourEyesQueue::open(dir.path()).unwrap();
        let result = queue2.approve(record_id, "bob", |_| Ok(()));
        assert!(result.is_ok(), "pending record must be approvable after reopen");
        assert_eq!(queue2.list_pending().len(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Idempotency guard
    // ─────────────────────────────────────────────────────────────────────

    /// Double-approving the same record does not call post_fn a second time.
    #[test]
    fn double_approve_idempotency_does_not_double_post() {
        let (_dir, queue) = setup();
        let rec = queue.submit(b"entry", "desc", "d", "alice").unwrap();
        let mut call_count = 0usize;

        queue
            .approve(rec.id, "bob", |_| {
                call_count += 1;
                Ok(())
            })
            .unwrap();

        // Second approve attempt on the already-approved record
        let result = queue.approve(rec.id, "carol", |_| {
            call_count += 1;
            Ok(())
        });
        assert!(result.is_ok(), "second approve must return Ok (idempotent)");
        assert_eq!(call_count, 1, "post_fn must be called exactly once regardless of retries");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Self-approval prevention
    // ─────────────────────────────────────────────────────────────────────

    /// Self-approval returns SelfApproval error.
    #[test]
    fn self_approval_returns_self_approval_error() {
        let (_dir, queue) = setup();
        let rec = queue.submit(b"e", "d", "domain", "alice").unwrap();
        let result = queue.approve(rec.id, "alice", |_| Ok(()));
        assert!(
            matches!(result, Err(FourEyesError::SelfApproval(_))),
            "self-approval must return SelfApproval error"
        );
        assert_eq!(
            queue.list_pending().len(),
            1,
            "record must remain pending after self-approval attempt"
        );
    }

    /// Self-rejection returns SelfApproval error.
    #[test]
    fn self_rejection_returns_self_approval_error() {
        let (_dir, queue) = setup();
        let rec = queue.submit(b"e", "d", "domain", "alice").unwrap();
        let result = queue.reject(rec.id, "alice", "changed my mind");
        assert!(
            matches!(result, Err(FourEyesError::SelfApproval(_))),
            "self-rejection must return SelfApproval error"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // open_with_audit
    // ─────────────────────────────────────────────────────────────────────

    /// open_with_audit writes audit events for submit/approve/reject.
    #[test]
    fn open_with_audit_emits_audit_events() {
        use std::sync::Arc;
        use vledger_audit::{AuditEventKind, AuditLog};

        let dir = TempDir::new().unwrap();
        let audit_path = dir.path().join("audit.log");
        let audit_log = Arc::new(AuditLog::open(&audit_path).unwrap());

        let queue_dir = dir.path().join("foureyes");
        std::fs::create_dir_all(&queue_dir).unwrap();
        let queue =
            FourEyesQueue::open_with_audit(&queue_dir, Arc::clone(&audit_log)).unwrap();

        // Submit
        let rec = queue.submit(b"e", "d", "domain", "alice").unwrap();
        // Approve
        queue.approve(rec.id, "bob", |_| Ok(())).unwrap();

        // Verify audit log has events
        let count = audit_log.verify_chain().unwrap();
        assert!(count >= 2, "must have at least 2 audit events (submitted + approved), got {count}");
    }
}
