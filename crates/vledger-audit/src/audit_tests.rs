/// Audit log tests.
///
/// Covers: AuditLog open/append/verify_chain, hash chaining correctness,
/// WORM append-only semantics, event sequencing, and chain_tip tracking.

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{
        event::AuditEventKind,
        log::AuditLog,
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn open_log(dir: &TempDir) -> AuditLog {
        std::fs::create_dir_all(dir.path().join("audit")).unwrap();
        AuditLog::open(dir.path().join("audit").join("audit.log")).unwrap()
    }

    fn entry_posted_event() -> AuditEventKind {
        AuditEventKind::EntryPosted {
            entry_id: Uuid::new_v4(),
            entry_sequence: 1,
            domain: "main".to_string(),
            amount_sum: 10000,
            caller_id: "test".to_string(),
        }
    }

    fn auth_event(success: bool) -> AuditEventKind {
        AuditEventKind::AuthEvent {
            caller_id: "test_user".to_string(),
            success,
            peer_addr: "127.0.0.1:12345".to_string(),
        }
    }

    fn account_created_event() -> AuditEventKind {
        AuditEventKind::AccountCreated {
            account_id: Uuid::new_v4(),
            account_code: "CASH".to_string(),
            domain: "main".to_string(),
            caller_id: "admin".to_string(),
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // OPEN AND CONSTRUCTION
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_opens_on_new_directory() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        assert_eq!(log.next_sequence(), 1, "new log must start at sequence 1");
    }

    #[test]
    fn audit_log_file_created_on_open() {
        let dir = TempDir::new().unwrap();
        let _log = open_log(&dir);
        assert!(
            dir.path().join("audit").join("audit.log").exists(),
            "audit.log file must be created on open"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // APPEND
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn append_returns_event_with_correct_sequence() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let event = log.append(entry_posted_event()).unwrap();
        assert_eq!(event.sequence, 1);
    }

    #[test]
    fn append_increments_sequence() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let e1 = log.append(entry_posted_event()).unwrap();
        let e2 = log.append(auth_event(true)).unwrap();
        let e3 = log.append(account_created_event()).unwrap();
        assert_eq!(e1.sequence, 1);
        assert_eq!(e2.sequence, 2);
        assert_eq!(e3.sequence, 3);
        assert_eq!(log.next_sequence(), 4);
    }

    #[test]
    fn append_produces_non_empty_hashes() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let event = log.append(entry_posted_event()).unwrap();
        assert!(
            !event.content_hash.is_empty(),
            "content_hash must not be empty"
        );
        assert!(
            !event.chain_hash.is_empty(),
            "chain_hash must not be empty"
        );
    }

    #[test]
    fn append_first_event_prev_hash_is_zero() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let event = log.append(entry_posted_event()).unwrap();
        // First event's prev_hash must be the zero hash (64 hex zeros).
        assert_eq!(
            event.prev_hash,
            "0".repeat(64),
            "first event prev_hash must be ZERO_HASH"
        );
    }

    #[test]
    fn append_second_event_prev_hash_equals_first_chain_hash() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let e1 = log.append(entry_posted_event()).unwrap();
        let e2 = log.append(auth_event(true)).unwrap();
        assert_eq!(
            e2.prev_hash, e1.chain_hash,
            "second event prev_hash must equal first event chain_hash"
        );
    }

    #[test]
    fn append_event_verify_passes() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let event = log.append(entry_posted_event()).unwrap();
        assert!(event.verify(), "freshly appended event must self-verify");
    }

    // ══════════════════════════════════════════════════════════════════════
    // VERIFY_CHAIN
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn verify_chain_empty_log_returns_zero() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let count = log.verify_chain().unwrap();
        assert_eq!(count, 0, "empty log must verify with count 0");
    }

    #[test]
    fn verify_chain_single_event_ok() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        log.append(entry_posted_event()).unwrap();
        let count = log.verify_chain().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn verify_chain_multiple_events_ok() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        for _ in 0..20 {
            log.append(entry_posted_event()).unwrap();
        }
        let count = log.verify_chain().unwrap();
        assert_eq!(count, 20);
    }

    #[test]
    fn verify_chain_all_event_kinds_ok() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);

        log.append(entry_posted_event()).unwrap();
        log.append(auth_event(true)).unwrap();
        log.append(auth_event(false)).unwrap();
        log.append(account_created_event()).unwrap();
        log.append(AuditEventKind::AccountClosed {
            account_id: Uuid::new_v4(),
            caller_id: "admin".to_string(),
        }).unwrap();
        log.append(AuditEventKind::BackupCreated {
            path: "/tmp/backup.tar".to_string(),
            size_bytes: 1024 * 1024,
            caller_id: "admin".to_string(),
        }).unwrap();

        let count = log.verify_chain().unwrap();
        assert_eq!(count, 6);
    }

    // ══════════════════════════════════════════════════════════════════════
    // CHAIN TIP TRACKING
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn chain_tip_updates_after_each_append() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);

        let tip_before = log.chain_tip();
        let e1 = log.append(entry_posted_event()).unwrap();
        let tip_after_1 = log.chain_tip();

        assert_ne!(tip_before, tip_after_1, "tip must change after first append");
        assert_eq!(
            tip_after_1, e1.chain_hash,
            "chain_tip must equal last event chain_hash"
        );

        let e2 = log.append(auth_event(true)).unwrap();
        let tip_after_2 = log.chain_tip();
        assert_eq!(tip_after_2, e2.chain_hash);
    }

    // ══════════════════════════════════════════════════════════════════════
    // PERSISTENCE — log survives reopen
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit").join("audit.log");
        std::fs::create_dir_all(dir.path().join("audit")).unwrap();

        // Write 5 events.
        {
            let log = AuditLog::open(&log_path).unwrap();
            for _ in 0..5 {
                log.append(entry_posted_event()).unwrap();
            }
        }

        // Reopen and verify.
        let log2 = AuditLog::open(&log_path).unwrap();
        assert_eq!(log2.next_sequence(), 6, "sequence must resume after reopen");
        let count = log2.verify_chain().unwrap();
        assert_eq!(count, 5, "all events must verify after reopen");
    }

    #[test]
    fn audit_log_appends_after_reopen_maintain_chain() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit").join("audit.log");
        std::fs::create_dir_all(dir.path().join("audit")).unwrap();

        // Write 3 events.
        {
            let log = AuditLog::open(&log_path).unwrap();
            for _ in 0..3 {
                log.append(entry_posted_event()).unwrap();
            }
        }

        // Reopen and append 2 more.
        {
            let log = AuditLog::open(&log_path).unwrap();
            log.append(auth_event(true)).unwrap();
            log.append(account_created_event()).unwrap();
        }

        // Verify the full chain of 5.
        let log3 = AuditLog::open(&log_path).unwrap();
        let count = log3.verify_chain().unwrap();
        assert_eq!(count, 5, "full chain must verify after reopen + append");
    }

    // ══════════════════════════════════════════════════════════════════════
    // CHAIN INTEGRITY — different events produce different hashes
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn different_events_produce_different_content_hashes() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let e1 = log.append(entry_posted_event()).unwrap();
        let e2 = log.append(auth_event(false)).unwrap();
        assert_ne!(
            e1.content_hash, e2.content_hash,
            "different events must produce different content hashes"
        );
    }

    #[test]
    fn chain_hashes_are_unique_across_events() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let mut hashes = std::collections::HashSet::new();
        for _ in 0..10 {
            let e = log.append(entry_posted_event()).unwrap();
            assert!(
                hashes.insert(e.chain_hash.clone()),
                "chain hashes must be unique across events"
            );
        }
    }
}
