//! The four-eyes approval queue.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::FourEyesError;
use crate::record::{ApprovalRecord, ApprovalStatus};

/// Four-eyes approval queue.  Thread-safe — wrap in `Arc` to share.
pub struct FourEyesQueue {
    dir:     PathBuf,
    /// In-memory index of all pending records (rebuilt from disk on open).
    pending: Mutex<HashMap<Uuid, ApprovalRecord>>,
    /// Optional shared audit log — when `Some`, submit/approve/reject each
    /// write a corresponding `AuditEventKind` entry.
    audit_log: Option<std::sync::Arc<vledger_audit::AuditLog>>,
}

impl FourEyesQueue {
    /// Open (or create) the queue using files in `queue_dir`.
    pub fn open(queue_dir: impl AsRef<Path>) -> Result<Self, FourEyesError> {
        let dir = queue_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;

        let mut pending = HashMap::new();
        Self::load_pending(&dir, &mut pending)?;

        info!(dir = %dir.display(), pending = pending.len(), "FourEyesQueue opened");
        Ok(Self { dir, pending: Mutex::new(pending), audit_log: None })
    }

    /// Open with a shared audit log so every approval action is recorded.
    pub fn open_with_audit(
        queue_dir: impl AsRef<Path>,
        audit_log: std::sync::Arc<vledger_audit::AuditLog>,
    ) -> Result<Self, FourEyesError> {
        let mut q = Self::open(queue_dir)?;
        q.audit_log = Some(audit_log);
        Ok(q)
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Submit a journal entry for four-eyes approval.
    ///
    /// `entry_bytes` is the bincode-serialised `JournalEntry`.
    /// Returns the `ApprovalRecord` (including its `id`) for tracking.
    pub fn submit(
        &self,
        entry_bytes:  &[u8],
        description:  impl Into<String>,
        domain:       impl Into<String>,
        submitter_id: impl Into<String>,
    ) -> Result<ApprovalRecord, FourEyesError> {
        let record = ApprovalRecord {
            id:                Uuid::new_v4(),
            status:            ApprovalStatus::Pending,
            submitter_id:      submitter_id.into(),
            approver_id:       None,
            reject_reason:     None,
            submitted_at:      Utc::now(),
            decided_at:        None,
            entry_payload_hex: hex::encode(entry_bytes),
            description:       description.into(),
            domain:            domain.into(),
        };

        self.persist_pending(&record)?;

        {
            let mut pending = self.pending.lock().unwrap();
            pending.insert(record.id, record.clone());
        }

        // ── Audit: FourEyesSubmitted ──────────────────────────────────────
        if let Some(log) = &self.audit_log {
            let _ = log.append(vledger_audit::AuditEventKind::FourEyesSubmitted {
                approval_id: record.id,
                entry_id:    record.id, // best proxy without separate entry_id param
                submitter:   record.submitter_id.clone(),
                domain:      record.domain.clone(),
            });
        }

        info!(id = %record.id, submitter = %record.submitter_id, "Four-eyes entry submitted");
        Ok(record)
    }

    /// Approve a pending entry.
    ///
    /// `post_fn` is called with the raw entry bytes — the caller should
    /// deserialise and call `LedgerStore::post_entry`.  Returns the approved
    /// `ApprovalRecord`.
    ///
    /// ## Idempotency guard (Fix #8)
    /// If the process crashes after `post_fn` succeeds but before the atomic
    /// rename that removes the entry from `pending.jsonl`, a second `approve`
    /// call on restart would attempt to post the same entry again.  We detect
    /// this by checking `approved.jsonl` for the `approval_id` before calling
    /// `post_fn`, and returning the already-approved record without re-posting
    /// if it is found there.
    pub fn approve<F>(
        &self,
        approval_id: Uuid,
        approver_id: impl Into<String>,
        post_fn:     F,
    ) -> Result<ApprovalRecord, FourEyesError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        let approver_id = approver_id.into();

        // ── Idempotency check ─────────────────────────────────────────────
        // If a previous approve() call succeeded with post_fn but crashed
        // before the pending-file rewrite completed, the record already lives
        // in approved.jsonl.  Return it immediately without re-posting.
        if let Some(already) = self.find_in_decided("approved", approval_id)? {
            warn!(id = %approval_id, "approve() called on already-approved entry — returning existing record (idempotent)");
            return Ok(already);
        }

        let mut record = self.get_pending(approval_id)?;

        if record.submitter_id == approver_id {
            return Err(FourEyesError::SelfApproval(approver_id));
        }

        // Decode the entry bytes and post via the provided function
        let entry_bytes = hex::decode(&record.entry_payload_hex)
            .map_err(|e| FourEyesError::Serialisation(e.to_string()))?;

        post_fn(&entry_bytes).map_err(FourEyesError::PostFailed)?;

        record.status      = ApprovalStatus::Approved;
        record.approver_id = Some(approver_id.clone());
        record.decided_at  = Some(Utc::now());

        self.persist_decided(&record, "approved")?;
        self.remove_pending(approval_id)?;
        self.pending.lock().unwrap().remove(&approval_id);

        // ── Audit: FourEyesApproved ───────────────────────────────────────
        if let Some(log) = &self.audit_log {
            let _ = log.append(vledger_audit::AuditEventKind::FourEyesApproved {
                approval_id,
                approver: approver_id.clone(),
            });
        }

        info!(id = %approval_id, approver = %approver_id, "Four-eyes entry approved");
        Ok(record)
    }

    /// Reject a pending entry.  The entry is NOT posted to the ledger.
    pub fn reject(
        &self,
        approval_id: Uuid,
        approver_id: impl Into<String>,
        reason:      impl Into<String>,
    ) -> Result<ApprovalRecord, FourEyesError> {
        let approver_id = approver_id.into();
        let reason      = reason.into();

        let mut record = self.get_pending(approval_id)?;

        if record.submitter_id == approver_id {
            return Err(FourEyesError::SelfApproval(approver_id));
        }

        record.status        = ApprovalStatus::Rejected;
        record.approver_id   = Some(approver_id.clone());
        record.reject_reason = Some(reason.clone());
        record.decided_at    = Some(Utc::now());

        self.persist_decided(&record, "rejected")?;
        self.remove_pending(approval_id)?;
        self.pending.lock().unwrap().remove(&approval_id);

        // ── Audit: FourEyesRejected ───────────────────────────────────────
        if let Some(log) = &self.audit_log {
            let _ = log.append(vledger_audit::AuditEventKind::FourEyesRejected {
                approval_id,
                approver: approver_id.clone(),
                reason:   reason.clone(),
            });
        }

        info!(id = %approval_id, approver = %approver_id, reason = %reason,
              "Four-eyes entry rejected");
        Ok(record)
    }

    /// List all currently pending approval requests.
    pub fn list_pending(&self) -> Vec<ApprovalRecord> {
        self.pending.lock().unwrap().values().cloned().collect()
    }

    /// Get a single approval record by ID (pending only).
    pub fn get(&self, id: Uuid) -> Option<ApprovalRecord> {
        self.pending.lock().unwrap().get(&id).cloned()
    }

    // ── Persistence helpers ───────────────────────────────────────────────

    /// Append a new pending record to `pending.jsonl`.
    ///
    /// Fix #8: permissions are set to 0o600 before any content is written so
    /// there is no window where a newly-created file is world-readable.
    fn persist_pending(&self, record: &ApprovalRecord) -> Result<(), FourEyesError> {
        let path = self.dir.join("pending.jsonl");
        // Create the file if absent so we can set permissions before writing.
        if !path.exists() {
            std::fs::File::create(&path)?;
            set_mode_600(&path);
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        let line  = serde_json::to_string(record)
            .map_err(|e| FourEyesError::Serialisation(e.to_string()))?;
        writeln!(f, "{line}")?;
        f.sync_all()?;
        Ok(())
    }

    /// Append a decided record to `approved.jsonl` or `rejected.jsonl`.
    ///
    /// Fix #8: same pre-creation permission pattern as `persist_pending`.
    fn persist_decided(
        &self,
        record: &ApprovalRecord,
        kind:   &str,
    ) -> Result<(), FourEyesError> {
        let path = self.dir.join(format!("{kind}.jsonl"));
        if !path.exists() {
            std::fs::File::create(&path)?;
            set_mode_600(&path);
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        let line  = serde_json::to_string(record)
            .map_err(|e| FourEyesError::Serialisation(e.to_string()))?;
        writeln!(f, "{line}")?;
        f.sync_all()?;
        Ok(())
    }

    /// Rewrite `pending.jsonl` with the given record removed.
    ///
    /// Fix #8: permissions are set on the tmp file immediately after creation
    /// (before any data is written) so the file is never readable by
    /// group/other users even for the brief window before the atomic rename.
    fn remove_pending(&self, id: Uuid) -> Result<(), FourEyesError> {
        let path = self.dir.join("pending.jsonl");
        if !path.exists() { return Ok(()); }

        let file   = File::open(&path)?;
        let reader = BufReader::new(file);
        let mut kept = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() { continue; }
            match serde_json::from_str::<ApprovalRecord>(&line) {
                Ok(r) if r.id == id => { debug!(id = %id, "Removing from pending.jsonl"); }
                Ok(_) | Err(_)      => kept.push(line),
            }
        }

        let tmp_path = self.dir.join("pending.jsonl.tmp");
        {
            // Create the tmp file first, set 0o600 before writing any content,
            // then write — eliminates the window where the file exists with
            // default umask permissions (Fix #8).
            let tmp_file = File::create(&tmp_path)?;
            set_mode_600(&tmp_path);
            drop(tmp_file);

            let mut tmp = OpenOptions::new().write(true).open(&tmp_path)?;
            for line in &kept {
                writeln!(tmp, "{line}")?;
            }
            tmp.sync_all()?;
        }
        // Atomic rename — on Unix this is guaranteed to be crash-safe: either
        // the old file survives or the new one replaces it, never a partial
        // state.
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Load all pending records from disk into the in-memory map.
    fn load_pending(
        dir:     &Path,
        pending: &mut HashMap<Uuid, ApprovalRecord>,
    ) -> Result<(), FourEyesError> {
        let path = dir.join("pending.jsonl");
        if !path.exists() { return Ok(()); }

        let file   = File::open(&path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() { continue; }
            match serde_json::from_str::<ApprovalRecord>(&line) {
                Ok(r) => { pending.insert(r.id, r); }
                Err(e) => warn!("Skipping malformed pending record: {e}"),
            }
        }
        Ok(())
    }

    fn get_pending(&self, id: Uuid) -> Result<ApprovalRecord, FourEyesError> {
        self.pending.lock().unwrap().get(&id).cloned()
            .ok_or(FourEyesError::NotFound(id))
    }

    /// Search `<kind>.jsonl` (e.g. "approved", "rejected") for a record with
    /// the given `id`.  Returns `Ok(None)` if the file does not exist or the
    /// record is not present.
    ///
    /// Used by the idempotency guard in `approve` (Fix #8).
    fn find_in_decided(
        &self,
        kind: &str,
        id:   Uuid,
    ) -> Result<Option<ApprovalRecord>, FourEyesError> {
        let path = self.dir.join(format!("{kind}.jsonl"));
        if !path.exists() { return Ok(None); }

        let file   = File::open(&path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() { continue; }
            if let Ok(r) = serde_json::from_str::<ApprovalRecord>(&line) {
                if r.id == id {
                    return Ok(Some(r));
                }
            }
        }
        Ok(None)
    }
}  // impl FourEyesQueue


// ── File permission helper (Fix #5) ──────────────────────────────────────────

/// Set UNIX file permissions to 0o600 (owner read/write only).
///
/// Applied to every foureyes JSONL file on open/create so that journal entry
/// payloads — which constitute sensitive financial data — are never readable
/// by group or other users.
///
/// On non-Unix platforms this is a no-op; Windows relies on ACLs scoped to
/// the data directory.
fn set_mode_600(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
