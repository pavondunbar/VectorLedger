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
}

impl FourEyesQueue {
    /// Open (or create) the queue using files in `queue_dir`.
    pub fn open(queue_dir: impl AsRef<Path>) -> Result<Self, FourEyesError> {
        let dir = queue_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;

        let mut pending = HashMap::new();
        Self::load_pending(&dir, &mut pending)?;

        info!(dir = %dir.display(), pending = pending.len(), "FourEyesQueue opened");
        Ok(Self { dir, pending: Mutex::new(pending) })
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

        info!(id = %record.id, submitter = %record.submitter_id, "Four-eyes entry submitted");
        Ok(record)
    }

    /// Approve a pending entry.
    ///
    /// `post_fn` is called with the raw entry bytes — the caller should
    /// deserialise and call `LedgerStore::post_entry`.  Returns the approved
    /// `ApprovalRecord`.
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
    fn persist_pending(&self, record: &ApprovalRecord) -> Result<(), FourEyesError> {
        let path = self.dir.join("pending.jsonl");
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        // Fix #5: harden permissions to 0o600 on every open so newly created
        // files are immediately restricted and pre-existing files stay locked.
        set_mode_600(&path);
        let line  = serde_json::to_string(record)
            .map_err(|e| FourEyesError::Serialisation(e.to_string()))?;
        writeln!(f, "{line}")?;
        f.sync_all()?;
        Ok(())
    }

    /// Append a decided record to `approved.jsonl` or `rejected.jsonl`.
    fn persist_decided(
        &self,
        record: &ApprovalRecord,
        kind:   &str,
    ) -> Result<(), FourEyesError> {
        let path = self.dir.join(format!("{kind}.jsonl"));
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        // Fix #5: harden permissions to 0o600.
        set_mode_600(&path);
        let line  = serde_json::to_string(record)
            .map_err(|e| FourEyesError::Serialisation(e.to_string()))?;
        writeln!(f, "{line}")?;
        f.sync_all()?;
        Ok(())
    }

    /// Rewrite `pending.jsonl` with the given record removed.
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
            let mut tmp = File::create(&tmp_path)?;
            for line in &kept {
                writeln!(tmp, "{line}")?;
            }
            tmp.sync_all()?;
        }
        // Fix #5: harden the temp file before the atomic rename so the
        // replacement inherits 0o600 permissions.
        set_mode_600(&tmp_path);
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
}


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
