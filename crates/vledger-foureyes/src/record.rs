//! Approval record — the durable state of a pending four-eyes entry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle status of a four-eyes approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for a second approver.
    Pending,
    /// Approved and posted to the ledger.
    Approved,
    /// Rejected — entry was NOT posted.
    Rejected,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Approved => write!(f, "Approved"),
            Self::Rejected => write!(f, "Rejected"),
        }
    }
}

/// A durable approval record stored in the four-eyes JSONL files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Unique approval request ID.
    pub id: Uuid,
    /// Status of this approval.
    pub status: ApprovalStatus,
    /// ID of the principal who submitted the entry for approval.
    pub submitter_id: String,
    /// ID of the second approver (set on approve/reject).
    pub approver_id: Option<String>,
    /// Rejection reason (set on reject).
    pub reject_reason: Option<String>,
    /// UTC timestamp when submitted.
    pub submitted_at: DateTime<Utc>,
    /// UTC timestamp of the approval/rejection decision.
    pub decided_at: Option<DateTime<Utc>>,
    /// The serialised `JournalEntry` payload (bincode hex-encoded).
    /// Stored so the queue can post it after approval without holding a
    /// reference to a live `LedgerStore`.
    pub entry_payload_hex: String,
    /// Human-readable description from the journal entry.
    pub description: String,
    /// Domain from the journal entry.
    pub domain: String,
}
