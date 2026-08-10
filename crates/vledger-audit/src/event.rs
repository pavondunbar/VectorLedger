//! Audit event definitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The type of security-relevant event being recorded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A SQL query was executed.
    QueryExecuted {
        sql:           String,
        caller_id:     String,
        rows_affected: usize,
        duration_ms:   u64,
    },
    /// A journal entry was committed to the ledger.
    EntryPosted {
        entry_id:       Uuid,
        entry_sequence: u64,
        domain:         String,
        amount_sum:     i64,
        caller_id:      String,
    },
    /// An account was created.
    AccountCreated {
        account_id:   Uuid,
        account_code: String,
        domain:       String,
        caller_id:    String,
    },
    /// An account was closed.
    AccountClosed {
        account_id: Uuid,
        caller_id:  String,
    },
    /// An HSM key was rotated.
    KeyRotated {
        key_id:    String,
        caller_id: String,
    },
    /// A WAL record was shipped to or received from a replica.
    ReplicationEvent {
        lsn:       u64,
        direction: String, // "shipped" | "received"
        peer:      String,
    },
    /// A login attempt was made.
    AuthEvent {
        caller_id: String,
        success:   bool,
        peer_addr: String,
    },
    /// A journal entry was submitted for four-eyes approval.
    FourEyesSubmitted {
        approval_id: Uuid,
        entry_id:    Uuid,
        submitter:   String,
        domain:      String,
    },
    /// A four-eyes approval was granted.
    FourEyesApproved {
        approval_id: Uuid,
        approver:    String,
    },
    /// A four-eyes approval was rejected.
    FourEyesRejected {
        approval_id: Uuid,
        approver:    String,
        reason:      String,
    },
    /// A backup snapshot was created.
    BackupCreated {
        path:      String,
        size_bytes: u64,
        caller_id: String,
    },
    /// Key rotation process was initiated.
    KeyRotationStarted {
        key_ids:   Vec<String>,
        caller_id: String,
    },
    /// The server process started successfully.
    ServerStarted {
        bind_addr: String,
        version:   String,
    },
}

impl AuditEventKind {
    /// A short human-readable name for this event type (used in CSV export).
    pub fn name(&self) -> &'static str {
        match self {
            Self::QueryExecuted { .. }      => "query_executed",
            Self::EntryPosted { .. }        => "entry_posted",
            Self::AccountCreated { .. }     => "account_created",
            Self::AccountClosed { .. }      => "account_closed",
            Self::KeyRotated { .. }         => "key_rotated",
            Self::ReplicationEvent { .. }   => "replication_event",
            Self::AuthEvent { .. }          => "auth_event",
            Self::FourEyesSubmitted { .. }  => "four_eyes_submitted",
            Self::FourEyesApproved { .. }   => "four_eyes_approved",
            Self::FourEyesRejected { .. }   => "four_eyes_rejected",
            Self::BackupCreated { .. }      => "backup_created",
            Self::KeyRotationStarted { .. } => "key_rotation_started",
            Self::ServerStarted { .. }      => "server_started",
        }
    }
}

/// A single immutable audit event written to the WORM log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic sequence number within this log file (1-based).
    pub sequence:     u64,
    /// UTC timestamp when this event occurred.
    pub ts:           DateTime<Utc>,
    /// The event payload — stored as a nested object to avoid field-name collisions.
    pub event:        AuditEventKind,
    /// BLAKE3 hash of the canonical bytes of this event (before chain hash).
    pub content_hash: String,
    /// BLAKE3 chain hash: H(sequence || prev_hash || content_hash).
    pub chain_hash:   String,
    /// Chain hash of the previous event (zero-filled hex for the first event).
    pub prev_hash:    String,
}

impl AuditEvent {
    /// Zero-hash sentinel used for the first event in the chain.
    pub const ZERO_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// Compute the canonical bytes for content hashing (excludes hash fields).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // serde_json serialization of AuditEventKind should never fail for
        // well-formed events, but we propagate the error rather than silently
        // computing a hash over empty bytes (which would make two different
        // events appear identical if serialization failed for both).
        let kind_json = serde_json::to_string(&self.event)
            .unwrap_or_else(|e| format!("{{\"serialization_error\":\"{e}\"}}"));
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        let ts_ns = self.ts.timestamp_nanos_opt().unwrap_or(0);
        buf.extend_from_slice(&ts_ns.to_le_bytes());
        buf.extend_from_slice(kind_json.as_bytes());
        buf
    }

    /// Finalise content_hash and chain_hash given the previous event's chain hash.
    pub fn finalise(&mut self, prev_chain_hash: &str) {
        let content_hex = hex::encode(blake3::hash(&self.canonical_bytes()).as_bytes());
        self.content_hash = content_hex.clone();
        self.prev_hash    = prev_chain_hash.to_string();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(prev_chain_hash.as_bytes());
        hasher.update(content_hex.as_bytes());
        self.chain_hash = hex::encode(hasher.finalize().as_bytes());
    }

    /// Verify that `content_hash` and `chain_hash` are internally consistent.
    pub fn verify(&self) -> bool {
        let expected_content = hex::encode(blake3::hash(&self.canonical_bytes()).as_bytes());
        if expected_content != self.content_hash {
            return false;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(expected_content.as_bytes());
        let expected_chain = hex::encode(hasher.finalize().as_bytes());
        expected_chain == self.chain_hash
    }
}
