//! # vledger-audit
//!
//! Append-only WORM audit log for VectorLedger.
//!
//! ## Design
//! Every security-relevant event is written as a single JSON line to
//! `audit/audit.log` (path relative to the data directory).
//!
//! **WORM semantics** are enforced at the `AuditLog` level:
//! - The file is opened `O_APPEND | O_CREAT` — no seek, no truncate.
//! - Each `AuditEvent` line is BLAKE3-hashed and the hash is embedded in the
//!   next event, forming a tamper-evident chain identical to the ledger chain.
//! - Existing bytes are never modified.
//!
//! ## Export
//! `AuditLog::export_json(range)` and `AuditLog::export_csv(range)` scan the
//! log file, filter by a UTC timestamp range, and write to any `Write` sink.
//!
//! ## Event types
//! | Variant              | Trigger                                       |
//! |----------------------|-----------------------------------------------|
//! | `QueryExecuted`      | Every SQL query executed by a connection      |
//! | `EntryPosted`        | Journal entry committed to the ledger         |
//! | `AccountCreated`     | Chart-of-accounts row created                 |
//! | `AccountClosed`      | Account closed                                |
//! | `KeyRotated`         | HSM key rotation completed                    |
//! | `ReplicationEvent`   | WAL record shipped / received                 |
//! | `AuthEvent`          | Login attempt (success or failure)            |
//! | `FourEyesSubmitted`  | Entry submitted for four-eyes approval        |
//! | `FourEyesApproved`   | Entry approved by second approver             |
//! | `FourEyesRejected`   | Entry rejected by second approver             |
//! | `BackupCreated`      | Snapshot backup created                       |
//! | `KeyRotationStarted` | Key rotation process initiated                |

pub mod error;
pub mod event;
pub mod export;
pub mod log;

pub use error::AuditError;
pub use event::{AuditEvent, AuditEventKind};
pub use export::{ExportFormat, TimeRange};
pub use log::AuditLog;
