//! # vledger-foureyes
//!
//! Server-layer four-eyes (dual-control) workflow for VectorLedger.
//!
//! ## Design
//! When a journal entry targets an account with `require_four_eyes = true`,
//! the entry is **not** posted immediately.  Instead:
//!
//! 1. The submitter calls `FourEyesQueue::submit(entry, submitter_id)`.
//!    The entry is persisted to `vledger-data/foureyes/pending.jsonl` and an
//!    `ApprovalId` (UUID) is returned.
//! 2. A second, **different** principal calls `FourEyesQueue::approve(id, approver_id)`.
//!    - The queue verifies `approver_id != submitter_id`.
//!    - It then calls the provided `post_fn` callback (which is `LedgerStore::post_entry`).
//!    - The pending record is moved to `foureyes/approved.jsonl`.
//! 3. Any principal can call `FourEyesQueue::reject(id, approver_id, reason)`.
//!    - The pending record is moved to `foureyes/rejected.jsonl`.
//!
//! All state changes are durable (fsynced) before the method returns.
//!
//! The `vledger-server` integration point: `handle_connection` checks the
//! `require_four_eyes` flag on every account touched by a POST and routes
//! through `FourEyesQueue` instead of `LedgerStore::post_entry` directly.

#[cfg(test)]
mod bypass_tests;
pub mod error;
pub mod queue;
pub mod record;

pub use error::FourEyesError;
pub use queue::FourEyesQueue;
pub use record::{ApprovalRecord, ApprovalStatus};
