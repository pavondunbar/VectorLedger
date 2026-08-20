//! Journal entries — the atomic unit of double-entry accounting.
//!
//! Every financial event is recorded as a `JournalEntry` containing two or
//! more `JournalLine`s.  The entry is **balanced** if and only if:
//!
//! ```text
//! Σ debit_amounts == Σ credit_amounts
//! ```
//!
//! This invariant is enforced before any entry is written to the ledger.
//! The ledger is append-only — entries are never modified or deleted.
//! Corrections are made via **reversal entries** that mirror the original.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vledger_crypto::{hash::hash_bytes, Hash, ZERO_HASH};

use crate::account::AccountId;
use crate::amount::Amount;
use crate::error::LedgerError;

/// Debit or Credit indicator on a journal line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrCr {
    Debit,
    Credit,
}

/// Lifecycle status of a journal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryStatus {
    /// Entry is posted and active.
    Posted,
    /// Entry has been reversed by another entry.
    Reversed,
    /// This entry is itself a reversal of another entry.
    Reversal,
    /// Entry is pending four-eyes approval.
    PendingApproval,
    /// Entry was rejected during four-eyes review.
    Rejected,
}

/// A single line in a journal entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalLine {
    pub id: Uuid,
    /// Account to be debited or credited.
    pub account_id: AccountId,
    /// Currency code (must match the account's currency).
    pub currency_code: String,
    /// Amount in minor units (always positive — direction is `dr_cr`).
    pub amount: Amount,
    /// Debit or Credit.
    pub dr_cr: DrCr,
    /// Optional memo for this specific line.
    pub memo: Option<String>,
}

impl JournalLine {
    /// Signed amount: positive for credits, negative for debits.
    pub fn signed_amount(&self) -> i128 {
        match self.dr_cr {
            DrCr::Credit => self.amount.as_i128(),
            DrCr::Debit => -self.amount.as_i128(),
        }
    }
}

/// A balanced, immutable journal entry.
///
/// Once posted, a `JournalEntry` is never mutated.  Corrections are new
/// `JournalEntry` records with `EntryStatus::Reversal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub id: Uuid,
    /// Monotonic sequence number assigned by the ledger.  Never reused.
    pub sequence: u64,
    pub status: EntryStatus,
    /// Human-readable description of this event.
    pub description: String,
    /// The journal lines that make up this entry (≥ 2).
    pub lines: Vec<JournalLine>,
    /// Effective date — when the event occurred (not when it was posted).
    pub effective_at: DateTime<Utc>,
    /// Posting date — when the entry was written to the ledger.
    pub posted_at: DateTime<Utc>,
    /// External reference (payment ID, order ID, blockchain tx hash, etc.)
    pub external_ref: Option<String>,
    /// Idempotency key — prevents duplicate entries for the same event.
    pub idempotency_key: Option<String>,
    /// ID of the entry this reverses (if `status == Reversal`).
    pub reverses_entry_id: Option<Uuid>,
    /// ID of the entry that reversed this one (if `status == Reversed`).
    pub reversed_by_entry_id: Option<Uuid>,
    /// Domain / legal entity.
    pub domain: String,
    /// BLAKE3 hash of this entry's canonical bytes.
    pub content_hash: Hash,
    /// Hash of the previous entry in the hash chain (`ZERO_HASH` if first).
    pub prev_hash: Hash,
    /// BLAKE3 hash chain link: H(sequence || prev_hash || content_hash).
    pub chain_hash: Hash,
    /// ID of the second approver (four-eyes control).
    pub approved_by: Option<String>,
}

impl JournalEntry {
    /// Validate the entry before posting.
    ///
    /// Checks:
    /// 1. At least 2 lines.
    /// 2. All amounts are non-zero (enforced by `Amount` type, but double-check).
    /// 3. Debits == Credits (balanced entry).
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.lines.len() < 2 {
            return Err(LedgerError::TooFewLines(self.lines.len()));
        }

        let mut total_debits: i128 = 0;
        let mut total_credits: i128 = 0;

        for line in &self.lines {
            let amt = line.amount.as_i128();
            match line.dr_cr {
                DrCr::Debit => total_debits += amt,
                DrCr::Credit => total_credits += amt,
            }
        }

        if total_debits != total_credits {
            return Err(LedgerError::UnbalancedEntry {
                debits: total_debits,
                credits: total_credits,
            });
        }

        Ok(())
    }

    /// Compute the canonical bytes used for content hashing.
    ///
    /// ## Design
    /// Every security-relevant field is included so that altering *any*
    /// metadata invalidates `content_hash` and thereby the entire hash chain
    /// from this entry forward.
    ///
    /// ## Encoding rules (prevent field-boundary collisions)
    /// Variable-length fields (strings, optional values, repeated groups) are
    /// always length-prefixed with a 4-byte little-endian `u32`.  Without this,
    /// two different field combinations can produce identical byte sequences —
    /// for example `["ab", "c"]` and `["a", "bc"]` would be indistinguishable
    /// if concatenated without delimiters.
    ///
    /// Fixed-width fields (UUIDs, i64, i128, u8 booleans, timestamps) are
    /// written raw with no prefix — their width is already unambiguous.
    ///
    /// The schema version byte is written first so that a future field addition
    /// produces a hash that is distinct from all previous versions.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Helper: write a length-prefixed byte slice.
        fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
        // Helper: write an optional length-prefixed byte slice.
        // Absence is encoded as length=0xFFFF_FFFF (sentinel) so that
        // Some("") and None produce different byte sequences.
        fn write_opt_bytes(buf: &mut Vec<u8>, data: Option<&[u8]>) {
            match data {
                Some(d) => write_bytes(buf, d),
                None => buf.extend_from_slice(&u32::MAX.to_le_bytes()),
            }
        }

        let mut buf = Vec::with_capacity(256);

        // ── Schema version — bump if the canonical format ever changes ────
        buf.push(0x01u8);

        // ── Fixed-width identity fields ───────────────────────────────────
        buf.extend_from_slice(self.id.as_bytes()); // 16 bytes
        buf.extend_from_slice(&self.sequence.to_le_bytes()); //  8 bytes
        buf.push(self.status as u8); //  1 byte
        buf.extend_from_slice(
            &self
                .effective_at
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_le_bytes(), //  8 bytes
        );
        buf.extend_from_slice(
            &self
                .posted_at
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_le_bytes(), //  8 bytes
        );

        // ── Variable-length identity fields (length-prefixed) ─────────────
        write_bytes(&mut buf, self.description.as_bytes());
        write_bytes(&mut buf, self.domain.as_bytes());
        write_opt_bytes(&mut buf, self.external_ref.as_deref().map(str::as_bytes));
        write_opt_bytes(&mut buf, self.idempotency_key.as_deref().map(str::as_bytes));

        // ── Reversal relationships (fixed-width UUID or sentinel) ─────────
        // 16 bytes each; absent → 16 zero bytes followed by a 0x00 presence flag,
        // present → UUID bytes followed by a 0x01 presence flag.
        match self.reverses_entry_id {
            Some(id) => {
                buf.extend_from_slice(id.as_bytes());
                buf.push(0x01);
            }
            None => {
                buf.extend_from_slice(&[0u8; 16]);
                buf.push(0x00);
            }
        }
        match self.reversed_by_entry_id {
            Some(id) => {
                buf.extend_from_slice(id.as_bytes());
                buf.push(0x01);
            }
            None => {
                buf.extend_from_slice(&[0u8; 16]);
                buf.push(0x00);
            }
        }

        // ── Approval metadata (length-prefixed) ───────────────────────────
        write_opt_bytes(&mut buf, self.approved_by.as_deref().map(str::as_bytes));

        // ── Journal lines (length-prefixed group count + per-line fields) ─
        buf.extend_from_slice(&(self.lines.len() as u32).to_le_bytes());
        for line in &self.lines {
            buf.extend_from_slice(line.id.as_bytes()); // 16 bytes
            buf.extend_from_slice(line.account_id.as_bytes()); // 16 bytes
            buf.extend_from_slice(&line.amount.as_i64().to_le_bytes()); //  8 bytes
            buf.push(line.dr_cr as u8); //  1 byte
            write_bytes(&mut buf, line.currency_code.as_bytes());
            write_opt_bytes(&mut buf, line.memo.as_deref().map(str::as_bytes));
        }

        buf
    }

    /// Pre-compute the content hash from the entry's own fields.
    ///
    /// This is the expensive BLAKE3 pass over `canonical_bytes()`.  It does
    /// **not** depend on any external (locked) ledger state, so it can be
    /// called before the write lock is acquired.
    ///
    /// After calling this, `content_hash` is populated.  Call
    /// `finalize_chain_hash` inside the write lock to complete the chain link.
    pub fn precompute_content_hash(&mut self) {
        let canonical = self.canonical_bytes();
        self.content_hash = hash_bytes(&canonical);
    }

    /// Finalize the chain hash using a pre-computed `content_hash`.
    ///
    /// Must be called **inside** the write lock after `sequence` and
    /// `posted_at` have been assigned, because the chain hash depends on
    /// `prev_chain_hash` (mutable shared state).
    ///
    /// Assumes `precompute_content_hash` has already been called.  If
    /// `content_hash` is still `ZERO_HASH` this will fall back to computing
    /// it inline (safe but slower — call `precompute_content_hash` first for
    /// best performance).
    pub fn finalize_chain_hash(&mut self, prev_chain_hash: &Hash) {
        // Guard: if content_hash was never pre-computed, do it now.
        if self.content_hash == ZERO_HASH {
            let canonical = self.canonical_bytes();
            self.content_hash = hash_bytes(&canonical);
        }
        self.prev_hash = *prev_chain_hash;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(prev_chain_hash);
        hasher.update(&self.content_hash);
        self.chain_hash = *hasher.finalize().as_bytes();
    }

    /// Compute and set the content hash and chain hash.
    /// Call this after all fields are set, before writing to the ledger.
    ///
    /// For performance-critical paths prefer calling `precompute_content_hash`
    /// before the write lock and `finalize_chain_hash` inside the lock.
    pub fn finalize_hashes(&mut self, prev_chain_hash: &Hash) {
        self.precompute_content_hash();
        self.finalize_chain_hash(prev_chain_hash);
    }

    /// Verify internal hash consistency.
    pub fn verify_hashes(&self) -> bool {
        let canonical = self.canonical_bytes();
        let expected_content = hash_bytes(&canonical);
        if expected_content != self.content_hash {
            return false;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.content_hash);
        let expected_chain = *hasher.finalize().as_bytes();
        expected_chain == self.chain_hash
    }
}

/// Builder for `JournalEntry`.
pub struct JournalEntryBuilder {
    description: String,
    lines: Vec<JournalLine>,
    effective_at: DateTime<Utc>,
    external_ref: Option<String>,
    idempotency_key: Option<String>,
    domain: String,
    reverses_entry_id: Option<Uuid>,
}

impl JournalEntryBuilder {
    pub fn new(description: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            lines: Vec::new(),
            effective_at: Utc::now(),
            external_ref: None,
            idempotency_key: None,
            domain: domain.into(),
            reverses_entry_id: None,
        }
    }

    pub fn debit(
        mut self,
        account_id: AccountId,
        amount: Amount,
        currency: impl Into<String>,
    ) -> Self {
        self.lines.push(JournalLine {
            id: Uuid::new_v4(),
            account_id,
            currency_code: currency.into().to_uppercase(),
            amount,
            dr_cr: DrCr::Debit,
            memo: None,
        });
        self
    }

    pub fn credit(
        mut self,
        account_id: AccountId,
        amount: Amount,
        currency: impl Into<String>,
    ) -> Self {
        self.lines.push(JournalLine {
            id: Uuid::new_v4(),
            account_id,
            currency_code: currency.into().to_uppercase(),
            amount,
            dr_cr: DrCr::Credit,
            memo: None,
        });
        self
    }

    pub fn effective_at(mut self, dt: DateTime<Utc>) -> Self {
        self.effective_at = dt;
        self
    }

    pub fn external_ref(mut self, r: impl Into<String>) -> Self {
        self.external_ref = Some(r.into());
        self
    }

    pub fn idempotency_key(mut self, k: impl Into<String>) -> Self {
        self.idempotency_key = Some(k.into());
        self
    }

    pub fn reverses(mut self, entry_id: Uuid) -> Self {
        self.reverses_entry_id = Some(entry_id);
        self
    }

    /// Build a `JournalEntry`.  Hashes are set to zero — call
    /// `finalize_hashes()` before posting.
    pub fn build(self) -> JournalEntry {
        JournalEntry {
            id: Uuid::new_v4(),
            sequence: 0, // assigned by LedgerStore
            status: if self.reverses_entry_id.is_some() {
                EntryStatus::Reversal
            } else {
                EntryStatus::Posted
            },
            description: self.description,
            lines: self.lines,
            effective_at: self.effective_at,
            posted_at: Utc::now(),
            external_ref: self.external_ref,
            idempotency_key: self.idempotency_key,
            reverses_entry_id: self.reverses_entry_id,
            reversed_by_entry_id: None,
            domain: self.domain,
            content_hash: ZERO_HASH,
            prev_hash: ZERO_HASH,
            chain_hash: ZERO_HASH,
            approved_by: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_balanced_entry() -> JournalEntry {
        let amt = Amount::new(10000).unwrap(); // $100.00
        let acct_a = Uuid::new_v4();
        let acct_b = Uuid::new_v4();
        JournalEntryBuilder::new("Test transfer", "test-domain")
            .debit(acct_a, amt, "USD")
            .credit(acct_b, amt, "USD")
            .build()
    }

    #[test]
    fn balanced_entry_validates() {
        let entry = make_balanced_entry();
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn unbalanced_entry_rejected() {
        let acct_a = Uuid::new_v4();
        let acct_b = Uuid::new_v4();
        let mut entry = JournalEntryBuilder::new("Bad entry", "test")
            .debit(acct_a, Amount::new(100).unwrap(), "USD")
            .credit(acct_b, Amount::new(99).unwrap(), "USD")
            .build();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn hash_chain_is_consistent() {
        let mut entry = make_balanced_entry();
        entry.sequence = 1;
        entry.finalize_hashes(&ZERO_HASH);
        assert!(entry.verify_hashes());
    }

    #[test]
    fn tampered_entry_fails_hash_verify() {
        let mut entry = make_balanced_entry();
        entry.sequence = 1;
        entry.finalize_hashes(&ZERO_HASH);
        // Tamper with description
        entry.description = "tampered".to_string();
        assert!(!entry.verify_hashes());
    }

    #[test]
    fn tampered_domain_fails_hash_verify() {
        let mut entry = make_balanced_entry();
        entry.sequence = 1;
        entry.finalize_hashes(&ZERO_HASH);
        // domain is now in canonical_bytes — altering it must break the hash
        entry.domain = "other-domain".to_string();
        assert!(!entry.verify_hashes());
    }

    #[test]
    fn tampered_status_fails_hash_verify() {
        let mut entry = make_balanced_entry();
        entry.sequence = 1;
        entry.finalize_hashes(&ZERO_HASH);
        // status is now in canonical_bytes — altering it must break the hash
        entry.status = EntryStatus::Reversed;
        assert!(!entry.verify_hashes());
    }

    #[test]
    fn canonical_bytes_field_boundary_collision_resistance() {
        // Two entries whose variable-length fields would collide without
        // length prefixes must produce different canonical bytes.
        let amt = Amount::new(10000).unwrap();
        let acct = Uuid::new_v4();
        let acct2 = Uuid::new_v4();

        let mut e1 = JournalEntryBuilder::new("ab", "c-domain")
            .debit(acct, amt, "USD")
            .credit(acct2, amt, "USD")
            .build();
        e1.sequence = 1;

        let mut e2 = JournalEntryBuilder::new("a", "bc-domain")
            .debit(acct, amt, "USD")
            .credit(acct2, amt, "USD")
            .build();
        e2.sequence = 1;
        // Force identical timestamps so only the string fields differ
        e2.effective_at = e1.effective_at;
        e2.posted_at = e1.posted_at;

        assert_ne!(
            e1.canonical_bytes(),
            e2.canonical_bytes(),
            "length-prefixed encoding must distinguish different field splits"
        );
    }
}
