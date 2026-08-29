//! # vledger-ledger
//!
//! Double-entry financial ledger for VectorLedger.
//!
//! ## Financial invariants enforced at every layer
//!
//! | Invariant                         | Where enforced                        |
//! |-----------------------------------|---------------------------------------|
//! | Amounts are integers only         | `Amount` newtype — no float anywhere  |
//! | Every journal entry is balanced   | `JournalEntry::validate()` pre-commit |
//! | No UPDATE/DELETE on ledger rows   | `LedgerStore` — append-only only      |
//! | Idempotency keys                  | `TransactionManager`                  |
//! | Balance ≥ 0 (configurable)        | `AccountConstraints`                  |
//! | UTC timestamps everywhere         | `chrono::DateTime<Utc>` only          |
//! | Hash chaining of all entries      | `ChainEntry` on every journal row     |
//! | Explicit reversals (no deletes)   | `LedgerStore::reverse_entry()`        |
//! | Double-entry (debit == credit)    | `JournalEntry::validate()`            |
//! | External reference traceability   | `JournalEntry::external_ref`          |

pub mod account;
pub mod amount;
#[cfg(test)]
mod concurrent_tests;
#[cfg(test)]
mod crash_tests;
pub mod currency;
pub mod entry;
pub mod entry_db;
pub mod error;
#[cfg(test)]
mod fault_injection_tests;
#[cfg(test)]
mod invariant_tests;
pub mod lockfile;
#[cfg(test)]
mod proptest_invariants;
pub mod store;
#[cfg(test)]
mod stress_tests;

pub use account::{Account, AccountId, AccountType};
pub use amount::Amount;
pub use currency::Currency;
pub use entry::{EntryStatus, JournalEntry, JournalEntryBuilder, JournalLine};
pub use error::LedgerError;
pub use lockfile::{DataDirLock, LockError};
pub use store::{LedgerStore, ReconciliationDiscrepancy, ReversalEvent, SettlementEvent};
