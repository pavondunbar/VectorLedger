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
pub mod currency;
pub mod entry;
pub mod error;
pub mod lockfile;
pub mod store;
#[cfg(test)]
mod crash_tests;
#[cfg(test)]
mod concurrent_tests;
#[cfg(test)]
mod fault_injection_tests;
#[cfg(test)]
mod invariant_tests;
#[cfg(test)]
mod proptest_invariants;
#[cfg(test)]
mod stress_tests;

pub use account::{Account, AccountId, AccountType};
pub use amount::Amount;
pub use currency::Currency;
pub use entry::{JournalEntry, JournalEntryBuilder, JournalLine, EntryStatus};
pub use error::LedgerError;
pub use lockfile::{DataDirLock, LockError};
pub use store::{LedgerStore, ReversalEvent};
