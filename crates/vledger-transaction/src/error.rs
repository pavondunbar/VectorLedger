//! Transaction error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxError {
    #[error("WAL error: {0}")]
    Wal(#[from] vledger_wal::WalError),

    #[error("Page error: {0}")]
    Page(#[from] vledger_pages::PageError),

    #[error("Transaction {0} not found")]
    NotFound(u64),

    #[error("Transaction {0} is already committed")]
    AlreadyCommitted(u64),

    #[error("Transaction {0} is already rolled back")]
    AlreadyRolledBack(u64),

    #[error("Serialization conflict: transaction {0} conflicts with a committed transaction")]
    SerializationConflict(u64),

    #[error("Deadlock detected involving transaction {0}")]
    Deadlock(u64),

    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("Financial invariant violated: {0}")]
    FinancialInvariant(String),

    #[error("Idempotency key already used: {0}")]
    IdempotencyKeyConflict(String),

    #[error("Attempted mutation on an append-only table: {0}")]
    AppendOnlyViolation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
