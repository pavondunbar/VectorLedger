//! Ledger error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("Transaction error: {0}")]
    Transaction(#[from] vledger_transaction::TxError),

    #[error("WAL error: {0}")]
    Wal(#[from] vledger_wal::WalError),

    #[error("Page error: {0}")]
    Page(#[from] vledger_pages::PageError),

    #[error("Unbalanced journal entry: debits {debits} ≠ credits {credits}")]
    UnbalancedEntry { debits: i128, credits: i128 },

    #[error("Journal entry must have at least 2 lines (got {0})")]
    TooFewLines(usize),

    #[error("Amount must be non-zero")]
    ZeroAmount,

    #[error("Balance would go negative for account {account_id} (balance {balance}, debit {debit})")]
    InsufficientFunds { account_id: String, balance: i128, debit: i128 },

    #[error("Account {0} not found")]
    AccountNotFound(String),

    #[error("Account {0} is closed — no new entries allowed")]
    AccountClosed(String),

    #[error("Currency mismatch: account uses {account_currency}, entry uses {entry_currency}")]
    CurrencyMismatch { account_currency: String, entry_currency: String },

    #[error("Idempotency key conflict: {0}")]
    IdempotencyConflict(String),

    #[error("Entry {0} not found")]
    EntryNotFound(String),

    #[error("Entry {0} cannot be reversed: status is {1:?}")]
    CannotReverse(String, crate::entry::EntryStatus),

    #[error("Entry {0} was already reversed by {1}")]
    AlreadyReversed(String, String),

    #[error("Exposure limit exceeded for account {account_id}: limit {limit}, attempted {attempted}")]
    ExposureLimitExceeded { account_id: String, limit: i128, attempted: i128 },

    #[error("Four-eyes control violation: entry requires a second approver")]
    FourEyesRequired,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
