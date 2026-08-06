//! SQL error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SqlError {
    #[error("SQL parse error: {0}")]
    Parse(String),

    #[error("Unsupported statement: {0}")]
    Unsupported(String),

    #[error("Unknown table: '{0}' — supported tables: ledger, accounts")]
    UnknownTable(String),

    #[error("Column '{0}' not found")]
    ColumnNotFound(String),

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid value for field '{field}': {reason}")]
    InvalidValue { field: String, reason: String },

    #[error("Ledger error: {0}")]
    Ledger(#[from] vledger_ledger::LedgerError),

    #[error("Execution error: {0}")]
    Execution(String),
}
