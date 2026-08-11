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

    /// Returned when the SQL text exceeds `MAX_SQL_BYTES` before the parser
    /// is called.  Prevents OOM from enormous payloads and limits the surface
    /// available for nesting-depth attacks.
    #[error("Query too long: {len} bytes exceeds the {limit}-byte limit")]
    QueryTooLong { len: usize, limit: usize },

    /// Returned when the SQL text contains more levels of parenthesis nesting
    /// than `MAX_NESTING_DEPTH`.  sqlparser-rs recurses once per nesting level;
    /// without this guard ~50 levels triggers a stack overflow (SIGABRT).
    #[error(
        "Query rejected: nesting depth {depth} exceeds the maximum allowed depth of {limit}"
    )]
    NestingTooDeep { depth: usize, limit: usize },
}
