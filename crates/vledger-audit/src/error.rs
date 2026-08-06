//! Audit error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("I/O error writing audit log: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    #[error("Audit log chain broken at sequence {sequence}: {reason}")]
    ChainBroken { sequence: u64, reason: String },

    #[error("Export error: {0}")]
    Export(String),
}
