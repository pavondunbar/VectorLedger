//! Compliance error types.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ComplianceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Audit log error: {0}")]
    Audit(String),
    #[error("Evidence collection failed for control '{control}': {reason}")]
    EvidenceCollection { control: String, reason: String },
    #[error("Serialisation error: {0}")]
    Serialisation(String),
}
