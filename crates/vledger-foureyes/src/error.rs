//! Four-eyes error types.
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum FourEyesError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Approval {0} not found")]
    NotFound(Uuid),

    #[error("Approval {0} is not pending (current status: {1})")]
    NotPending(Uuid, String),

    #[error("Self-approval is not permitted (submitter and approver are both '{0}')")]
    SelfApproval(String),

    #[error("Ledger post failed: {0}")]
    PostFailed(String),

    #[error("Serialisation error: {0}")]
    Serialisation(String),
}
