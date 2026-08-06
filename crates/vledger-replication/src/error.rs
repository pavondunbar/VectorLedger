//! Replication error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReplicationError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    #[error("Replica ACK timeout after {ms}ms for LSN {lsn}")]
    AckTimeout { lsn: u64, ms: u64 },

    #[error("Replica sent unexpected ACK {got}, expected {expected}")]
    AckMismatch { expected: u64, got: u64 },

    #[error("Replication stream ended unexpectedly")]
    StreamEnded,

    #[error("Replica connection refused: {0}")]
    ConnectionRefused(String),

    #[error("Invalid WAL record in replication stream: {0}")]
    InvalidRecord(String),

    #[error("WAL ledger error: {0}")]
    Ledger(String),

    /// Fix #9: handshake failed — wrong secret or tampered challenge.
    #[error("Replication authentication failed: {0}")]
    AuthFailed(String),

    /// Fix #9: replication secret file could not be read or parsed.
    #[error("Replication secret error: {0}")]
    SecretError(String),

    /// Tasks #1/#2: TLS configuration or handshake error.
    #[error("Replication TLS error: {0}")]
    Tls(String),
}
