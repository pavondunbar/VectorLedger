//! HSM error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HsmError {
    #[error("PyHSM IPC error: {0}")]
    Ipc(String),

    #[error("PyHSM returned error: {0}")]
    Remote(String),

    #[error("PyHSM socket not found at {path} — is the PyHSM daemon running?")]
    SocketNotFound { path: String },

    #[error("PyHSM IPC timeout after {ms}ms")]
    Timeout { ms: u64 },

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key policy violation: {0}")]
    PolicyViolation(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoFailed(String),

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
