//! HSM error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HsmError {
    // ── Model 1 — local IPC ───────────────────────────────────────────────
    #[error("PyHSM IPC error: {0}")]
    Ipc(String),

    #[error("PyHSM returned error: {0}")]
    Remote(String),

    #[error("PyHSM socket not found at {path} — is the PyHSM daemon running?")]
    SocketNotFound { path: String },

    #[error("PyHSM IPC timeout after {ms}ms")]
    Timeout { ms: u64 },

    // ── Model 2 — remote TLS / mTLS ───────────────────────────────────────
    /// TLS handshake, certificate loading, or mTLS configuration error.
    #[error("PyHSM TLS error: {0}")]
    Tls(String),

    /// Network-level connection error for remote transport.
    #[error("PyHSM remote connection error: {0}")]
    Connection(String),

    /// Configuration error (e.g. malformed endpoint URL, missing CA cert path).
    #[error("PyHSM configuration error: {0}")]
    Config(String),

    /// All retry attempts exhausted for a remote request.
    #[error("PyHSM remote request failed after {attempts} attempt(s): {last_error}")]
    RetriesExhausted { attempts: u32, last_error: String },

    // ── Shared ────────────────────────────────────────────────────────────
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
