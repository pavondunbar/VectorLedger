//! Error types for vledger-secrets.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretsError {
    #[error("Environment variable '{var}' not set or empty")]
    EnvVarMissing { var: String },

    #[error("Key file '{path}': {reason}")]
    FileError { path: String, reason: String },

    #[error("Key must be exactly 32 bytes (64 hex chars); got {got} bytes")]
    InvalidKeyLength { got: usize },

    #[error("Invalid hex in key material: {0}")]
    HexDecode(String),

    #[error("HashiCorp Vault error: {0}")]
    Vault(String),

    #[error("AWS KMS error: {0}")]
    AwsKms(String),

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Unknown key source backend: '{0}'")]
    UnknownBackend(String),
}
