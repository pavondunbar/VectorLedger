//! Server error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("SQL error: {0}")]
    Sql(#[from] vledger_sql::SqlError),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Authorisation denied: {0}")]
    Forbidden(String),

    #[error("Server not initialised — call Server::run()")]
    NotInitialized,

    #[error("Server bind error on {addr}: {reason}")]
    BindFailed { addr: String, reason: String },
}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
