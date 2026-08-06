use thiserror::Error;

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("Key not found")]
    KeyNotFound,
    #[error("Duplicate key: {0}")]
    DuplicateKey(String),
    #[error("Index is read-only")]
    ReadOnly,
}
