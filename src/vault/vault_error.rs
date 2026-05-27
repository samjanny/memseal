use thiserror::Error;

/// Errors that can occur in vault operations.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Invalid vault header")]
    InvalidHeader,
    #[error("Invalid vault index")]
    InvalidIndex,
    #[error("Invalid vault data block")]
    InvalidDataBlock,
    #[error("Invalid vault meta block")]
    InvalidMetaBlock,
    #[error("Invalid vault key")]
    InvalidKey,
    #[error("Invalid vault password")]
    InvalidPassword,
    #[error("Invalid vault path")]
    InvalidPath,
    #[error("Invalid vault version")]
    InvalidVersion,
    #[error("Invalid vault format")]
    InvalidFormat,
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("Corrupted data: {0}")]
    CorruptedData(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Entry not found: {0}")]
    EntryNotFound(String),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
