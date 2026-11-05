use crate::crypto::aad_aead::AadAeadError;
use crate::crypto::utils::RandomError;
use crate::vault::vault_index::IndexError;
use thiserror::Error;

/// Errors that can occur in vault operations.
///
/// The enum is `#[non_exhaustive]`: variants may be added in minor releases,
/// so downstream `match` expressions need a wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// Authenticated decryption of the vault index failed.
    ///
    /// XChaCha20-Poly1305 cannot distinguish a wrong password from a
    /// tampered, truncated, or corrupted vault, so this single variant covers
    /// all of them. Treat it as "authentication failed" rather than as proof
    /// that the password was mistyped, and keep in mind that every retry
    /// repeats the Argon2 derivation on the same bytes.
    ///
    /// `change_password` returns the same variant when the current password
    /// does not reproduce the keys in memory; no AEAD is involved there.
    #[error("Vault authentication failed: wrong password or tampered data")]
    InvalidPassword,
    /// An argument violated a documented limit: the password is shorter than
    /// the minimum, an entry name or payload is larger than the maximum, or
    /// the vault already holds the maximum number of entries.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// A cryptographic or random-number operation failed, or locked memory
    /// for the subkeys could not be allocated.
    #[error("Crypto error: {0}")]
    CryptoError(String),
    /// The vault bytes are malformed, violate a documented bound, or the
    /// authenticated index is internally inconsistent.
    #[error("Corrupted data: {0}")]
    CorruptedData(String),
    /// Serializing the vault failed or the output exceeded the size bound.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// A file operation in `load` or `save` failed.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

impl From<IndexError> for VaultError {
    fn from(error: IndexError) -> Self {
        match error {
            IndexError::Inconsistent(_) => VaultError::CorruptedData(error.to_string()),
            IndexError::Full(_) => VaultError::InvalidInput(error.to_string()),
            IndexError::CounterOverflow(_)
            | IndexError::Random(_)
            | IndexError::LockedMemory(_)
            | IndexError::Crypto(_) => VaultError::CryptoError(error.to_string()),
        }
    }
}

impl From<AadAeadError> for VaultError {
    fn from(error: AadAeadError) -> Self {
        VaultError::CryptoError(error.to_string())
    }
}

impl From<RandomError> for VaultError {
    fn from(error: RandomError) -> Self {
        VaultError::CryptoError(error.to_string())
    }
}
