use thiserror::Error;

/// Errors that can occur in vault operations.
///
/// The enum is `#[non_exhaustive]`: variants may be added in minor releases,
/// so downstream `match` expressions need a wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// The in-memory encryption subkey is not available.
    #[error("Invalid vault key")]
    InvalidKey,
    /// Authenticated decryption of the vault index failed.
    ///
    /// XChaCha20-Poly1305 cannot distinguish a wrong password from a
    /// tampered, truncated, or corrupted vault, so this single variant covers
    /// all of them. Treat it as "authentication failed" rather than as proof
    /// that the password was mistyped, and keep in mind that every retry
    /// repeats the Argon2 derivation on the same bytes.
    #[error("Vault authentication failed: wrong password or tampered data")]
    InvalidPassword,
    /// A cryptographic operation failed, or an input violated a limit such
    /// as the password, entry name, or entry data bounds.
    #[error("Crypto error: {0}")]
    CryptoError(String),
    /// The vault bytes are malformed or violate a documented bound.
    #[error("Corrupted data: {0}")]
    CorruptedData(String),
    /// Serializing the vault failed or the output exceeded the size bound.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// A file operation in `load` or `save` failed.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
