use secrecy::SecretBox;

/// Errors that can occur during encryption or decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("Deserialization failed")]
    DeserializationFailed,
    #[error("Secret key generation failed")]
    SecretKeyGenerationFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("Nonce generation failed")]
    NonceGenerationFailed,
    #[error("Serialization error")]
    SerializationError,
    #[error("Deserialization error")]
    DeserializationError,
    #[error("Generic error occurred: {0}")]
    GenericError(String),
}

/// Trait for constructing a type from secure key material provided by a closure.
pub trait SecureConstructor: Sized {
    fn secure_new<F>(f: F) -> Result<Self, EncryptionError>
    where
        F: FnOnce() -> Result<SecretBox<Vec<u8>>, &'static str>;
}

/// Trait for accessing the decrypted key material inside a secure container.
pub trait SecureAccess {
    fn secure_access<F>(&self, f: F) -> Result<(), EncryptionError>
    where
        F: FnOnce(&SecretBox<Vec<u8>>) -> Result<(), &'static str>;
}
