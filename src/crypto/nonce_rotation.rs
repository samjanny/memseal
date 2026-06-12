use thiserror::Error;

/// Type-state marker: nonce has not been rotated yet.
pub struct NonceNotRotated;
/// Type-state marker: nonce has been rotated and is safe to use.
pub struct NonceRotated;

/// Trait for rotating the nonce of a type-stated struct.
pub trait NonceRotation {
    type Output;

    fn rotate_nonce(self) -> Result<Self::Output, NonceRotationError>;
}

/// Errors that can occur during nonce rotation.
#[derive(Debug, Error)]
pub enum NonceRotationError {
    #[error("Nonce rotation failed")]
    NonceRotationFailed,
    #[error("Nonce counter overflow")]
    CounterOverflow,
}
