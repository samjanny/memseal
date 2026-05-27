use crate::constants::nonce_derivation::NONCE_HKDF_INFO_PREFIX;
use crate::constants::xchacha20_poly1305::XCHACHA20_NONCE_LEN;
use orion::hazardous::kdf::hkdf;
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

/// Errors that can occur during nonce rotation or derivation.
#[derive(Debug, Error)]
pub enum NonceRotationError {
    #[error("Nonce rotation failed")]
    NonceRotationFailed,
    #[error("Nonce counter overflow")]
    CounterOverflow,
    #[error("HKDF derivation failed: {0}")]
    HkdfError(String),
    #[error("Key not available for nonce derivation")]
    KeyNotAvailable,
}

/// Derives a deterministic 24-byte XChaCha20 nonce from a key and counter via HKDF-SHA256.
pub fn derive_nonce_from_counter(
    key_bytes: &[u8],
    counter: u64,
    salt: &[u8],
) -> Result<[u8; XCHACHA20_NONCE_LEN], NonceRotationError> {
    let counter_bytes = counter.to_le_bytes();
    let mut info = Vec::with_capacity(NONCE_HKDF_INFO_PREFIX.len() + 8);
    info.extend_from_slice(NONCE_HKDF_INFO_PREFIX);
    info.extend_from_slice(&counter_bytes);

    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    hkdf::sha256::derive_key(salt, key_bytes, Some(&info), &mut nonce)
        .map_err(|e| NonceRotationError::HkdfError(format!("{}", e)))?;

    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_nonce_produces_24_byte_output() {
        let key = [0x42u8; 32];
        let nonce = derive_nonce_from_counter(&key, 0, &[]).unwrap();
        assert_eq!(nonce.len(), XCHACHA20_NONCE_LEN);
    }

    #[test]
    fn derive_nonce_is_deterministic() {
        let key = [0x42u8; 32];
        let n1 = derive_nonce_from_counter(&key, 42, &[]).unwrap();
        let n2 = derive_nonce_from_counter(&key, 42, &[]).unwrap();
        assert_eq!(n1, n2);
    }

    #[test]
    fn different_counters_produce_different_nonces() {
        let key = [0x42u8; 32];
        let n0 = derive_nonce_from_counter(&key, 0, &[]).unwrap();
        let n1 = derive_nonce_from_counter(&key, 1, &[]).unwrap();
        assert_ne!(n0, n1);
    }

    #[test]
    fn different_keys_produce_different_nonces() {
        let k1 = [0x42u8; 32];
        let k2 = [0x43u8; 32];
        let n1 = derive_nonce_from_counter(&k1, 0, &[]).unwrap();
        let n2 = derive_nonce_from_counter(&k2, 0, &[]).unwrap();
        assert_ne!(n1, n2);
    }
}
