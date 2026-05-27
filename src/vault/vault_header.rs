use crate::constants::argon2::SALT_LEN;
use crate::constants::{VAULT_VERSION, argon2};
use crate::crypto::utils::secure_bytes_fill;
use crate::vault::vault_error::VaultError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
/// Vault header containing KDF parameters and format version.
///
/// Serialized to JSON and used as AAD during index encryption,
/// so any tampering causes authenticated decryption failure.
pub struct VaultHeader {
    pub version: u16,
    pub kdf_salt: [u8; SALT_LEN],
    pub kdf_iterations: u32,
    pub kdf_memory_cost: u32,
    pub key_length: usize,
}

impl VaultHeader {
    /// Creates a header with explicit parameters.
    pub fn new(
        kdf_salt: [u8; SALT_LEN],
        kdf_iterations: u32,
        kdf_memory_cost: u32,
        key_length: usize,
    ) -> Self {
        VaultHeader {
            version: VAULT_VERSION,
            kdf_salt,
            kdf_iterations,
            kdf_memory_cost,
            key_length,
        }
    }

    /// Serializes this header to JSON bytes for use as AEAD additional authenticated data.
    pub fn to_aad_bytes(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self).map_err(|e| {
            VaultError::CryptoError(format!("Failed to serialize header for AAD: {}", e))
        })
    }

    /// Generates a new header with a random salt and default Argon2i parameters.
    pub fn generate() -> Result<Self, VaultError> {
        let mut kdf_salt = [0; SALT_LEN];
        secure_bytes_fill(&mut kdf_salt)
            .map_err(|e| VaultError::CryptoError(format!("Failed to fill secure bytes: {}", e)))?;
        Ok(VaultHeader::new(
            kdf_salt,
            argon2::ITERATIONS,
            argon2::MEMORY_COST,
            argon2::KEY_LEN,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::argon2::{ITERATIONS, KEY_LEN, MEMORY_COST, SALT_LEN};

    #[test]
    fn creates_vault_header_with_correct_parameters() {
        let salt = [1; SALT_LEN];
        let header = VaultHeader::new(salt, ITERATIONS, MEMORY_COST, KEY_LEN);
        assert_eq!(header.version, VAULT_VERSION);
        assert_eq!(header.kdf_salt, salt);
        assert_eq!(header.kdf_iterations, ITERATIONS);
        assert_eq!(header.kdf_memory_cost, MEMORY_COST);
        assert_eq!(header.key_length, KEY_LEN);
    }

    #[test]
    fn generates_vault_header_with_random_salt() {
        let header1 = VaultHeader::generate().unwrap();
        let header2 = VaultHeader::generate().unwrap();
        assert_ne!(header1.kdf_salt, header2.kdf_salt);
        assert_eq!(header1.kdf_iterations, ITERATIONS);
    }

    #[test]
    fn to_aad_bytes_is_deterministic() {
        let h = VaultHeader::new([0xAA; SALT_LEN], ITERATIONS, MEMORY_COST, KEY_LEN);
        let aad1 = h.to_aad_bytes().unwrap();
        let aad2 = h.to_aad_bytes().unwrap();
        assert_eq!(aad1, aad2);
        assert!(!aad1.is_empty());
    }

    #[test]
    fn different_headers_produce_different_aad() {
        let h1 = VaultHeader::new([1; SALT_LEN], ITERATIONS, MEMORY_COST, KEY_LEN);
        let h2 = VaultHeader::new([2; SALT_LEN], ITERATIONS, MEMORY_COST, KEY_LEN);
        assert_ne!(h1.to_aad_bytes().unwrap(), h2.to_aad_bytes().unwrap());
    }
}
