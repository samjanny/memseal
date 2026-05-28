//! High-level API for creating, opening, and managing encrypted vaults.
//!
//! # Examples
//!
//! ```
//! use memseal::Vault;
//!
//! let mut vault = Vault::create(b"my-password-here").unwrap();
//!
//! vault.store("api_key", b"sk-secret-12345").unwrap();
//! assert_eq!(
//!     vault.retrieve("api_key").unwrap(),
//!     Some(b"sk-secret-12345".to_vec())
//! );
//!
//! let bytes = vault.export().unwrap();
//! let reopened = Vault::open(b"my-password-here", &bytes).unwrap();
//! assert_eq!(
//!     reopened.retrieve("api_key").unwrap(),
//!     Some(b"sk-secret-12345".to_vec())
//! );
//! ```

use crate::constants::argon2::KEY_LEN;
use crate::constants::nonce_derivation::{
    DATA_NONCE_HKDF_INFO_PREFIX, NAME_NONCE_HKDF_INFO_PREFIX,
};
use crate::constants::xchacha20_poly1305::XCHACHA20_NONCE_LEN;
use crate::constants::{
    MAX_ENTRY_DATA_SIZE, MAX_ENTRY_NAME_LEN, MIN_KDF_ITERATIONS, MIN_KDF_MEMORY, MIN_PASSWORD_LEN,
    SUPPORTED_VAULT_VERSIONS, VAULT_VERSION,
};
use crate::crypto::aad_aead::{open_with_aad, seal_with_aad};
use crate::crypto::utils::secure_bytes_fill;
use crate::mem::secure_memory_vault::MemoryVaultError;
use crate::vault::vault_error::VaultError;
use crate::vault::vault_header::VaultHeader;
use crate::vault::vault_index::{
    IndexMetaBlockLocation, IndexMetaBlockMetadata, VaultIndex, derive_subkeys,
};
use orion::hazardous::kdf::{argon2i, hkdf};
use std::io::Read as IoRead;
use std::path::Path;
use zeroize::Zeroize;

const MAX_KDF_MEMORY: u32 = 4_194_304; // 4 GiB
const MAX_KDF_ITERATIONS: u32 = 100;
const MAX_VAULT_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

/// An encrypted in-memory vault for storing named secrets.
///
/// Secrets are encrypted with XChaCha20-Poly1305, keys are derived from a
/// password via Argon2i, and all key material is zeroized on drop.
///
/// # Examples
///
/// ```
/// use memseal::Vault;
///
/// let mut vault = Vault::create(b"password1234").unwrap();
/// vault.store("db_url", b"postgres://localhost/mydb").unwrap();
///
/// # let dir = std::env::temp_dir();
/// # let path = dir.join("test_vault_doc2.seal");
/// vault.save(&path).unwrap();
///
/// let loaded = Vault::load(&path, b"password1234").unwrap();
/// assert_eq!(
///     loaded.retrieve("db_url").unwrap(),
///     Some(b"postgres://localhost/mydb".to_vec())
/// );
/// # std::fs::remove_file(&path).ok();
/// ```
pub struct Vault {
    header: VaultHeader,
    index: VaultIndex<crate::crypto::nonce_rotation::NonceNotRotated>,
}

impl Vault {
    /// Creates a new empty vault protected by the given password.
    ///
    /// Password must be at least 8 bytes.
    pub fn create(password: &[u8]) -> Result<Self, VaultError> {
        validate_password(password)?;
        let header = VaultHeader::generate()?;
        let mut master_key = derive_master_key(password, &header)?;

        let result = VaultIndex::from_master_key(&master_key, &header.kdf_salt)
            .map_err(|e| VaultError::CryptoError(e.to_string()));

        master_key.zeroize();
        Ok(Vault {
            header,
            index: result?,
        })
    }

    /// Opens an existing vault from exported bytes.
    ///
    /// Returns [`VaultError::InvalidPassword`] if the password is wrong.
    pub fn open(password: &[u8], data: &[u8]) -> Result<Self, VaultError> {
        if data.len() < 4 {
            return Err(VaultError::CorruptedData("Data too short".to_string()));
        }

        let header_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;

        if header_len > MAX_VAULT_FILE_SIZE as usize {
            return Err(VaultError::CorruptedData(
                "Header length too large".to_string(),
            ));
        }

        let after_header = 4usize
            .checked_add(header_len)
            .ok_or(VaultError::CorruptedData(
                "Header length overflow".to_string(),
            ))?;

        let min_total = after_header
            .checked_add(XCHACHA20_NONCE_LEN + 8)
            .ok_or(VaultError::CorruptedData("Size overflow".to_string()))?;

        if data.len() < min_total {
            return Err(VaultError::CorruptedData(
                "Data too short for nonce and counter".to_string(),
            ));
        }

        let header: VaultHeader = serde_json::from_slice(&data[4..after_header])
            .map_err(|e| VaultError::CorruptedData(format!("Invalid header JSON: {}", e)))?;

        validate_header(&header)?;

        let nonce: [u8; XCHACHA20_NONCE_LEN] = data
            [after_header..after_header + XCHACHA20_NONCE_LEN]
            .try_into()
            .unwrap();

        let counter_start = after_header + XCHACHA20_NONCE_LEN;
        let encrypted_index = &data[counter_start + 8..];

        let mut master_key = derive_master_key(password, &header)?;
        let mut enc_sub = [0u8; 32];

        let result = (|| -> Result<Self, VaultError> {
            let (e, _h) = derive_subkeys(&master_key, &header.kdf_salt)
                .map_err(|e| VaultError::CryptoError(e.to_string()))?;
            enc_sub = e;

            let aad = header.to_aad_bytes()?;
            let index_json = open_with_aad(&enc_sub, &nonce, encrypted_index, &aad)
                .map_err(|_| VaultError::InvalidPassword)?;

            #[derive(serde::Deserialize)]
            struct IndexData {
                version: u16,
                nonce: [u8; XCHACHA20_NONCE_LEN],
                nonce_counter: u64,
                data_nonce_counter: u64,
                files: std::collections::HashMap<String, IndexMetaBlockMetadata>,
            }

            let idx_data: IndexData = serde_json::from_slice(&index_json)
                .map_err(|e| VaultError::CorruptedData(format!("Invalid index JSON: {}", e)))?;

            if !crate::constants::vault_index_constants::SUPPORTED_VAULT_INDEX_VERSIONS
                .contains(&idx_data.version)
            {
                return Err(VaultError::CorruptedData(format!(
                    "Unsupported index version: {}",
                    idx_data.version
                )));
            }

            let index = VaultIndex::from_master_key_and_data(
                &master_key,
                &header.kdf_salt,
                idx_data.nonce,
                idx_data.nonce_counter,
                idx_data.data_nonce_counter,
                idx_data.files,
            )
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

            Ok(Vault { header, index })
        })();

        master_key.zeroize();
        enc_sub.zeroize();
        result
    }

    /// Loads a vault from a file on disk.
    ///
    /// Reads at most 256 MiB to prevent resource exhaustion.
    pub fn load(path: &Path, password: &[u8]) -> Result<Self, VaultError> {
        let file = std::fs::File::open(path)?;
        let mut limited = file.take(MAX_VAULT_FILE_SIZE + 1);
        let mut data = Vec::new();
        limited.read_to_end(&mut data)?;
        if data.len() as u64 > MAX_VAULT_FILE_SIZE {
            return Err(VaultError::CorruptedData(format!(
                "Vault file too large (max {} bytes)",
                MAX_VAULT_FILE_SIZE
            )));
        }
        Self::open(password, &data)
    }

    /// Stores a named secret in the vault, encrypting it immediately.
    ///
    /// Name must be at most 255 bytes. Data must be at most 64 MiB.
    /// If a secret with the same name already exists, it is overwritten.
    pub fn store(&mut self, name: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        if name.len() > MAX_ENTRY_NAME_LEN {
            return Err(VaultError::CryptoError(format!(
                "Entry name too long: {} bytes (max {})",
                name.len(),
                MAX_ENTRY_NAME_LEN
            )));
        }
        if plaintext.len() > MAX_ENTRY_DATA_SIZE {
            return Err(VaultError::CryptoError(format!(
                "Entry data too large: {} bytes (max {})",
                plaintext.len(),
                MAX_ENTRY_DATA_SIZE
            )));
        }

        let data_counter = self
            .index
            .next_data_nonce_counter()
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let enc_vault = self.index.enc_key().ok_or(VaultError::InvalidKey)?;

        let mut enc_key_bytes = [0u8; 32];
        let mut data_nonce = [0u8; XCHACHA20_NONCE_LEN];
        let mut name_nonce = [0u8; XCHACHA20_NONCE_LEN];

        let salt = self.index.kdf_salt().to_vec();
        enc_vault
            .access(|chunk, _tag| {
                if chunk.len() >= 32 {
                    enc_key_bytes.copy_from_slice(&chunk[..32]);
                }
                data_nonce = derive_nonce_with_prefix(
                    &enc_key_bytes,
                    data_counter,
                    DATA_NONCE_HKDF_INFO_PREFIX,
                    &salt,
                )
                .map_err(|e| MemoryVaultError::GenericError(e.to_string()))?;
                name_nonce = derive_nonce_with_prefix(
                    &enc_key_bytes,
                    data_counter,
                    NAME_NONCE_HKDF_INFO_PREFIX,
                    &salt,
                )
                .map_err(|e| MemoryVaultError::GenericError(e.to_string()))?;
                Ok(())
            })
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Compute HMAC'd key for AAD binding (prevents entry-swap attacks)
        let hmac_key = self
            .index
            .lookup_hmac_key_for_name(name)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;
        let entry_aad = build_entry_aad(&hmac_key, data_counter);

        let result = (|| -> Result<(), VaultError> {
            let ciphertext = seal_with_aad(&enc_key_bytes, &data_nonce, plaintext, &entry_aad)
                .map_err(|e| VaultError::CryptoError(e.to_string()))?;

            let encrypted_name_ct =
                seal_with_aad(&enc_key_bytes, &name_nonce, name.as_bytes(), &entry_aad)
                    .map_err(|e| VaultError::CryptoError(e.to_string()))?;

            let mut encrypted = Vec::with_capacity(XCHACHA20_NONCE_LEN + ciphertext.len());
            encrypted.extend_from_slice(&data_nonce);
            encrypted.extend_from_slice(&ciphertext);

            let mut enc_name = Vec::with_capacity(XCHACHA20_NONCE_LEN + encrypted_name_ct.len());
            enc_name.extend_from_slice(&name_nonce);
            enc_name.extend_from_slice(&encrypted_name_ct);

            let metadata = IndexMetaBlockMetadata::new(
                IndexMetaBlockLocation::Inline,
                0,
                0,
                false,
                Some(encrypted),
                Some(enc_name),
                data_counter,
            );

            self.index
                .insert_file(name, metadata)
                .map_err(|e| VaultError::CryptoError(e.to_string()))?;

            Ok(())
        })();

        enc_key_bytes.zeroize();
        result
    }

    /// Retrieves a secret by name, decrypting it.
    ///
    /// Returns `Ok(None)` if no secret with that name exists.
    pub fn retrieve(&self, name: &str) -> Result<Option<Vec<u8>>, VaultError> {
        let hmac_key = self
            .index
            .lookup_hmac_key_for_name(name)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let meta = self
            .index
            .lookup_file(name)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let meta = match meta {
            Some(m) => m,
            None => return Ok(None),
        };

        let encrypted = match &meta.encrypted_data {
            Some(d) => d,
            None => return Ok(None),
        };

        if encrypted.len() < XCHACHA20_NONCE_LEN {
            return Err(VaultError::CorruptedData(
                "Encrypted data too short for nonce".to_string(),
            ));
        }

        let enc_vault = self.index.enc_key().ok_or(VaultError::InvalidKey)?;

        let mut enc_key_bytes = [0u8; 32];
        enc_vault
            .access(|chunk, _tag| {
                if chunk.len() >= 32 {
                    enc_key_bytes.copy_from_slice(&chunk[..32]);
                }
                Ok(())
            })
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let nonce: [u8; XCHACHA20_NONCE_LEN] = encrypted[..XCHACHA20_NONCE_LEN].try_into().unwrap();
        let ciphertext = &encrypted[XCHACHA20_NONCE_LEN..];

        let entry_aad = build_entry_aad(&hmac_key, meta.data_counter);

        let plaintext = open_with_aad(&enc_key_bytes, &nonce, ciphertext, &entry_aad)
            .map_err(|e| VaultError::CryptoError(e.to_string()));

        enc_key_bytes.zeroize();
        Ok(Some(plaintext?))
    }

    /// Removes a secret by name. Returns `true` if it existed.
    pub fn remove(&mut self, name: &str) -> Result<bool, VaultError> {
        let removed = self
            .index
            .remove_file(name)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        if let Some(mut meta) = removed {
            if let Some(ref mut data) = meta.encrypted_data {
                data.zeroize();
            }
            if let Some(ref mut name_data) = meta.encrypted_name {
                name_data.zeroize();
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Serializes the vault to bytes for persistence.
    ///
    /// Each call rotates the index nonce to prevent nonce reuse.
    pub fn export(&mut self) -> Result<Vec<u8>, VaultError> {
        self.index
            .advance_nonce()
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let header_json = serde_json::to_vec(&self.header)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        let index_json = serde_json::to_vec(&self.index)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        let enc_vault = self.index.enc_key().ok_or(VaultError::InvalidKey)?;
        let mut enc_key_bytes = [0u8; 32];
        enc_vault
            .access(|chunk, _tag| {
                if chunk.len() >= 32 {
                    enc_key_bytes.copy_from_slice(&chunk[..32]);
                }
                Ok(())
            })
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let aad = self.header.to_aad_bytes()?;
        let encrypted_index = seal_with_aad(&enc_key_bytes, &self.index.nonce, &index_json, &aad)
            .map_err(|e| VaultError::CryptoError(e.to_string()));

        enc_key_bytes.zeroize();
        let encrypted_index = encrypted_index?;

        let header_len = (header_json.len() as u32).to_le_bytes();

        let mut output = Vec::with_capacity(
            4 + header_json.len() + XCHACHA20_NONCE_LEN + 8 + encrypted_index.len(),
        );
        output.extend_from_slice(&header_len);
        output.extend_from_slice(&header_json);
        output.extend_from_slice(&self.index.nonce);
        output.extend_from_slice(&self.index.nonce_counter.to_le_bytes());
        output.extend_from_slice(&encrypted_index);

        Ok(output)
    }

    /// Saves the vault to a file on disk.
    ///
    /// Uses atomic write (temp file + rename) with 0600 permissions on Unix.
    pub fn save(&mut self, path: &Path) -> Result<(), VaultError> {
        use std::io::Write;

        let data = self.export()?;
        let dir = path.parent().unwrap_or(Path::new("."));

        let mut rand_suffix = [0u8; 8];
        secure_bytes_fill(&mut rand_suffix).map_err(|e| VaultError::CryptoError(e.to_string()))?;
        let hex_suffix: String = rand_suffix.iter().map(|b| format!("{:02x}", b)).collect();
        let tmp_path = dir.join(format!(".memseal_tmp_{}", hex_suffix));

        let mut file = {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }

            opts.open(&tmp_path)?
        };

        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })?;

        #[cfg(unix)]
        if let Ok(dir_file) = std::fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }

        Ok(())
    }

    /// Changes the vault's password.
    ///
    /// Re-derives all keys from the new password and re-encrypts every entry
    /// one at a time (at most one plaintext in memory at any given time).
    pub fn change_password(
        &mut self,
        current_password: &[u8],
        new_password: &[u8],
    ) -> Result<(), VaultError> {
        validate_password(new_password)?;

        // Verify current password by exporting and re-opening.
        // Note: export() advances the nonce counter on self. If the password
        // check fails, self has a different nonce but is otherwise unchanged
        // and fully functional. This is acceptable because the nonce counter
        // is monotonic and the vault data is intact.
        let mut exported = self.export()?;
        let _ = Vault::open(current_password, &exported)?;
        exported.zeroize();

        let new_header = VaultHeader::generate()?;
        let mut new_master_key = derive_master_key(new_password, &new_header)?;

        // Collect encrypted entries with HMAC'd keys and data_counter for AAD
        type OldEntry = (String, u64, Option<Vec<u8>>, Option<Vec<u8>>);
        let old_entries: Vec<OldEntry> = self
            .index
            .files
            .iter()
            .map(|(k, m)| {
                (
                    k.clone(),
                    m.data_counter,
                    m.encrypted_name.clone(),
                    m.encrypted_data.clone(),
                )
            })
            .collect();

        let old_enc_vault = self.index.enc_key().ok_or(VaultError::InvalidKey)?;
        let mut old_enc_key = [0u8; 32];
        old_enc_vault
            .access(|chunk, _tag| {
                if chunk.len() >= 32 {
                    old_enc_key.copy_from_slice(&chunk[..32]);
                }
                Ok(())
            })
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Build new vault - zeroize both keys on any failure
        let new_index_result = VaultIndex::from_master_key(&new_master_key, &new_header.kdf_salt)
            .map_err(|e| VaultError::CryptoError(e.to_string()));
        new_master_key.zeroize();
        let new_index = match new_index_result {
            Ok(idx) => idx,
            Err(e) => {
                old_enc_key.zeroize();
                return Err(e);
            }
        };

        let mut new_vault = Vault {
            header: new_header,
            index: new_index,
        };

        // Re-encrypt entries one at a time into new_vault
        let loop_result = (|| -> Result<(), VaultError> {
            for (old_hmac_key, old_counter, enc_name_opt, enc_data_opt) in &old_entries {
                let old_aad = build_entry_aad(old_hmac_key, *old_counter);

                let mut plaintext_name = match enc_name_opt {
                    Some(enc_name) if enc_name.len() >= XCHACHA20_NONCE_LEN => {
                        let nonce: [u8; XCHACHA20_NONCE_LEN] =
                            enc_name[..XCHACHA20_NONCE_LEN].try_into().unwrap();
                        let ct = &enc_name[XCHACHA20_NONCE_LEN..];
                        let name_bytes = open_with_aad(&old_enc_key, &nonce, ct, &old_aad)
                            .map_err(|e| VaultError::CryptoError(e.to_string()))?;
                        String::from_utf8(name_bytes).map_err(|_| {
                            VaultError::CorruptedData("Invalid entry name".to_string())
                        })?
                    }
                    _ => continue,
                };

                let encrypted = match enc_data_opt {
                    Some(enc) if enc.len() >= XCHACHA20_NONCE_LEN => enc,
                    _ => {
                        plaintext_name.zeroize();
                        continue;
                    }
                };

                let nonce: [u8; XCHACHA20_NONCE_LEN] =
                    encrypted[..XCHACHA20_NONCE_LEN].try_into().unwrap();
                let ciphertext = &encrypted[XCHACHA20_NONCE_LEN..];
                let mut plaintext = open_with_aad(&old_enc_key, &nonce, ciphertext, &old_aad)
                    .map_err(|e| VaultError::CryptoError(e.to_string()))?;

                let store_result = new_vault.store(&plaintext_name, &plaintext);
                plaintext.zeroize();
                plaintext_name.zeroize();
                store_result?;
            }
            Ok(())
        })();

        old_enc_key.zeroize();

        // Only swap on full success - on error, self retains old keys/data
        // (nonce counter may have advanced from the export() verification above)
        loop_result?;
        self.header = new_vault.header;
        self.index = new_vault.index;
        Ok(())
    }
}

fn validate_password(password: &[u8]) -> Result<(), VaultError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(VaultError::CryptoError(format!(
            "Password must be at least {} bytes",
            MIN_PASSWORD_LEN
        )));
    }
    Ok(())
}

fn validate_header(header: &VaultHeader) -> Result<(), VaultError> {
    if !SUPPORTED_VAULT_VERSIONS.contains(&header.version) {
        return Err(VaultError::CorruptedData(format!(
            "Unsupported vault version: {} (supported: {})",
            header.version, VAULT_VERSION
        )));
    }
    if header.kdf_memory_cost > MAX_KDF_MEMORY || header.kdf_memory_cost < MIN_KDF_MEMORY {
        return Err(VaultError::CorruptedData(format!(
            "KDF memory cost out of range: {} KiB (allowed {}-{})",
            header.kdf_memory_cost, MIN_KDF_MEMORY, MAX_KDF_MEMORY
        )));
    }
    if header.kdf_iterations > MAX_KDF_ITERATIONS || header.kdf_iterations < MIN_KDF_ITERATIONS {
        return Err(VaultError::CorruptedData(format!(
            "KDF iterations out of range: {} (allowed {}-{})",
            header.kdf_iterations, MIN_KDF_ITERATIONS, MAX_KDF_ITERATIONS
        )));
    }
    if header.key_length != KEY_LEN {
        return Err(VaultError::CorruptedData(format!(
            "Invalid key length: {} (expected {})",
            header.key_length, KEY_LEN
        )));
    }
    Ok(())
}

fn build_entry_aad(hmac_key: &str, counter: u64) -> Vec<u8> {
    let key_bytes = hmac_key.as_bytes();
    let counter_bytes = counter.to_le_bytes();
    let mut aad = Vec::with_capacity(key_bytes.len() + 8);
    aad.extend_from_slice(key_bytes);
    aad.extend_from_slice(&counter_bytes);
    aad
}

fn derive_master_key(password: &[u8], header: &VaultHeader) -> Result<[u8; KEY_LEN], VaultError> {
    let mut master_key = [0u8; KEY_LEN];
    argon2i::derive_key(
        password,
        &header.kdf_salt,
        header.kdf_iterations,
        header.kdf_memory_cost,
        None,
        None,
        &mut master_key,
    )
    .map_err(|e| VaultError::CryptoError(format!("Argon2i derivation failed: {}", e)))?;
    Ok(master_key)
}

fn derive_nonce_with_prefix(
    enc_key: &[u8],
    counter: u64,
    prefix: &[u8],
    salt: &[u8],
) -> Result<[u8; XCHACHA20_NONCE_LEN], VaultError> {
    let counter_bytes = counter.to_le_bytes();
    let mut info = Vec::with_capacity(prefix.len() + 8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(&counter_bytes);

    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    hkdf::sha256::derive_key(salt, enc_key, Some(&info), &mut nonce)
        .map_err(|e| VaultError::CryptoError(format!("Nonce derivation failed: {}", e)))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_export_open_roundtrip() {
        let mut vault = Vault::create(b"test-password-123").unwrap();
        let exported = vault.export().unwrap();
        let _reopened = Vault::open(b"test-password-123", &exported).unwrap();
    }

    #[test]
    fn store_and_retrieve_roundtrip() {
        let mut vault = Vault::create(b"test-password").unwrap();
        vault.store("api_key", b"sk-secret-12345").unwrap();

        let exported = vault.export().unwrap();
        let reopened = Vault::open(b"test-password", &exported).unwrap();
        assert_eq!(
            reopened.retrieve("api_key").unwrap(),
            Some(b"sk-secret-12345".to_vec())
        );
    }

    #[test]
    fn retrieve_missing_returns_none() {
        let vault = Vault::create(b"password").unwrap();
        assert_eq!(vault.retrieve("nonexistent").unwrap(), None);
    }

    #[test]
    fn remove_returns_true_for_existing() {
        let mut vault = Vault::create(b"password").unwrap();
        vault.store("key", b"value").unwrap();
        assert!(vault.remove("key").unwrap());
        assert_eq!(vault.retrieve("key").unwrap(), None);
    }

    #[test]
    fn remove_returns_false_for_missing() {
        let mut vault = Vault::create(b"password").unwrap();
        assert!(!vault.remove("nonexistent").unwrap());
    }

    #[test]
    fn wrong_password_fails_open() {
        let mut vault = Vault::create(b"correct-pw").unwrap();
        let exported = vault.export().unwrap();
        assert!(matches!(
            Vault::open(b"wrong-pw!", &exported),
            Err(VaultError::InvalidPassword)
        ));
    }

    #[test]
    fn tampered_export_fails_open() {
        let mut vault = Vault::create(b"password").unwrap();
        let mut exported = vault.export().unwrap();
        if let Some(last) = exported.last_mut() {
            *last ^= 0xFF;
        }
        assert!(Vault::open(b"password", &exported).is_err());
    }

    #[test]
    fn multiple_entries() {
        let mut vault = Vault::create(b"password").unwrap();
        vault.store("key1", b"value1").unwrap();
        vault.store("key2", b"value2").unwrap();
        vault.store("key3", b"value3").unwrap();

        let exported = vault.export().unwrap();
        let reopened = Vault::open(b"password", &exported).unwrap();

        assert_eq!(reopened.retrieve("key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(reopened.retrieve("key2").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(reopened.retrieve("key3").unwrap(), Some(b"value3".to_vec()));
    }

    #[test]
    fn empty_vault_roundtrip() {
        let mut vault = Vault::create(b"password").unwrap();
        let exported = vault.export().unwrap();
        let _reopened = Vault::open(b"password", &exported).unwrap();
    }

    #[test]
    fn store_empty_data() {
        let mut vault = Vault::create(b"password").unwrap();
        vault.store("empty", b"").unwrap();

        let exported = vault.export().unwrap();
        let reopened = Vault::open(b"password", &exported).unwrap();
        assert_eq!(reopened.retrieve("empty").unwrap(), Some(vec![]));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("memseal_test_save_load2.seal");

        let mut vault = Vault::create(b"file-password").unwrap();
        vault.store("secret", b"file-stored-value").unwrap();
        vault.save(&path).unwrap();

        let loaded = Vault::load(&path, b"file-password").unwrap();
        assert_eq!(
            loaded.retrieve("secret").unwrap(),
            Some(b"file-stored-value".to_vec())
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_wrong_password_fails() {
        let dir = std::env::temp_dir();
        let path = dir.join("memseal_test_wrong_pw2.seal");

        let mut vault = Vault::create(b"correct!").unwrap();
        vault.save(&path).unwrap();

        assert!(matches!(
            Vault::load(&path, b"wrong!!!"),
            Err(VaultError::InvalidPassword)
        ));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn change_password_then_retrieve_by_name() {
        let mut vault = Vault::create(b"old-password").unwrap();
        vault.store("key", b"preserved-value").unwrap();

        vault
            .change_password(b"old-password", b"new-password")
            .unwrap();

        let mut exported = vault.export().unwrap();
        assert!(Vault::open(b"old-password", &exported).is_err());

        let reopened = Vault::open(b"new-password", &exported).unwrap();
        assert_eq!(
            reopened.retrieve("key").unwrap(),
            Some(b"preserved-value".to_vec())
        );
        exported.zeroize();
    }

    #[test]
    fn change_password_wrong_current_fails() {
        let mut vault = Vault::create(b"real-pwd!").unwrap();
        assert!(vault.change_password(b"wrong!!!", b"new-pwd!").is_err());
    }

    #[test]
    fn export_rotates_nonce() {
        let mut vault = Vault::create(b"password").unwrap();
        let nonce_before = vault.index.nonce;
        let _ = vault.export().unwrap();
        assert_ne!(vault.index.nonce, nonce_before);
    }

    #[test]
    fn multiple_exports_produce_different_ciphertext() {
        let mut vault = Vault::create(b"password").unwrap();
        vault.store("k", b"v").unwrap();
        let e1 = vault.export().unwrap();
        let e2 = vault.export().unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn header_validation_rejects_extreme_memory() {
        let bad = VaultHeader::new([0; 16], 4, MAX_KDF_MEMORY + 1, 32);
        assert!(validate_header(&bad).is_err());
    }

    #[test]
    fn header_validation_rejects_zero_iterations() {
        let bad = VaultHeader::new([0; 16], 0, 131_072, 32);
        assert!(validate_header(&bad).is_err());
    }

    #[test]
    fn header_validation_rejects_wrong_version() {
        let mut h = VaultHeader::new([0; 16], 4, 131_072, 32);
        h.version = 99;
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn header_validation_rejects_wrong_key_length() {
        let bad = VaultHeader::new([0; 16], 4, 131_072, 16);
        assert!(validate_header(&bad).is_err());
    }

    #[test]
    fn header_validation_rejects_below_minimum_memory() {
        let bad = VaultHeader::new([0; 16], 4, MIN_KDF_MEMORY - 1, 32);
        assert!(validate_header(&bad).is_err());
    }

    #[test]
    fn short_password_rejected() {
        assert!(Vault::create(b"short").is_err());
    }

    #[test]
    fn long_entry_name_rejected() {
        let mut vault = Vault::create(b"password").unwrap();
        let long_name = "x".repeat(MAX_ENTRY_NAME_LEN + 1);
        assert!(vault.store(&long_name, b"data").is_err());
    }

    #[test]
    fn header_len_overflow_rejected() {
        let mut data = vec![0u8; 100];
        data[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Vault::open(b"password", &data).is_err());
    }

    // Tampering group A: raw-bytes truncation and boundary checks.
    // These test the bounded parsing logic of `Vault::open` independent of
    // header content or ciphertext validity.

    fn make_valid_export(password: &[u8]) -> Vec<u8> {
        let mut vault = Vault::create(password).unwrap();
        vault.store("k", b"v").unwrap();
        vault.export().unwrap()
    }

    #[test]
    fn open_rejects_empty_input() {
        let result = Vault::open(b"password", &[]);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_input_below_header_len_field() {
        let result = Vault::open(b"password", &[0u8, 0, 0]);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_zero_header_len() {
        // 4 bytes containing header_len=0, plus enough trailing bytes to clear
        // the size check. Header JSON region is empty so deserialization fails.
        let mut data = vec![0u8; 4 + XCHACHA20_NONCE_LEN + 8];
        data[..4].copy_from_slice(&0u32.to_le_bytes());
        let result = Vault::open(b"password", &data);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_header_len_exceeding_available_bytes() {
        // header_len within MAX_VAULT_FILE_SIZE but larger than provided bytes.
        // Exercises the `data.len() < min_total` branch, distinct from the
        // `header_len > MAX_VAULT_FILE_SIZE` branch covered by
        // `header_len_overflow_rejected`.
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(&10_000u32.to_le_bytes());
        let result = Vault::open(b"password", &data);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_truncation_inside_nonce_region() {
        // Truncate a valid export inside the 24-byte nonce region.
        let valid = make_valid_export(b"password-aaaa");
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let nonce_start = 4 + header_len;
        // Keep half of the nonce so the size check fails.
        let truncated = &valid[..nonce_start + XCHACHA20_NONCE_LEN / 2];
        let result = Vault::open(b"password-aaaa", truncated);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_truncation_inside_counter_region() {
        // Truncate a valid export inside the 8-byte counter region.
        let valid = make_valid_export(b"password-bbbb");
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let counter_start = 4 + header_len + XCHACHA20_NONCE_LEN;
        // Keep half of the counter so the size check fails.
        let truncated = &valid[..counter_start + 4];
        let result = Vault::open(b"password-bbbb", truncated);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_missing_ciphertext_after_counter() {
        // Header + nonce + counter present, but the ciphertext region is empty
        // (no AEAD tag). The size check passes; AEAD must reject the input.
        // `open_with_aad` failures are surfaced as `InvalidPassword` by design.
        let valid = make_valid_export(b"password-cccc");
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let cut = 4 + header_len + XCHACHA20_NONCE_LEN + 8;
        let truncated = &valid[..cut];
        let result = Vault::open(b"password-cccc", truncated);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    // Tampering group B: header JSON tampering and AAD divergence.
    // The vault header is serialized as JSON and used as AAD for index
    // encryption. Any modification must either be rejected by parsing/
    // validation or surface as an AEAD failure (`InvalidPassword`).

    fn replace_header_json(export: &[u8], new_header_json: &[u8]) -> Vec<u8> {
        let old_header_len = u32::from_le_bytes(export[..4].try_into().unwrap()) as usize;
        let after_old_header = 4 + old_header_len;
        let mut out =
            Vec::with_capacity(4 + new_header_json.len() + export.len() - after_old_header);
        out.extend_from_slice(&(new_header_json.len() as u32).to_le_bytes());
        out.extend_from_slice(new_header_json);
        out.extend_from_slice(&export[after_old_header..]);
        out
    }

    fn extract_header_value(export: &[u8]) -> serde_json::Value {
        let header_len = u32::from_le_bytes(export[..4].try_into().unwrap()) as usize;
        serde_json::from_slice(&export[4..4 + header_len]).unwrap()
    }

    #[test]
    fn open_rejects_malformed_header_json() {
        let valid = make_valid_export(b"password-dddd");
        let tampered = replace_header_json(&valid, b"{");
        let result = Vault::open(b"password-dddd", &tampered);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_header_missing_required_field() {
        let valid = make_valid_export(b"password-eeee");
        let mut value = extract_header_value(&valid);
        // Drop the `version` field; deserialization must fail because
        // VaultHeader fields have no serde defaults.
        value.as_object_mut().unwrap().remove("version");
        let new_json = serde_json::to_vec(&value).unwrap();
        let tampered = replace_header_json(&valid, &new_json);
        let result = Vault::open(b"password-eeee", &tampered);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_header_with_unsupported_version() {
        let valid = make_valid_export(b"password-ffff");
        let mut value = extract_header_value(&valid);
        value.as_object_mut().unwrap().insert(
            "version".to_string(),
            serde_json::Value::Number(999u16.into()),
        );
        let new_json = serde_json::to_vec(&value).unwrap();
        let tampered = replace_header_json(&valid, &new_json);
        let result = Vault::open(b"password-ffff", &tampered);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_header_with_out_of_range_kdf_memory() {
        // Exercises validate_header() through the full open() path, distinct
        // from the unit test that calls validate_header() in isolation.
        let valid = make_valid_export(b"password-gggg");
        let mut value = extract_header_value(&valid);
        value.as_object_mut().unwrap().insert(
            "kdf_memory_cost".to_string(),
            serde_json::Value::Number((MAX_KDF_MEMORY + 1).into()),
        );
        let new_json = serde_json::to_vec(&value).unwrap();
        let tampered = replace_header_json(&valid, &new_json);
        let result = Vault::open(b"password-gggg", &tampered);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_header_with_modified_salt() {
        // Salt is part of the header AAD AND drives master key derivation.
        // Both effects independently force AEAD to fail; surfaced as
        // InvalidPassword.
        let valid = make_valid_export(b"password-hhhh");
        let mut value = extract_header_value(&valid);
        let salt = value
            .as_object_mut()
            .unwrap()
            .get_mut("kdf_salt")
            .unwrap()
            .as_array_mut()
            .unwrap();
        // Flip a byte in the salt.
        let first = salt[0].as_u64().unwrap();
        salt[0] = serde_json::Value::Number((first ^ 0xFF & 0xFF).into());
        let new_json = serde_json::to_vec(&value).unwrap();
        let tampered = replace_header_json(&valid, &new_json);
        let result = Vault::open(b"password-hhhh", &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn open_rejects_cross_vault_header_swap() {
        // Two vaults created with the same password produce different headers
        // (different random salts). Swapping the header of vault A onto the
        // ciphertext of vault B must fail: the header bytes are bound to the
        // index ciphertext as AAD, and the salt drives master key derivation.
        let password: &[u8] = b"shared-password";
        let export_a = make_valid_export(password);
        let export_b = make_valid_export(password);

        let header_len_a = u32::from_le_bytes(export_a[..4].try_into().unwrap()) as usize;
        let header_a_json = &export_a[4..4 + header_len_a];

        let tampered = replace_header_json(&export_b, header_a_json);
        let result = Vault::open(password, &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    // Tampering group C: nonce and counter region tampering.
    // The nonce is part of the AEAD construction; tampering must surface as
    // an AEAD failure. The counter field stored in the file at the fixed
    // offset is an export of vault state but is not consumed by `open()`
    // (the authoritative counter values are inside the encrypted index JSON).

    #[test]
    fn open_rejects_bit_flipped_nonce() {
        let password: &[u8] = b"password-iiii";
        let valid = make_valid_export(password);
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let nonce_start = 4 + header_len;

        let mut tampered = valid.clone();
        // Flip the first byte of the 24-byte nonce.
        tampered[nonce_start] ^= 0x01;

        let result = Vault::open(password, &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn open_ignores_counter_field_in_file() {
        // The 8-byte counter field written by `export()` at offset
        // `4 + header_len + 24` is never read back by `open()`; the
        // authoritative counter is recovered from the encrypted index JSON.
        // This test pins that behavior: flipping every bit of those 8 bytes
        // must NOT change the outcome of `open()`. If this test ever starts
        // failing, the file format is being used differently and the layout
        // should be revisited (the 8 bytes are otherwise wire-format dead
        // weight that should either be removed or actually consumed).
        let password: &[u8] = b"password-jjjj";
        let valid = make_valid_export(password);
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let counter_start = 4 + header_len + XCHACHA20_NONCE_LEN;

        let mut tampered = valid.clone();
        for i in 0..8 {
            tampered[counter_start + i] ^= 0xFF;
        }

        let from_valid = Vault::open(password, &valid).unwrap();
        let from_tampered = Vault::open(password, &tampered).unwrap();
        // Both opens succeed and recover the same authoritative counter.
        assert_eq!(
            from_valid.index.nonce_counter,
            from_tampered.index.nonce_counter
        );
    }

    #[test]
    fn open_rejects_replaying_old_nonce_into_new_export() {
        // Each `export()` rotates the nonce. Splicing the nonce from an
        // earlier export onto a later export's ciphertext must fail because
        // the ciphertext was sealed with the later nonce; the AAD also
        // authenticates the header but the nonce is what the AEAD uses to
        // decrypt.
        let password: &[u8] = b"password-kkkk";
        let mut vault = Vault::create(password).unwrap();
        vault.store("k", b"v").unwrap();

        let export_first = vault.export().unwrap();
        let export_second = vault.export().unwrap();

        let header_len_first = u32::from_le_bytes(export_first[..4].try_into().unwrap()) as usize;
        let header_len_second = u32::from_le_bytes(export_second[..4].try_into().unwrap()) as usize;
        // The two exports share the same header (same KDF params and salt),
        // so the nonce offset is the same in both.
        assert_eq!(header_len_first, header_len_second);

        let nonce_start = 4 + header_len_second;
        let old_nonce =
            &export_first[4 + header_len_first..4 + header_len_first + XCHACHA20_NONCE_LEN];

        let mut tampered = export_second.clone();
        tampered[nonce_start..nonce_start + XCHACHA20_NONCE_LEN].copy_from_slice(old_nonce);

        // Sanity: the spliced nonce really differs from the second export's nonce.
        assert_ne!(
            &export_second[nonce_start..nonce_start + XCHACHA20_NONCE_LEN],
            old_nonce
        );

        let result = Vault::open(password, &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }
}
