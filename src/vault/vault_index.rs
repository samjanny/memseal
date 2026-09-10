use crate::constants::subkeys::{ENCRYPTION_SUBKEY_INFO, HMAC_SUBKEY_INFO, SUBKEY_LEN};
use crate::constants::vault_index_constants::{
    MAX_INDEX_ENTRIES, SUPPORTED_VAULT_INDEX_VERSIONS, VAULT_INDEX_VERSION,
};
use crate::constants::xchacha20_poly1305::XCHACHA20_NONCE_LEN;
use crate::crypto::encdec_trait::{EncryptionError, SecureAccess, SecureConstructor};
use crate::crypto::nonce_rotation::{
    NonceNotRotated, NonceRotated, NonceRotation, NonceRotationError,
};
use crate::crypto::utils::secure_bytes_fill;
use crate::mem::secure_memory_vault::SecureMemoryVault;
use orion::hazardous::kdf::hkdf;
use orion::hazardous::mac::hmac::sha256::{HmacSha256, SecretKey as HmacSecretKey};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur in vault index operations.
#[derive(Debug, Error)]
pub enum IndexError {
    #[error("Offset is out of bounds")]
    OffsetOutOfBounds,
    #[error("Unsupported version")]
    UnsupportedVersion,
    #[error("Nonce error: {0}")]
    NonceError(String),
    #[error("Generic error: {0}")]
    GenericError(String),
}

/// Where an entry's data is stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
pub enum IndexMetaBlockLocation {
    LargeFile {
        metablock_uid: String,
    },
    SmallFileInPack {
        metablock_uid: String,
        offset: usize,
    },
    Inline,
}

/// Metadata for a single entry in the vault index.
///
/// Zeroized on drop, so ciphertexts that are replaced, removed, or released
/// with the vault do not linger in freed memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct IndexMetaBlockMetadata {
    pub location: IndexMetaBlockLocation,
    pub created: u64,
    pub modified: u64,
    pub is_dummy: bool,
    pub encrypted_data: Option<Vec<u8>>,
    pub encrypted_name: Option<Vec<u8>>,
    pub data_counter: u64,
}

/// Encrypted index mapping HMAC'd entry names to their metadata.
///
/// Carries a type-state parameter `N` (`NonceNotRotated` or `NonceRotated`)
/// for callers that consume the index through `rotate_nonce()`. The `Vault`
/// facade does not use the type-state path; it advances nonces imperatively
/// via `advance_nonce()` before each export.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultIndex<N> {
    pub version: u16,
    pub nonce: [u8; XCHACHA20_NONCE_LEN],
    pub nonce_counter: u64,
    pub data_nonce_counter: u64,
    pub files: HashMap<String, IndexMetaBlockMetadata>,
    #[serde(skip)]
    enc_key: Option<SecureMemoryVault>,
    #[serde(skip)]
    hmac_key: Option<SecureMemoryVault>,
    #[serde(skip)]
    kdf_salt: Vec<u8>,
    #[serde(skip)]
    _state: PhantomData<N>,
}

/// Derives separate encryption and HMAC subkeys from a master key via HKDF-SHA256.
pub fn derive_subkeys(
    master_key: &[u8],
    salt: &[u8],
) -> Result<([u8; SUBKEY_LEN], [u8; SUBKEY_LEN]), IndexError> {
    let mut enc_sub = [0u8; SUBKEY_LEN];
    hkdf::sha256::derive_key(salt, master_key, Some(ENCRYPTION_SUBKEY_INFO), &mut enc_sub)
        .map_err(|e| IndexError::GenericError(format!("HKDF enc subkey failed: {}", e)))?;

    let mut hmac_sub = [0u8; SUBKEY_LEN];
    hkdf::sha256::derive_key(salt, master_key, Some(HMAC_SUBKEY_INFO), &mut hmac_sub)
        .map_err(|e| IndexError::GenericError(format!("HKDF hmac subkey failed: {}", e)))?;

    Ok((enc_sub, hmac_sub))
}

impl<N> VaultIndex<N> {
    /// Returns a reference to the encryption subkey vault, if present.
    pub fn enc_key(&self) -> Option<&SecureMemoryVault> {
        self.enc_key.as_ref()
    }

    /// Returns a reference to the KDF salt used for HKDF derivation.
    pub fn kdf_salt(&self) -> &[u8] {
        &self.kdf_salt
    }

    /// Increments the nonce counter and generates a fresh random nonce.
    /// Must be called before each export.
    ///
    /// The nonce is drawn from the OS CSPRNG rather than derived from the
    /// counter, so two vault instances opened from the same persisted state
    /// cannot reuse a nonce when both export. The counter is kept as
    /// authenticated, monotonic state.
    pub fn advance_nonce(&mut self) -> Result<(), IndexError> {
        self.nonce_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or(IndexError::GenericError(
                "Nonce counter overflow".to_string(),
            ))?;

        let mut new_nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut new_nonce).map_err(|e| IndexError::NonceError(e.to_string()))?;

        self.nonce = new_nonce;
        Ok(())
    }

    /// Returns the current data nonce counter and increments it for the next use.
    pub fn next_data_nonce_counter(&mut self) -> Result<u64, IndexError> {
        let counter = self.data_nonce_counter;
        self.data_nonce_counter =
            self.data_nonce_counter
                .checked_add(1)
                .ok_or(IndexError::GenericError(
                    "Data nonce counter overflow".to_string(),
                ))?;
        Ok(counter)
    }

    fn hmac_filename(&self, plaintext_name: &str) -> Result<String, IndexError> {
        let hmac_vault = self.hmac_key.as_ref().ok_or(IndexError::GenericError(
            "HMAC key not available".to_string(),
        ))?;

        let mut hex_result: Result<String, IndexError> =
            Err(IndexError::GenericError("HMAC not computed".to_string()));
        hmac_vault
            .access(|key_chunk, _tag| {
                let hmac_key = HmacSecretKey::from_slice(key_chunk)
                    .map_err(|_| crate::mem::secure_memory_vault::MemoryVaultError::Crypto)?;
                let tag = HmacSha256::hmac(&hmac_key, plaintext_name.as_bytes())
                    .map_err(|_| crate::mem::secure_memory_vault::MemoryVaultError::Crypto)?;

                let tag_bytes = tag.unprotected_as_bytes();
                let mut hex = String::with_capacity(tag_bytes.len() * 2);
                for b in tag_bytes {
                    write!(hex, "{:02x}", b).unwrap();
                }
                hex_result = Ok(hex);
                Ok(())
            })
            .map_err(|e| IndexError::GenericError(e.to_string()))?;

        hex_result
    }

    /// Returns the HMAC'd key for a given plaintext name (for use as AAD).
    pub fn lookup_hmac_key_for_name(&self, plaintext_name: &str) -> Result<String, IndexError> {
        self.hmac_filename(plaintext_name)
    }

    /// Inserts an entry, hashing the plaintext name with HMAC-SHA256.
    /// If an entry with the same name already exists it is dropped, which
    /// zeroizes its encrypted fields.
    pub fn insert_file(
        &mut self,
        plaintext_name: &str,
        metadata: IndexMetaBlockMetadata,
    ) -> Result<(), IndexError> {
        let hashed_key = self.hmac_filename(plaintext_name)?;
        // The cap applies to the map size; overwriting an existing entry does
        // not grow the map and stays allowed at the cap.
        if self.files.len() >= MAX_INDEX_ENTRIES && !self.files.contains_key(&hashed_key) {
            return Err(IndexError::GenericError(format!(
                "Maximum index entries ({}) reached",
                MAX_INDEX_ENTRIES
            )));
        }
        self.files.insert(hashed_key, metadata);
        Ok(())
    }

    /// Looks up an entry by plaintext name (HMAC'd internally).
    pub fn lookup_file(
        &self,
        plaintext_name: &str,
    ) -> Result<Option<&IndexMetaBlockMetadata>, IndexError> {
        let hashed_key = self.hmac_filename(plaintext_name)?;
        Ok(self.files.get(&hashed_key))
    }

    /// Removes an entry by plaintext name. Returns the metadata if it existed.
    pub fn remove_file(
        &mut self,
        plaintext_name: &str,
    ) -> Result<Option<IndexMetaBlockMetadata>, IndexError> {
        let hashed_key = self.hmac_filename(plaintext_name)?;
        Ok(self.files.remove(&hashed_key))
    }
}

impl<N> Drop for VaultIndex<N> {
    fn drop(&mut self) {
        // Entry values zeroize themselves on drop. Wipe the HMAC-derived map
        // keys, the index nonce, and the salt copy as well so no index
        // metadata lingers in freed memory. The subkey vaults have their own
        // Drop.
        for (mut key, _meta) in self.files.drain() {
            key.zeroize();
        }
        self.nonce.zeroize();
        self.kdf_salt.zeroize();
    }
}

impl VaultIndex<NonceNotRotated> {
    /// Constructs an index from pre-existing data (used when opening a vault).
    #[allow(clippy::too_many_arguments)]
    pub fn from_data(
        version: u16,
        nonce: [u8; XCHACHA20_NONCE_LEN],
        nonce_counter: u64,
        data_nonce_counter: u64,
        enc_key: Option<SecureMemoryVault>,
        hmac_key: Option<SecureMemoryVault>,
        kdf_salt: Vec<u8>,
        files: HashMap<String, IndexMetaBlockMetadata>,
    ) -> Result<Self, IndexError> {
        if !SUPPORTED_VAULT_INDEX_VERSIONS.contains(&version) {
            return Err(IndexError::UnsupportedVersion);
        }
        Ok(VaultIndex::<NonceNotRotated> {
            version,
            nonce,
            nonce_counter,
            data_nonce_counter,
            files,
            enc_key,
            hmac_key,
            kdf_salt,
            _state: Default::default(),
        })
    }

    /// Creates a new empty index from an externally-derived master key and salt.
    pub fn from_master_key(master_key: &[u8], salt: &[u8]) -> Result<Self, IndexError> {
        let (mut enc_sub, mut hmac_sub) = derive_subkeys(master_key, salt)?;

        let initial_counter: u64 = 0;
        let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut nonce).map_err(|e| IndexError::NonceError(e.to_string()))?;

        let enc_vault = SecureMemoryVault::new(&enc_sub)
            .map_err(|e| IndexError::GenericError(e.to_string()))?;
        let hmac_vault = SecureMemoryVault::new(&hmac_sub)
            .map_err(|e| IndexError::GenericError(e.to_string()))?;

        enc_sub.zeroize();
        hmac_sub.zeroize();

        VaultIndex::from_data(
            VAULT_INDEX_VERSION,
            nonce,
            initial_counter,
            0,
            Some(enc_vault),
            Some(hmac_vault),
            salt.to_vec(),
            HashMap::new(),
        )
    }

    /// Reconstructs an index from a master key and deserialized fields.
    pub fn from_master_key_and_data(
        master_key: &[u8],
        salt: &[u8],
        nonce: [u8; XCHACHA20_NONCE_LEN],
        nonce_counter: u64,
        data_nonce_counter: u64,
        files: HashMap<String, IndexMetaBlockMetadata>,
    ) -> Result<Self, IndexError> {
        let (mut enc_sub, mut hmac_sub) = derive_subkeys(master_key, salt)?;
        let result = Self::from_subkeys_and_data(
            &enc_sub,
            &hmac_sub,
            salt,
            nonce,
            nonce_counter,
            data_nonce_counter,
            files,
        );
        enc_sub.zeroize();
        hmac_sub.zeroize();
        result
    }

    /// Reconstructs an index from already-derived subkeys and deserialized
    /// fields. `Vault::open` uses this so that HKDF runs exactly once per
    /// open; the caller owns and zeroizes `enc_sub` and `hmac_sub`.
    pub fn from_subkeys_and_data(
        enc_sub: &[u8; SUBKEY_LEN],
        hmac_sub: &[u8; SUBKEY_LEN],
        salt: &[u8],
        nonce: [u8; XCHACHA20_NONCE_LEN],
        nonce_counter: u64,
        data_nonce_counter: u64,
        files: HashMap<String, IndexMetaBlockMetadata>,
    ) -> Result<Self, IndexError> {
        // Entry nonces are random and stored with each ciphertext (DESIGN.md
        // section 5), so this check is not about nonce uniqueness. The
        // counter still feeds the per-entry AAD (hmac_key_hex || data_counter):
        // a vault written by this library always advances data_nonce_counter
        // past every stored entry, so on reopen it must be strictly greater
        // than the largest stored data_counter. A violation means the
        // (authenticated) index is inconsistent; reject it rather than let a
        // later store() reissue a (name, counter) AAD pair under which an
        // older ciphertext for that name could be replayed.
        if let Some(max_counter) = files.values().map(|m| m.data_counter).max()
            && data_nonce_counter <= max_counter
        {
            return Err(IndexError::GenericError(format!(
                "data_nonce_counter ({}) must exceed the largest stored data_counter ({})",
                data_nonce_counter, max_counter
            )));
        }

        let enc_vault =
            SecureMemoryVault::new(enc_sub).map_err(|e| IndexError::GenericError(e.to_string()))?;
        let hmac_vault = SecureMemoryVault::new(hmac_sub)
            .map_err(|e| IndexError::GenericError(e.to_string()))?;

        VaultIndex::from_data(
            VAULT_INDEX_VERSION,
            nonce,
            nonce_counter,
            data_nonce_counter,
            Some(enc_vault),
            Some(hmac_vault),
            salt.to_vec(),
            files,
        )
    }

    /// Generates a new index with a random master key (for standalone use without a password).
    pub fn generate() -> Result<Self, IndexError> {
        let master_vault = SecureMemoryVault::safe_new(|| {
            let mut key = [0u8; 32];
            secure_bytes_fill(&mut key)?;
            Ok(key)
        })
        .map_err(|e| IndexError::GenericError(e.to_string()))?;

        let mut enc_sub = [0u8; SUBKEY_LEN];
        let mut hmac_sub = [0u8; SUBKEY_LEN];
        let initial_counter: u64 = 0;

        master_vault
            .access(|master_chunk, _tag| {
                let (e, h) = derive_subkeys(master_chunk, &[]).map_err(|e| {
                    crate::mem::secure_memory_vault::MemoryVaultError::GenericError(e.to_string())
                })?;
                enc_sub = e;
                hmac_sub = h;
                Ok(())
            })
            .map_err(|e| IndexError::GenericError(e.to_string()))?;

        let mut initial_nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut initial_nonce).map_err(|e| IndexError::NonceError(e.to_string()))?;

        let enc_vault = SecureMemoryVault::new(&enc_sub)
            .map_err(|e| IndexError::GenericError(e.to_string()))?;
        let hmac_vault = SecureMemoryVault::new(&hmac_sub)
            .map_err(|e| IndexError::GenericError(e.to_string()))?;

        enc_sub.zeroize();
        hmac_sub.zeroize();

        VaultIndex::from_data(
            VAULT_INDEX_VERSION,
            initial_nonce,
            initial_counter,
            0,
            Some(enc_vault),
            Some(hmac_vault),
            Vec::new(),
            HashMap::new(),
        )
    }
}

impl IndexMetaBlockMetadata {
    /// Creates entry metadata with explicit fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        location: IndexMetaBlockLocation,
        created: u64,
        modified: u64,
        is_dummy: bool,
        encrypted_data: Option<Vec<u8>>,
        encrypted_name: Option<Vec<u8>>,
        data_counter: u64,
    ) -> Self {
        IndexMetaBlockMetadata {
            location,
            created,
            modified,
            is_dummy,
            encrypted_data,
            encrypted_name,
            data_counter,
        }
    }

    /// Creates a dummy entry for padding (no real data, timestamps zeroed).
    pub fn generate_dummy(offset: usize) -> Result<Self, IndexError> {
        if offset >= MAX_INDEX_ENTRIES {
            return Err(IndexError::OffsetOutOfBounds);
        }
        Ok(IndexMetaBlockMetadata {
            location: IndexMetaBlockLocation::SmallFileInPack {
                metablock_uid: String::new(),
                offset,
            },
            created: 0,
            modified: 0,
            is_dummy: true,
            encrypted_data: None,
            encrypted_name: None,
            data_counter: 0,
        })
    }
}

impl NonceRotation for VaultIndex<NonceNotRotated> {
    type Output = VaultIndex<NonceRotated>;
    fn rotate_nonce(mut self) -> Result<Self::Output, NonceRotationError> {
        let new_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or(NonceRotationError::CounterOverflow)?;

        let mut new_nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut new_nonce).map_err(|_| NonceRotationError::NonceRotationFailed)?;

        // `VaultIndex` implements Drop, so the fields are moved out with
        // `take` and the emptied source is dropped normally afterwards.
        Ok(VaultIndex {
            version: self.version,
            nonce: new_nonce,
            nonce_counter: new_counter,
            data_nonce_counter: self.data_nonce_counter,
            files: std::mem::take(&mut self.files),
            enc_key: self.enc_key.take(),
            hmac_key: self.hmac_key.take(),
            kdf_salt: std::mem::take(&mut self.kdf_salt),
            _state: PhantomData,
        })
    }
}

impl SecureConstructor for VaultIndex<NonceNotRotated> {
    fn secure_new<F>(f: F) -> Result<Self, EncryptionError>
    where
        F: FnOnce() -> Result<SecretBox<Vec<u8>>, &'static str>,
    {
        let secure_data = f().map_err(|e| EncryptionError::GenericError(e.to_string()))?;
        let master_bytes = secure_data.expose_secret();

        let (mut enc_sub, mut hmac_sub) = derive_subkeys(master_bytes, &[])
            .map_err(|e| EncryptionError::GenericError(e.to_string()))?;

        let initial_counter: u64 = 0;
        let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut nonce).map_err(|e| EncryptionError::GenericError(e.to_string()))?;

        let enc_vault = SecureMemoryVault::new(&enc_sub)
            .map_err(|e| EncryptionError::GenericError(e.to_string()))?;
        let hmac_vault = SecureMemoryVault::new(&hmac_sub)
            .map_err(|e| EncryptionError::GenericError(e.to_string()))?;

        enc_sub.zeroize();
        hmac_sub.zeroize();

        VaultIndex::from_data(
            VAULT_INDEX_VERSION,
            nonce,
            initial_counter,
            0,
            Some(enc_vault),
            Some(hmac_vault),
            Vec::new(),
            HashMap::new(),
        )
        .map_err(|e| EncryptionError::GenericError(e.to_string()))
    }
}

impl SecureAccess for VaultIndex<NonceRotated> {
    fn secure_access<F>(&self, f: F) -> Result<(), EncryptionError>
    where
        F: FnOnce(&SecretBox<Vec<u8>>) -> Result<(), &'static str>,
    {
        let enc_vault = self
            .enc_key
            .as_ref()
            .ok_or(EncryptionError::SecretKeyGenerationFailed)?;

        // Sized up front so extend_from_slice never reallocates and leaves
        // an unwiped copy of the key behind in the old allocation.
        let mut collected = zeroize::Zeroizing::new(Vec::with_capacity(enc_vault.len()));
        enc_vault
            .access(|key_bytes, _tag| {
                collected.extend_from_slice(key_bytes);
                Ok(())
            })
            .map_err(|e| EncryptionError::GenericError(e.to_string()))?;

        let inner = std::mem::take(&mut *collected);
        let secret_box = SecretBox::new(Box::new(inner));
        f(&secret_box).map_err(|e| EncryptionError::GenericError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::nonce_rotation::NonceRotation;

    #[test]
    fn generate_creates_index_with_counter_zero() {
        let idx = VaultIndex::generate().unwrap();
        assert_eq!(idx.nonce_counter, 0);
        assert_eq!(idx.data_nonce_counter, 0);
        assert_eq!(idx.version, VAULT_INDEX_VERSION);
        assert!(idx.enc_key.is_some());
        assert!(idx.hmac_key.is_some());
    }

    #[test]
    fn from_master_key_uses_random_initial_nonce() {
        // Nonces are drawn from the OS CSPRNG, so two indexes built from the
        // same master key and salt must not share an initial nonce.
        let master = [0x42u8; 32];
        let salt = [0xAA; 16];
        let idx1 = VaultIndex::from_master_key(&master, &salt).unwrap();
        let idx2 = VaultIndex::from_master_key(&master, &salt).unwrap();
        assert_ne!(idx1.nonce, idx2.nonce);
    }

    #[test]
    fn rotate_nonce_increments_counter() {
        let idx = VaultIndex::generate().unwrap();
        let original_nonce = idx.nonce;
        let rotated = idx.rotate_nonce().unwrap();
        assert_eq!(rotated.nonce_counter, 1);
        assert_ne!(rotated.nonce, original_nonce);
    }

    #[test]
    fn enc_and_hmac_keys_are_different() {
        let idx = VaultIndex::generate().unwrap();
        let mut enc_bytes = Vec::new();
        idx.enc_key
            .as_ref()
            .unwrap()
            .access(|chunk, _| {
                enc_bytes.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        let mut hmac_bytes = Vec::new();
        idx.hmac_key
            .as_ref()
            .unwrap()
            .access(|chunk, _| {
                hmac_bytes.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_ne!(enc_bytes, hmac_bytes);
        assert_eq!(enc_bytes.len(), SUBKEY_LEN);
        assert_eq!(hmac_bytes.len(), SUBKEY_LEN);
    }

    #[test]
    fn insert_and_lookup_file_roundtrip() {
        let mut idx = VaultIndex::generate().unwrap();
        let meta = IndexMetaBlockMetadata::new(
            IndexMetaBlockLocation::Inline,
            1000,
            2000,
            false,
            Some(b"encrypted".to_vec()),
            None,
            0,
        );
        idx.insert_file("secret.txt", meta.clone()).unwrap();
        let found = idx.lookup_file("secret.txt").unwrap();
        assert_eq!(found, Some(&meta));
    }

    #[test]
    fn lookup_missing_file_returns_none() {
        let idx = VaultIndex::generate().unwrap();
        assert_eq!(idx.lookup_file("nonexistent.txt").unwrap(), None);
    }

    #[test]
    fn hashmap_keys_are_not_plaintext() {
        let mut idx = VaultIndex::generate().unwrap();
        let meta = IndexMetaBlockMetadata::new(
            IndexMetaBlockLocation::Inline,
            1000,
            2000,
            false,
            None,
            None,
            0,
        );
        idx.insert_file("secret.txt", meta).unwrap();
        for key in idx.files.keys() {
            assert_ne!(key, "secret.txt");
        }
    }

    #[test]
    fn hmac_is_deterministic() {
        let idx = VaultIndex::generate().unwrap();
        let h1 = idx.hmac_filename("test.txt").unwrap();
        let h2 = idx.hmac_filename("test.txt").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_filenames_produce_different_keys() {
        let idx = VaultIndex::generate().unwrap();
        let h1 = idx.hmac_filename("file_a.txt").unwrap();
        let h2 = idx.hmac_filename("file_b.txt").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn remove_file_works() {
        let mut idx = VaultIndex::generate().unwrap();
        let meta = IndexMetaBlockMetadata::new(
            IndexMetaBlockLocation::Inline,
            1000,
            2000,
            false,
            None,
            None,
            0,
        );
        idx.insert_file("to_remove.txt", meta.clone()).unwrap();
        let removed = idx.remove_file("to_remove.txt").unwrap();
        assert_eq!(removed, Some(meta));
        assert_eq!(idx.lookup_file("to_remove.txt").unwrap(), None);
    }

    #[test]
    fn from_data_rejects_unsupported_version() {
        let result = VaultIndex::from_data(
            999,
            [0u8; XCHACHA20_NONCE_LEN],
            0,
            0,
            None,
            None,
            Vec::new(),
            HashMap::new(),
        );
        assert!(matches!(result, Err(IndexError::UnsupportedVersion)));
    }

    #[test]
    fn subkeys_are_deterministic_for_same_master() {
        let master = [0xABu8; 32];
        let (enc1, hmac1) = derive_subkeys(&master, &[]).unwrap();
        let (enc2, hmac2) = derive_subkeys(&master, &[]).unwrap();
        assert_eq!(enc1, enc2);
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn subkeys_differ_for_different_masters() {
        let (enc1, hmac1) = derive_subkeys(&[0x01u8; 32], &[]).unwrap();
        let (enc2, hmac2) = derive_subkeys(&[0x02u8; 32], &[]).unwrap();
        assert_ne!(enc1, enc2);
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn advance_nonce_produces_unique_nonces() {
        let mut idx = VaultIndex::generate().unwrap();
        idx.advance_nonce().unwrap();
        let first = idx.nonce;
        idx.advance_nonce().unwrap();
        assert_ne!(idx.nonce, first);
        assert_eq!(idx.nonce_counter, 2);
    }

    #[test]
    fn insert_file_at_cap_allows_overwrite_but_rejects_new_entry() {
        let mut idx = VaultIndex::generate().unwrap();
        for i in 0..MAX_INDEX_ENTRIES {
            idx.insert_file(&format!("entry-{}", i), meta_with_counter(0))
                .unwrap();
        }
        assert_eq!(idx.files.len(), MAX_INDEX_ENTRIES);

        // Overwriting an existing name does not grow the map: must succeed.
        idx.insert_file("entry-0", meta_with_counter(1)).unwrap();
        assert_eq!(idx.files.len(), MAX_INDEX_ENTRIES);

        // A new name would exceed the cap: must fail.
        assert!(
            idx.insert_file("one-too-many", meta_with_counter(2))
                .is_err()
        );
    }

    #[test]
    fn advance_nonce_overflow() {
        let mut idx = VaultIndex::generate().unwrap();
        idx.nonce_counter = u64::MAX;
        assert!(idx.advance_nonce().is_err());
    }

    #[test]
    fn data_nonce_counter_overflow() {
        let mut idx = VaultIndex::generate().unwrap();
        idx.data_nonce_counter = u64::MAX;
        assert!(idx.next_data_nonce_counter().is_err());
    }

    fn meta_with_counter(counter: u64) -> IndexMetaBlockMetadata {
        IndexMetaBlockMetadata::new(
            IndexMetaBlockLocation::Inline,
            0,
            0,
            false,
            None,
            None,
            counter,
        )
    }

    #[test]
    fn metadata_zeroize_clears_ciphertext_fields() {
        let mut meta = IndexMetaBlockMetadata::new(
            IndexMetaBlockLocation::Inline,
            1,
            2,
            false,
            Some(vec![9u8; 8]),
            Some(vec![7u8; 8]),
            3,
        );
        meta.zeroize();
        assert_eq!(meta.encrypted_data, None);
        assert_eq!(meta.encrypted_name, None);
        assert_eq!(meta.data_counter, 0);
    }

    #[test]
    fn from_master_key_and_data_rejects_counter_not_ahead_of_entries() {
        // data_nonce_counter must be strictly greater than the largest stored
        // data_counter, otherwise a later store() could reissue an AAD
        // counter that is already bound to a stored ciphertext.
        let master = [0x11u8; 32];
        let salt = [0x22u8; 16];
        let mut files = HashMap::new();
        files.insert("a".to_string(), meta_with_counter(5));

        // Equal to the max stored counter: must be rejected.
        let result = VaultIndex::from_master_key_and_data(
            &master,
            &salt,
            [0u8; XCHACHA20_NONCE_LEN],
            0,
            5,
            files.clone(),
        );
        assert!(result.is_err());

        // Below the max stored counter: must be rejected.
        let result = VaultIndex::from_master_key_and_data(
            &master,
            &salt,
            [0u8; XCHACHA20_NONCE_LEN],
            0,
            3,
            files,
        );
        assert!(result.is_err());
    }

    #[test]
    fn from_master_key_and_data_accepts_counter_ahead_of_entries() {
        let master = [0x11u8; 32];
        let salt = [0x22u8; 16];
        let mut files = HashMap::new();
        files.insert("a".to_string(), meta_with_counter(5));

        let result = VaultIndex::from_master_key_and_data(
            &master,
            &salt,
            [0u8; XCHACHA20_NONCE_LEN],
            0,
            6,
            files,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn from_master_key_and_data_accepts_empty_files_with_zero_counter() {
        let master = [0x11u8; 32];
        let salt = [0x22u8; 16];
        let result = VaultIndex::from_master_key_and_data(
            &master,
            &salt,
            [0u8; XCHACHA20_NONCE_LEN],
            0,
            0,
            HashMap::new(),
        );
        assert!(result.is_ok());
    }
}
