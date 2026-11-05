use crate::constants::subkeys::{ENCRYPTION_SUBKEY_INFO, HMAC_SUBKEY_INFO, SUBKEY_LEN};
use crate::constants::vault_index_constants::MAX_INDEX_ENTRIES;
use crate::constants::xchacha20_poly1305::XCHACHA20_NONCE_LEN;
use crate::crypto::utils::{RandomError, secure_bytes_fill};
use crate::mem::locked_secret::{LockedSecret, LockedSecretError};
use crate::vault::index_codec::key_to_hex;
use orion::hazardous::kdf::hkdf;
use orion::hazardous::mac::hmac::sha256::{HmacSha256, SecretKey as HmacSecretKey};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Errors that can occur in vault index operations.
#[derive(Debug, Error)]
pub enum IndexError {
    /// The (authenticated) index violates one of its own invariants.
    #[error("Index inconsistent: {0}")]
    Inconsistent(String),
    /// The index already holds the maximum number of entries.
    #[error("Maximum index entries ({0}) reached")]
    Full(usize),
    /// A monotonic counter reached `u64::MAX`.
    #[error("Counter overflow: {0}")]
    CounterOverflow(&'static str),
    /// The OS random number generator failed.
    #[error("Random generation failed: {0}")]
    Random(#[from] RandomError),
    /// Locked memory for a subkey could not be set up.
    #[error("Locked memory error: {0}")]
    LockedMemory(#[from] LockedSecretError),
    /// HKDF or HMAC failed.
    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// One stored secret: both ciphertexts carry their 24-byte nonce prefix and
/// are bound to `data_counter` through the entry AAD (DESIGN.md section 8).
///
/// Zeroized on drop, so ciphertexts that are replaced, removed, or released
/// with the vault do not linger in freed memory.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct IndexEntry {
    pub data_counter: u64,
    pub encrypted_name: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

/// In-memory index mapping HMAC'd entry names to their ciphertexts.
///
/// Entries are keyed by `hmac_key_for_name(plaintext_name)`; callers compute
/// that key once and use it both for the map and for the entry AAD. The
/// `Vault` facade advances the index nonce via `advance_nonce()` before each
/// export.
#[derive(Debug)]
pub struct VaultIndex {
    pub nonce: [u8; XCHACHA20_NONCE_LEN],
    pub nonce_counter: u64,
    pub data_nonce_counter: u64,
    pub files: HashMap<String, IndexEntry>,
    enc_key: LockedSecret,
    hmac_key: LockedSecret,
}

/// Derives separate encryption and HMAC subkeys from a master key via
/// HKDF-SHA256, writing them into buffers the caller owns. Taking output
/// buffers instead of returning arrays keeps the subkeys from being copied
/// through unwiped stack slots: the caller passes `Zeroizing` buffers and
/// no other copy of the subkeys ever exists.
pub fn derive_subkeys(
    master_key: &[u8],
    salt: &[u8],
    enc_out: &mut [u8; SUBKEY_LEN],
    hmac_out: &mut [u8; SUBKEY_LEN],
) -> Result<(), IndexError> {
    hkdf::sha256::derive_key(salt, master_key, Some(ENCRYPTION_SUBKEY_INFO), enc_out)
        .map_err(|e| IndexError::Crypto(format!("HKDF enc subkey failed: {}", e)))?;
    hkdf::sha256::derive_key(salt, master_key, Some(HMAC_SUBKEY_INFO), hmac_out)
        .map_err(|e| IndexError::Crypto(format!("HKDF hmac subkey failed: {}", e)))?;
    Ok(())
}

impl VaultIndex {
    /// Returns the encryption subkey container.
    pub fn enc_key(&self) -> &LockedSecret {
        &self.enc_key
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
            .ok_or(IndexError::CounterOverflow("nonce counter"))?;

        let mut new_nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut new_nonce)?;

        self.nonce = new_nonce;
        Ok(())
    }

    /// Returns the current data nonce counter and increments it for the next use.
    pub fn next_data_nonce_counter(&mut self) -> Result<u64, IndexError> {
        let counter = self.data_nonce_counter;
        self.data_nonce_counter = self
            .data_nonce_counter
            .checked_add(1)
            .ok_or(IndexError::CounterOverflow("data nonce counter"))?;
        Ok(counter)
    }

    /// Returns the map key for a plaintext entry name: HMAC-SHA256 of the
    /// name under the HMAC subkey, hex encoded. The same string is bound into
    /// the entry AAD. The key is pseudonymous rather than secret, but it is
    /// still wiped on drop so that freed memory does not accumulate a record
    /// of which names were looked up.
    pub fn hmac_key_for_name(&self, plaintext_name: &str) -> Result<Zeroizing<String>, IndexError> {
        let tag = self.hmac_key.with_bytes(|key_bytes| {
            let hmac_key = HmacSecretKey::from_slice(key_bytes)
                .map_err(|_| IndexError::Crypto("HMAC key invalid".to_string()))?;
            HmacSha256::hmac(&hmac_key, plaintext_name.as_bytes())
                .map_err(|_| IndexError::Crypto("HMAC failed".to_string()))
        })?;
        Ok(Zeroizing::new(key_to_hex(tag.unprotected_as_bytes())))
    }

    /// Inserts an entry under an already computed `hmac_key_for_name` key.
    /// If an entry with the same key already exists it is dropped, which
    /// zeroizes its encrypted fields.
    pub fn insert_by_key(
        &mut self,
        mut hashed_key: Zeroizing<String>,
        entry: IndexEntry,
    ) -> Result<(), IndexError> {
        // Overwrite in place so the map keeps its existing key and the
        // duplicate stays inside `hashed_key`, which wipes it on drop. This
        // also keeps overwrites allowed at the cap: the map does not grow.
        if let Some(slot) = self.files.get_mut(hashed_key.as_str()) {
            *slot = entry;
            return Ok(());
        }
        if self.files.len() >= MAX_INDEX_ENTRIES {
            return Err(IndexError::Full(MAX_INDEX_ENTRIES));
        }
        // Move the String out of its wrapper (no copy of the heap buffer);
        // the map now owns it and `VaultIndex::drop` wipes it.
        self.files.insert(std::mem::take(&mut *hashed_key), entry);
        Ok(())
    }

    /// Looks up an entry by its `hmac_key_for_name` key.
    pub fn lookup_by_key(&self, hashed_key: &str) -> Option<&IndexEntry> {
        self.files.get(hashed_key)
    }

    /// Removes an entry by its `hmac_key_for_name` key, wiping the stored
    /// key. Returns the entry if it existed.
    pub fn remove_by_key(&mut self, hashed_key: &str) -> Option<IndexEntry> {
        let (mut key, entry) = self.files.remove_entry(hashed_key)?;
        key.zeroize();
        Some(entry)
    }

    /// Creates a new empty index from an externally-derived master key and salt.
    pub fn from_master_key(master_key: &[u8], salt: &[u8]) -> Result<Self, IndexError> {
        let mut enc_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        let mut hmac_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        derive_subkeys(master_key, salt, &mut enc_sub, &mut hmac_sub)?;

        let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut nonce)?;

        Ok(VaultIndex {
            nonce,
            nonce_counter: 0,
            data_nonce_counter: 0,
            files: HashMap::new(),
            enc_key: LockedSecret::new(enc_sub.as_slice())?,
            hmac_key: LockedSecret::new(hmac_sub.as_slice())?,
        })
    }

    /// Reconstructs an index from already-derived subkeys and decoded
    /// fields. `Vault::open` uses this so that HKDF runs exactly once per
    /// open; the caller owns and zeroizes `enc_sub` and `hmac_sub`.
    pub fn from_subkeys_and_data(
        enc_sub: &[u8; SUBKEY_LEN],
        hmac_sub: &[u8; SUBKEY_LEN],
        nonce: [u8; XCHACHA20_NONCE_LEN],
        nonce_counter: u64,
        data_nonce_counter: u64,
        files: HashMap<String, IndexEntry>,
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
            return Err(IndexError::Inconsistent(format!(
                "data_nonce_counter ({}) must exceed the largest stored data_counter ({})",
                data_nonce_counter, max_counter
            )));
        }

        Ok(VaultIndex {
            nonce,
            nonce_counter,
            data_nonce_counter,
            files,
            enc_key: LockedSecret::new(enc_sub)?,
            hmac_key: LockedSecret::new(hmac_sub)?,
        })
    }
}

impl Drop for VaultIndex {
    fn drop(&mut self) {
        // Entry values zeroize themselves on drop. Wipe the HMAC-derived map
        // keys and the index nonce as well so no index metadata lingers in
        // freed memory. The subkey containers have their own Drop.
        for (mut key, _entry) in self.files.drain() {
            key.zeroize();
        }
        self.nonce.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl VaultIndex {
        /// Test helper: an empty index keyed by a random master key.
        pub(crate) fn generate() -> Result<Self, IndexError> {
            let mut master = Zeroizing::new([0u8; 32]);
            secure_bytes_fill(master.as_mut_slice())?;
            VaultIndex::from_master_key(master.as_slice(), &[])
        }

        /// Test helper: insert under a plaintext name.
        fn insert_named(&mut self, name: &str, entry: IndexEntry) -> Result<(), IndexError> {
            let key = self.hmac_key_for_name(name)?;
            self.insert_by_key(key, entry)
        }

        /// Test helper: look up by plaintext name.
        fn lookup_named(&self, name: &str) -> Option<&IndexEntry> {
            self.lookup_by_key(&self.hmac_key_for_name(name).unwrap())
        }
    }

    fn index_from_master(
        master: &[u8],
        salt: &[u8],
        data_nonce_counter: u64,
        files: HashMap<String, IndexEntry>,
    ) -> Result<VaultIndex, IndexError> {
        let mut enc_sub = [0u8; SUBKEY_LEN];
        let mut hmac_sub = [0u8; SUBKEY_LEN];
        derive_subkeys(master, salt, &mut enc_sub, &mut hmac_sub).unwrap();
        VaultIndex::from_subkeys_and_data(
            &enc_sub,
            &hmac_sub,
            [0u8; XCHACHA20_NONCE_LEN],
            0,
            data_nonce_counter,
            files,
        )
    }

    pub(crate) fn entry_with_counter(counter: u64) -> IndexEntry {
        IndexEntry {
            data_counter: counter,
            encrypted_name: vec![1u8; 40],
            encrypted_data: vec![2u8; 40],
        }
    }

    #[test]
    fn from_master_key_starts_with_counters_at_zero() {
        let idx = VaultIndex::generate().unwrap();
        assert_eq!(idx.nonce_counter, 0);
        assert_eq!(idx.data_nonce_counter, 0);
        assert!(idx.files.is_empty());
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
    fn enc_and_hmac_keys_are_different() {
        let idx = VaultIndex::generate().unwrap();
        let enc_bytes = idx.enc_key.with_bytes(|b| b.to_vec());
        let hmac_bytes = idx.hmac_key.with_bytes(|b| b.to_vec());
        assert_ne!(enc_bytes, hmac_bytes);
        assert_eq!(enc_bytes.len(), SUBKEY_LEN);
        assert_eq!(hmac_bytes.len(), SUBKEY_LEN);
    }

    #[test]
    fn insert_and_lookup_roundtrip() {
        let mut idx = VaultIndex::generate().unwrap();
        let entry = entry_with_counter(0);
        idx.insert_named("secret.txt", entry.clone()).unwrap();
        assert_eq!(idx.lookup_named("secret.txt"), Some(&entry));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let idx = VaultIndex::generate().unwrap();
        assert_eq!(idx.lookup_named("nonexistent.txt"), None);
    }

    #[test]
    fn map_keys_are_hex_hmacs_not_plaintext() {
        let mut idx = VaultIndex::generate().unwrap();
        idx.insert_named("secret.txt", entry_with_counter(0))
            .unwrap();
        for key in idx.files.keys() {
            assert_ne!(key, "secret.txt");
            assert_eq!(key.len(), 64);
            assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn hmac_is_deterministic() {
        let idx = VaultIndex::generate().unwrap();
        let h1 = idx.hmac_key_for_name("test.txt").unwrap();
        let h2 = idx.hmac_key_for_name("test.txt").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_names_produce_different_keys() {
        let idx = VaultIndex::generate().unwrap();
        let h1 = idx.hmac_key_for_name("file_a.txt").unwrap();
        let h2 = idx.hmac_key_for_name("file_b.txt").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn remove_by_key_works() {
        let mut idx = VaultIndex::generate().unwrap();
        let entry = entry_with_counter(0);
        idx.insert_named("to_remove.txt", entry.clone()).unwrap();
        let key = idx.hmac_key_for_name("to_remove.txt").unwrap();
        assert_eq!(idx.remove_by_key(&key), Some(entry));
        assert_eq!(idx.lookup_named("to_remove.txt"), None);
        assert_eq!(idx.remove_by_key(&key), None);
    }

    fn subkeys(master: &[u8]) -> ([u8; SUBKEY_LEN], [u8; SUBKEY_LEN]) {
        let mut enc = [0u8; SUBKEY_LEN];
        let mut hmac = [0u8; SUBKEY_LEN];
        derive_subkeys(master, &[], &mut enc, &mut hmac).unwrap();
        (enc, hmac)
    }

    #[test]
    fn subkeys_are_deterministic_for_same_master() {
        let master = [0xABu8; 32];
        let (enc1, hmac1) = subkeys(&master);
        let (enc2, hmac2) = subkeys(&master);
        assert_eq!(enc1, enc2);
        assert_eq!(hmac1, hmac2);
        assert_ne!(enc1, hmac1);
    }

    #[test]
    fn subkeys_differ_for_different_masters() {
        let (enc1, hmac1) = subkeys(&[0x01u8; 32]);
        let (enc2, hmac2) = subkeys(&[0x02u8; 32]);
        assert_ne!(enc1, enc2);
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn overwrite_keeps_one_entry_and_is_allowed_at_the_cap() {
        let mut idx = VaultIndex::generate().unwrap();
        for i in 0..MAX_INDEX_ENTRIES {
            idx.insert_named(&format!("entry-{i}"), entry_with_counter(i as u64))
                .unwrap();
        }
        assert_eq!(idx.files.len(), MAX_INDEX_ENTRIES);
        idx.insert_named("entry-0", entry_with_counter(9999))
            .unwrap();
        assert_eq!(idx.files.len(), MAX_INDEX_ENTRIES);
        assert_eq!(idx.lookup_named("entry-0").unwrap().data_counter, 9999);
        assert!(matches!(
            idx.insert_named("one-too-many", entry_with_counter(1)),
            Err(IndexError::Full(MAX_INDEX_ENTRIES))
        ));
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
    fn insert_at_cap_allows_overwrite_but_rejects_new_entry() {
        let mut idx = VaultIndex::generate().unwrap();
        for i in 0..MAX_INDEX_ENTRIES {
            idx.insert_named(&format!("entry-{}", i), entry_with_counter(0))
                .unwrap();
        }
        assert_eq!(idx.files.len(), MAX_INDEX_ENTRIES);

        // Overwriting an existing name does not grow the map: must succeed.
        idx.insert_named("entry-0", entry_with_counter(1)).unwrap();
        assert_eq!(idx.files.len(), MAX_INDEX_ENTRIES);

        // A new name would exceed the cap: must fail.
        assert!(matches!(
            idx.insert_named("one-too-many", entry_with_counter(2)),
            Err(IndexError::Full(MAX_INDEX_ENTRIES))
        ));
    }

    #[test]
    fn advance_nonce_overflow() {
        let mut idx = VaultIndex::generate().unwrap();
        idx.nonce_counter = u64::MAX;
        assert!(matches!(
            idx.advance_nonce(),
            Err(IndexError::CounterOverflow(_))
        ));
    }

    #[test]
    fn data_nonce_counter_overflow() {
        let mut idx = VaultIndex::generate().unwrap();
        idx.data_nonce_counter = u64::MAX;
        assert!(matches!(
            idx.next_data_nonce_counter(),
            Err(IndexError::CounterOverflow(_))
        ));
    }

    #[test]
    fn entry_zeroize_clears_ciphertext_fields() {
        let mut entry = entry_with_counter(3);
        entry.zeroize();
        assert!(entry.encrypted_data.is_empty());
        assert!(entry.encrypted_name.is_empty());
        assert_eq!(entry.data_counter, 0);
    }

    #[test]
    fn from_subkeys_and_data_rejects_counter_not_ahead_of_entries() {
        // data_nonce_counter must be strictly greater than the largest stored
        // data_counter, otherwise a later store() could reissue an AAD
        // counter that is already bound to a stored ciphertext.
        let master = [0x11u8; 32];
        let salt = [0x22u8; 16];
        let mut files = HashMap::new();
        files.insert("a".to_string(), entry_with_counter(5));

        // Equal to the max stored counter: must be rejected.
        assert!(matches!(
            index_from_master(&master, &salt, 5, files.clone()),
            Err(IndexError::Inconsistent(_))
        ));

        // Below the max stored counter: must be rejected.
        assert!(matches!(
            index_from_master(&master, &salt, 3, files),
            Err(IndexError::Inconsistent(_))
        ));
    }

    #[test]
    fn from_subkeys_and_data_accepts_counter_ahead_of_entries() {
        let master = [0x11u8; 32];
        let salt = [0x22u8; 16];
        let mut files = HashMap::new();
        files.insert("a".to_string(), entry_with_counter(5));

        assert!(index_from_master(&master, &salt, 6, files).is_ok());
    }

    #[test]
    fn from_subkeys_and_data_accepts_empty_files_with_zero_counter() {
        let master = [0x11u8; 32];
        let salt = [0x22u8; 16];
        assert!(index_from_master(&master, &salt, 0, HashMap::new()).is_ok());
    }
}
