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
//! let matches = vault
//!     .with_secret("api_key", |secret| secret == b"sk-secret-12345")
//!     .unwrap();
//! assert_eq!(matches, Some(true));
//!
//! let bytes = vault.export().unwrap();
//! let reopened = Vault::open(b"my-password-here", &bytes).unwrap();
//! let matches = reopened
//!     .with_secret("api_key", |secret| secret == b"sk-secret-12345")
//!     .unwrap();
//! assert_eq!(matches, Some(true));
//! ```

use crate::constants::argon2::KEY_LEN;
use crate::constants::subkeys::SUBKEY_LEN;
use crate::constants::xchacha20_poly1305::XCHACHA20_NONCE_LEN;
use crate::constants::{
    LEGACY_VAULT_VERSION_1, MAX_ENTRY_DATA_SIZE, MAX_ENTRY_NAME_LEN, MAX_HEADER_JSON_LEN,
    MAX_KDF_ITERATIONS, MAX_KDF_MEMORY, MAX_VAULT_FILE_SIZE, MIN_KDF_ITERATIONS, MIN_KDF_MEMORY,
    MIN_PASSWORD_LEN, SUPPORTED_VAULT_VERSIONS,
};
use crate::crypto::aad_aead::{open_with_aad, seal_into, seal_with_nonce_prefix};
use crate::crypto::utils::secure_bytes_fill;
use crate::mem::locked_secret::LockedSecret;
use crate::vault::index_codec::{
    MIN_ENCRYPTED_INDEX_LEN, MIN_ENCRYPTED_INDEX_LEN_V1, decode_index, decode_index_v1,
    encode_index, encoded_index_len,
};
use crate::vault::vault_error::VaultError;
use crate::vault::vault_header::VaultHeader;
use crate::vault::vault_index::{IndexEntry, VaultIndex, derive_subkeys};
use orion::hazardous::kdf::argon2i;
use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;
use std::io::Read as IoRead;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// An encrypted in-memory vault for storing named secrets.
///
/// Secrets are encrypted with XChaCha20-Poly1305, keys are derived from a
/// password via Argon2id, and all key material is zeroized on drop.
///
/// # Examples
///
/// ```
/// use memseal::Vault;
///
/// let mut vault = Vault::create(b"password1234").unwrap();
/// vault.store("db_url", b"postgres://localhost/mydb").unwrap();
///
/// # let dir = tempfile::tempdir().unwrap();
/// # let path = dir.path().join("vault.seal");
/// vault.save(&path).unwrap();
///
/// let loaded = Vault::load(&path, b"password1234").unwrap();
/// assert_eq!(
///     loaded.retrieve("db_url").unwrap(),
///     Some(b"postgres://localhost/mydb".to_vec())
/// );
/// ```
pub struct Vault {
    header: VaultHeader,
    index: VaultIndex,
}

impl Vault {
    /// Creates a new empty vault protected by the given password.
    ///
    /// Password must be at least 8 bytes.
    pub fn create(password: &[u8]) -> Result<Self, VaultError> {
        validate_password(password)?;
        let header = VaultHeader::generate()?;
        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        derive_master_key(password, &header, &mut master_key)?;
        let index = VaultIndex::from_master_key(master_key.as_slice(), &header.kdf_salt)?;
        Ok(Vault { header, index })
    }

    /// Opens an existing vault from exported bytes.
    ///
    /// `data` is treated as untrusted input. The header is length-capped and
    /// its KDF parameters are range-checked before Argon2 runs, so the most
    /// a forged file can cost is one Argon2 derivation at 256 MiB and 10
    /// passes; see `DESIGN.md` section 10.
    ///
    /// Both the current format (version 2) and the format written by
    /// releases up to 0.2.1 (version 1) are accepted. A version 1 vault is
    /// upgraded in memory: its keys were derived with Argon2i, so the vault
    /// is re-keyed with Argon2id under the same password (a second
    /// derivation plus one re-encryption of every entry, exactly what
    /// [`Vault::change_password`] does) and the next [`Vault::export`] or
    /// [`Vault::save`] writes it in the current format. Nothing is written
    /// until then.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidPassword`] when the encrypted index fails
    /// to authenticate. The AEAD cannot tell a wrong password from a
    /// tampered, truncated, or corrupted file, so this variant covers both;
    /// callers that retry on it repeat the full key derivation each time.
    /// Structural problems found before or after authentication (bad length
    /// fields, malformed header, out-of-range parameters, an encrypted index
    /// too short to hold even an empty one, an inconsistent index) return
    /// [`VaultError::CorruptedData`]; those found before authentication are
    /// reported without running Argon2.
    pub fn open(password: &[u8], data: &[u8]) -> Result<Self, VaultError> {
        let envelope = parse_envelope(data)?;
        let header = envelope.header;

        // Argon2 is the expensive step; everything above is cheap. The two
        // subkeys are derived once for this header and the master key is
        // dropped right away. Zeroizing wipes each buffer on every exit
        // path, including the early returns below. (A version 1 file goes
        // through a second derivation in `rekey` below, after it has
        // authenticated.)
        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        derive_master_key(password, &header, &mut master_key)?;
        let mut enc_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        let mut hmac_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        derive_subkeys(
            master_key.as_slice(),
            &header.kdf_salt,
            &mut enc_sub,
            &mut hmac_sub,
        )?;
        drop(master_key);

        let aad = header.to_aad_bytes()?;
        // The decrypted index (HMAC entry names, nonce counters, structural
        // metadata) is cleared on scope exit as well.
        let index_bytes = Zeroizing::new(
            open_with_aad(&enc_sub, &envelope.nonce, envelope.encrypted_index, &aad)
                .map_err(|_| VaultError::InvalidPassword)?,
        );

        let idx_data = if header.version == LEGACY_VAULT_VERSION_1 {
            decode_index_v1(&index_bytes)?
        } else {
            decode_index(&index_bytes)?
        };

        let index = VaultIndex::from_subkeys_and_data(
            &enc_sub,
            &hmac_sub,
            envelope.nonce,
            idx_data.nonce_counter,
            idx_data.data_nonce_counter,
            idx_data.files,
        )?;

        let mut vault = Vault { header, index };
        if vault.header.version == LEGACY_VAULT_VERSION_1 {
            // Format 1 derived its keys with Argon2i. Re-key with the current
            // KDF under the same password so the in-memory vault is always
            // current-format and the next export writes version 2
            // (DESIGN.md section 12).
            vault.rekey(password)?;
        }
        Ok(vault)
    }

    /// Loads a vault from a file on disk.
    ///
    /// Reads at most 256 MiB, then hands the bytes to [`Vault::open`], so the
    /// same untrusted-input bounds and error mapping apply. The path is
    /// opened with the platform defaults, which follow symbolic links;
    /// callers that accept paths from untrusted sources must validate them
    /// first.
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
    /// Returns [`VaultError::InvalidInput`] when a limit is exceeded, or when
    /// the vault already holds 1024 entries under other names (overwriting
    /// an existing name is still allowed at the cap).
    pub fn store(&mut self, name: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        if name.len() > MAX_ENTRY_NAME_LEN {
            return Err(VaultError::InvalidInput(format!(
                "Entry name too long: {} bytes (max {})",
                name.len(),
                MAX_ENTRY_NAME_LEN
            )));
        }
        if plaintext.len() > MAX_ENTRY_DATA_SIZE {
            return Err(VaultError::InvalidInput(format!(
                "Entry data too large: {} bytes (max {})",
                plaintext.len(),
                MAX_ENTRY_DATA_SIZE
            )));
        }

        // Computed once: it is both the map key and part of the entry AAD
        // (which prevents entry-swap attacks).
        let hmac_key = self.index.hmac_key_for_name(name)?;

        // A new name in a full vault is refused here, before a data counter
        // is consumed and before the payload is encrypted for nothing.
        self.index.ensure_room_for(&hmac_key)?;

        let data_counter = self.index.next_data_nonce_counter()?;

        // Random nonces from the OS CSPRNG. They are stored as the prefix of
        // each ciphertext, so they never need to be re-derived; randomness
        // also rules out reuse when two vault instances are opened from the
        // same persisted state.
        let mut data_nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut data_nonce)?;
        let mut name_nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut name_nonce)?;

        let entry_aad = build_entry_aad(&hmac_key, data_counter);

        // Each blob is sealed directly behind its nonce in the allocation
        // the index will keep, so storing a payload never holds a second
        // copy of its ciphertext.
        let (encrypted_data, encrypted_name) = with_enc_key(self.index.enc_key(), |key| {
            Ok((
                seal_with_nonce_prefix(key, &data_nonce, plaintext, &entry_aad)?,
                seal_with_nonce_prefix(key, &name_nonce, name.as_bytes(), &entry_aad)?,
            ))
        })?;

        let entry = IndexEntry {
            data_counter,
            encrypted_name,
            encrypted_data,
        };

        self.index.insert_by_key(hmac_key, entry)?;
        Ok(())
    }

    /// Decrypts a secret and exposes it to `f` for the duration of the call.
    ///
    /// The library-owned plaintext buffer is zeroized immediately after `f`
    /// returns, including when `f` unwinds. The callback is not invoked and
    /// `Ok(None)` is returned if no secret with that name exists.
    ///
    /// The callback's return value may leave the closure, but it cannot borrow
    /// the temporary plaintext buffer. Callers can still deliberately copy the
    /// secret inside `f`; such copies are caller-owned and are not zeroized by
    /// the vault.
    ///
    /// A miss costs one HMAC and a map probe, a hit additionally runs an AEAD
    /// decryption, so call timing reveals whether a name exists. This is not
    /// a concern for a local vault but matters if names arrive from untrusted
    /// parties over a network.
    ///
    /// # Examples
    ///
    /// ```
    /// use memseal::Vault;
    ///
    /// let mut vault = Vault::create(b"my-password-here").unwrap();
    /// vault.store("api_key", b"sk-secret-12345").unwrap();
    ///
    /// let length = vault
    ///     .with_secret("api_key", |secret| secret.len())
    ///     .unwrap();
    /// assert_eq!(length, Some(15));
    /// ```
    ///
    /// A reference to the temporary plaintext cannot escape the callback:
    ///
    /// ```compile_fail
    /// use memseal::Vault;
    ///
    /// let mut vault = Vault::create(b"my-password-here").unwrap();
    /// vault.store("api_key", b"sk-secret-12345").unwrap();
    /// let secret: &[u8] = vault
    ///     .with_secret("api_key", |plaintext| plaintext)
    ///     .unwrap()
    ///     .unwrap();
    /// ```
    pub fn with_secret<R, F>(&self, name: &str, f: F) -> Result<Option<R>, VaultError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let plaintext = match self.decrypt_secret(name)? {
            Some(plaintext) => Zeroizing::new(plaintext),
            None => return Ok(None),
        };

        Ok(Some(f(plaintext.as_slice())))
    }

    /// Retrieves a secret by name, decrypting it into a caller-owned buffer.
    ///
    /// Returns `Ok(None)` if no secret with that name exists.
    /// Prefer [`Vault::with_secret`] when the plaintext only needs to be used
    /// temporarily. The caller is responsible for clearing the returned
    /// buffer from memory.
    pub fn retrieve(&self, name: &str) -> Result<Option<Vec<u8>>, VaultError> {
        self.decrypt_secret(name)
    }

    fn decrypt_secret(&self, name: &str) -> Result<Option<Vec<u8>>, VaultError> {
        let hmac_key = self.index.hmac_key_for_name(name)?;
        let Some(entry) = self.index.lookup_by_key(&hmac_key) else {
            return Ok(None);
        };

        let (nonce, ciphertext) = split_nonce(&entry.encrypted_data)?;
        let entry_aad = build_entry_aad(&hmac_key, entry.data_counter);

        let plaintext = with_enc_key(self.index.enc_key(), |key| {
            Ok(open_with_aad(key, &nonce, ciphertext, &entry_aad)?)
        })?;
        Ok(Some(plaintext))
    }

    /// Removes a secret by name. Returns `true` if it existed.
    ///
    /// The removed entry's ciphertexts are zeroized when it is dropped.
    pub fn remove(&mut self, name: &str) -> Result<bool, VaultError> {
        let hmac_key = self.index.hmac_key_for_name(name)?;
        Ok(self.index.remove_by_key(&hmac_key).is_some())
    }

    /// Serializes the vault to bytes for persistence, always in the current
    /// format (version 2).
    ///
    /// Each call generates a fresh random index nonce and advances the
    /// authenticated nonce counter.
    ///
    /// Returns [`VaultError::SerializationError`] if the serialized vault
    /// would exceed the 256 MiB file-size bound enforced by [`Vault::load`];
    /// this guarantees that anything `export()` produces can be loaded back.
    /// The index is a compact binary encoding, so the bound on total stored
    /// secrets is close to the file bound itself: each entry costs its
    /// plaintext size plus 128 bytes plus the name length, on top of a
    /// header of a few hundred bytes. The size is known before anything is
    /// encoded, so this error costs no allocation and leaves the vault
    /// exactly as it was, nonce counter included; remove entries and export
    /// again.
    ///
    /// On top of the returned buffer, a successful export transiently holds
    /// one more copy of the vault's size (the plaintext index, zeroized
    /// before returning).
    pub fn export(&mut self) -> Result<Vec<u8>, VaultError> {
        // The header bytes written to the file are also the AAD of the index
        // (DESIGN.md section 3), so they are serialized once.
        let header_bytes = self.header.to_aad_bytes()?;
        let nonce_start = 4 + header_bytes.len();
        let index_start = nonce_start + XCHACHA20_NONCE_LEN;
        let total = index_start + encoded_index_len(&self.index) + POLY1305_OUTSIZE;

        // Enforced on the computed size, before the index is encoded or
        // encrypted and before the nonce counter moves: an oversized vault
        // is refused for free instead of after materializing the export.
        validate_export_size(total as u64)?;

        self.index.advance_nonce()?;

        // The plaintext index carries HMAC'd names and counters; clear it on
        // scope exit like the rest of the key-handling in this file.
        let index_bytes = Zeroizing::new(encode_index(&self.index)?);

        // One allocation of the final size; the index is sealed straight
        // into its tail rather than into a buffer that is then copied.
        let mut output = vec![0u8; total];
        output[..4].copy_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        output[4..nonce_start].copy_from_slice(&header_bytes);
        output[nonce_start..index_start].copy_from_slice(&self.index.nonce);
        with_enc_key(self.index.enc_key(), |key| {
            Ok(seal_into(
                key,
                &self.index.nonce,
                &index_bytes,
                &header_bytes,
                &mut output[index_start..],
            )?)
        })?;

        Ok(output)
    }

    /// Saves the vault to a file on disk.
    ///
    /// Writes a temporary file in the same directory, fsyncs it, and renames
    /// it over `path`. On Unix the directory is then fsynced as well, best
    /// effort: by that point the rename has taken effect, so a failure of
    /// this last step is not reported (some filesystems do not support it)
    /// and only the durability of the rename across a crash is in doubt.
    ///
    /// On Unix the file is created with mode `0600`. On Windows no ACL is
    /// applied: the file inherits the DACL of its directory, so callers who
    /// need owner-only access there must restrict the directory or set the
    /// ACL themselves after saving.
    ///
    /// Symbolic links in the directory components of `path` are followed; a
    /// link at `path` itself is replaced by the rename, not written through.
    /// Each call advances the vault's nonce counter, see [`Vault::export`].
    pub fn save(&mut self, path: &Path) -> Result<(), VaultError> {
        use std::io::Write;

        let data = self.export()?;
        // `Path::parent` of a bare file name is `Some("")`, not `None`; both
        // mean the current directory, and `""` cannot be opened for the
        // directory fsync below.
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };

        let mut rand_suffix = [0u8; 8];
        secure_bytes_fill(&mut rand_suffix)?;
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

        let write_result = file.write_all(&data).and_then(|_| file.sync_all());
        drop(file);
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        std::fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })?;

        // Best effort, see the doc comment: the new file is already in
        // place, and reporting an error here would read as "not saved".
        #[cfg(unix)]
        if let Ok(dir_file) = std::fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }

        Ok(())
    }

    /// Changes the vault's password.
    ///
    /// `current_password` is verified by deriving its subkeys with the
    /// current header and comparing the encryption subkey with the one in
    /// memory in constant time; this costs one Argon2id derivation and has no
    /// side effects. Returns [`VaultError::InvalidPassword`] on a mismatch
    /// and leaves the vault untouched.
    ///
    /// On success, every entry is decrypted and re-encrypted one at a time
    /// under keys derived from `new_password` with a fresh salt (at most one
    /// plaintext in memory at any given time). The vault is only replaced
    /// once every entry has been re-encrypted; any failure leaves it
    /// unchanged and fully usable.
    pub fn change_password(
        &mut self,
        current_password: &[u8],
        new_password: &[u8],
    ) -> Result<(), VaultError> {
        validate_password(new_password)?;
        self.verify_password(current_password)?;
        self.rekey(new_password)
    }

    /// Derives fresh keys from `password` with a new header (current format
    /// version, fresh salt) and re-encrypts every entry under them, one at a
    /// time. `self` is replaced only once every entry has been re-encrypted;
    /// any failure leaves it unchanged.
    fn rekey(&mut self, password: &[u8]) -> Result<(), VaultError> {
        let new_header = VaultHeader::generate()?;
        let mut new_master_key = Zeroizing::new([0u8; KEY_LEN]);
        derive_master_key(password, &new_header, &mut new_master_key)?;
        let new_index =
            VaultIndex::from_master_key(new_master_key.as_slice(), &new_header.kdf_salt)?;
        drop(new_master_key);

        let mut new_vault = Vault {
            header: new_header,
            index: new_index,
        };

        // Re-encrypt entries one at a time into new_vault, reading the old
        // ciphertexts in place. The old key is lent from its locked page for
        // the whole pass; `store` borrows the new one the same way.
        with_enc_key(self.index.enc_key(), |old_enc_key| {
            for (old_hmac_key, entry) in &self.index.files {
                let old_aad = build_entry_aad(old_hmac_key, entry.data_counter);

                let (name_nonce, name_ct) = split_nonce(&entry.encrypted_name)?;
                let name_bytes = open_with_aad(old_enc_key, &name_nonce, name_ct, &old_aad)?;
                let plaintext_name =
                    Zeroizing::new(String::from_utf8(name_bytes).map_err(|e| {
                        let mut bytes = e.into_bytes();
                        bytes.zeroize();
                        VaultError::CorruptedData("Invalid entry name".to_string())
                    })?);

                let (data_nonce, data_ct) = split_nonce(&entry.encrypted_data)?;
                let plaintext =
                    Zeroizing::new(open_with_aad(old_enc_key, &data_nonce, data_ct, &old_aad)?);

                new_vault.store(&plaintext_name, &plaintext)?;
            }
            Ok(())
        })?;

        // Only swap on full success; on error, self retains old keys and data.
        self.header = new_vault.header;
        self.index = new_vault.index;
        Ok(())
    }

    /// Checks `password` against the keys in memory without touching the
    /// vault: one Argon2id derivation with the current header, then a
    /// constant-time comparison of the derived encryption subkey with the
    /// stored one.
    fn verify_password(&self, password: &[u8]) -> Result<(), VaultError> {
        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        derive_master_key(password, &self.header, &mut master_key)?;
        let mut enc_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        let mut hmac_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        derive_subkeys(
            master_key.as_slice(),
            &self.header.kdf_salt,
            &mut enc_sub,
            &mut hmac_sub,
        )?;
        drop(hmac_sub);
        drop(master_key);

        self.index
            .enc_key()
            .with_bytes(|stored| orion::util::secure_cmp(stored, enc_sub.as_slice()))
            .map_err(|_| VaultError::InvalidPassword)
    }
}

/// The plaintext envelope of a vault file (DESIGN.md section 2), parsed and
/// bounds-checked but not yet authenticated. Everything in it is
/// attacker-controlled until `encrypted_index` verifies under the key
/// derived from `header`.
pub(crate) struct Envelope<'a> {
    header: VaultHeader,
    nonce: [u8; XCHACHA20_NONCE_LEN],
    encrypted_index: &'a [u8],
}

/// Steps 1-8 of DESIGN.md section 2.1: the part of `open` that runs before
/// any key derivation. It is pure and cheap, which is what makes it the
/// right target for fuzzing the untrusted-input parser without paying for
/// Argon2 on every input.
pub(crate) fn parse_envelope(data: &[u8]) -> Result<Envelope<'_>, VaultError> {
    // `load` already enforces this on the file; `open` takes bytes from
    // anywhere, so the same cap applies here. It bounds the AEAD pass and
    // the index allocation at 256 MiB, as DESIGN.md section 10.1 promises.
    if data.len() as u64 > MAX_VAULT_FILE_SIZE {
        return Err(VaultError::CorruptedData(format!(
            "Vault data of {} bytes exceeds maximum {}",
            data.len(),
            MAX_VAULT_FILE_SIZE
        )));
    }
    if data.len() < 4 {
        return Err(VaultError::CorruptedData("Data too short".to_string()));
    }

    let header_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;

    // The header is plaintext and is parsed before anything has been
    // authenticated, so it gets its own tight bound rather than the
    // 256 MiB file cap. This also rules out any offset overflow below.
    if header_len > MAX_HEADER_JSON_LEN {
        return Err(VaultError::CorruptedData(format!(
            "Header length {} exceeds maximum {}",
            header_len, MAX_HEADER_JSON_LEN
        )));
    }

    let after_header = 4 + header_len;
    if data.len() < after_header + XCHACHA20_NONCE_LEN {
        return Err(VaultError::CorruptedData(
            "Data too short for header and nonce".to_string(),
        ));
    }

    let header_bytes = &data[4..after_header];
    let header: VaultHeader = serde_json::from_slice(header_bytes)
        .map_err(|e| VaultError::CorruptedData(format!("Invalid header JSON: {}", e)))?;

    validate_header(&header)?;

    // The AAD is the canonical serialization of the parsed header, so the
    // bytes in the file are only authenticated if they are that
    // serialization. Require it: every file this library has written is in
    // canonical form, and anything else (reordered or padded JSON) would be
    // an unauthenticated edit (DESIGN.md section 3).
    if header_bytes != header.to_aad_bytes()?.as_slice() {
        return Err(VaultError::CorruptedData(
            "Header JSON is not in canonical form".to_string(),
        ));
    }

    let nonce: [u8; XCHACHA20_NONCE_LEN] = data[after_header..after_header + XCHACHA20_NONCE_LEN]
        .try_into()
        .unwrap();

    // Format version 1 wrote an 8-byte copy of the nonce counter after the
    // nonce that was never read back; the authenticated copy inside the
    // index is the one that counts. Skip it.
    let mut index_start = after_header + XCHACHA20_NONCE_LEN;
    if header.version == LEGACY_VAULT_VERSION_1 {
        index_start += 8;
        if data.len() < index_start {
            return Err(VaultError::CorruptedData(
                "Data too short for legacy counter".to_string(),
            ));
        }
    }
    let encrypted_index = &data[index_start..];

    // An index shorter than a tag around the smallest possible plaintext
    // cannot decode even if it authenticated, so it is rejected here rather
    // than after an Argon2 derivation with the header's parameters.
    let min_index_len = if header.version == LEGACY_VAULT_VERSION_1 {
        MIN_ENCRYPTED_INDEX_LEN_V1
    } else {
        MIN_ENCRYPTED_INDEX_LEN
    };
    if encrypted_index.len() < min_index_len {
        return Err(VaultError::CorruptedData(format!(
            "Encrypted index of {} bytes is shorter than the minimum {}",
            encrypted_index.len(),
            min_index_len
        )));
    }

    Ok(Envelope {
        header,
        nonce,
        encrypted_index,
    })
}

fn validate_password(password: &[u8]) -> Result<(), VaultError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(VaultError::InvalidInput(format!(
            "Password must be at least {} bytes",
            MIN_PASSWORD_LEN
        )));
    }
    Ok(())
}

fn validate_header(header: &VaultHeader) -> Result<(), VaultError> {
    if !SUPPORTED_VAULT_VERSIONS.contains(&header.version) {
        return Err(VaultError::CorruptedData(format!(
            "Unsupported vault version: {} (supported: {:?})",
            header.version, SUPPORTED_VAULT_VERSIONS
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

/// Rejects exports larger than the bound `Vault::load` enforces, so a vault
/// that `save()` writes can always be loaded back.
fn validate_export_size(len: u64) -> Result<(), VaultError> {
    if len > MAX_VAULT_FILE_SIZE {
        return Err(VaultError::SerializationError(format!(
            "Exported vault is {} bytes, exceeding the maximum vault file size of {} bytes; remove entries before exporting",
            len, MAX_VAULT_FILE_SIZE
        )));
    }
    Ok(())
}

/// Splits a stored blob into its 24-byte nonce prefix and the ciphertext.
/// Decoders already reject shorter blobs; this is the in-memory guard.
fn split_nonce(blob: &[u8]) -> Result<([u8; XCHACHA20_NONCE_LEN], &[u8]), VaultError> {
    if blob.len() < XCHACHA20_NONCE_LEN {
        return Err(VaultError::CorruptedData(
            "Encrypted entry too short for nonce".to_string(),
        ));
    }
    let nonce: [u8; XCHACHA20_NONCE_LEN] = blob[..XCHACHA20_NONCE_LEN].try_into().unwrap();
    Ok((nonce, &blob[XCHACHA20_NONCE_LEN..]))
}

fn build_entry_aad(hmac_key: &str, counter: u64) -> Zeroizing<Vec<u8>> {
    let key_bytes = hmac_key.as_bytes();
    let counter_bytes = counter.to_le_bytes();
    let mut aad = Zeroizing::new(Vec::with_capacity(key_bytes.len() + 8));
    aad.extend_from_slice(key_bytes);
    aad.extend_from_slice(&counter_bytes);
    aad
}

/// Lends the 32-byte encryption subkey to `f` straight from its locked
/// container, for the duration of one operation.
///
/// The key is never copied into a buffer of this crate: `f` receives a
/// reference into the locked page, and the only copy made while it runs is
/// the one `orion` keeps in its own zeroize-on-drop key type. A function
/// that returned the key by value would be moved through its caller's frame,
/// and a move may leave the bytes behind in a stack slot nothing wipes.
///
/// The subkey is always exactly 32 bytes (HKDF-SHA256 output). Any other
/// length is a hard error, and `f` is not called, rather than being silently
/// padded, which would otherwise lead to encryption or decryption under a
/// partly known key.
fn with_enc_key<R>(
    enc_secret: &LockedSecret,
    f: impl FnOnce(&[u8; SUBKEY_LEN]) -> Result<R, VaultError>,
) -> Result<R, VaultError> {
    enc_secret.with_bytes(|bytes| {
        let key: &[u8; SUBKEY_LEN] = bytes.try_into().map_err(|_| {
            VaultError::CryptoError(format!(
                "encryption subkey is {} bytes, expected {}",
                bytes.len(),
                SUBKEY_LEN
            ))
        })?;
        f(key)
    })
}

/// Derives the master key from the password into `master_key`, with the KDF
/// of the header's format version: Argon2id for the current format, Argon2i
/// for format version 1 (DESIGN.md sections 4 and 12). Both use the header's
/// salt, memory cost, and pass count with a single lane.
///
/// Like `derive_subkeys`, this writes into a buffer the caller owns instead
/// of returning the key: the caller passes a `Zeroizing` array, so the key
/// exists in exactly one place and is wiped on every exit path, including
/// the error returns below (which may leave it partly written).
fn derive_master_key(
    password: &[u8],
    header: &VaultHeader,
    master_key: &mut [u8; KEY_LEN],
) -> Result<(), VaultError> {
    if header.version == LEGACY_VAULT_VERSION_1 {
        argon2i::derive_key(
            password,
            &header.kdf_salt,
            header.kdf_iterations,
            header.kdf_memory_cost,
            None,
            None,
            master_key.as_mut_slice(),
        )
        .map_err(|e| VaultError::CryptoError(format!("Argon2i derivation failed: {}", e)))?;
    } else {
        let params = argon2::Params::new(
            header.kdf_memory_cost,
            header.kdf_iterations,
            1,
            Some(KEY_LEN),
        )
        .map_err(|e| VaultError::CryptoError(format!("Argon2id parameters: {}", e)))?;
        // `hash_password_into` would allocate the memory matrix itself and
        // free it without wiping; the last block of the lane is one hash away
        // from the master key, so the matrix is owned here and zeroized on
        // drop (the Argon2i path through `orion` wipes its own blocks).
        let mut blocks = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into_with_memory(
                password,
                &header.kdf_salt,
                master_key.as_mut_slice(),
                blocks.as_mut_slice(),
            )
            .map_err(|e| VaultError::CryptoError(format!("Argon2id derivation failed: {}", e)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{VAULT_VERSION, argon2};
    use crate::vault::index_codec::{
        ENTRY_KEY_LEN, MAX_ENCRYPTED_NAME_LEN, MIN_ENCRYPTED_LEN, key_to_hex,
    };

    /// Test helper: the master key for `header` in a zeroizing buffer.
    fn master_key_for(password: &[u8], header: &VaultHeader) -> Zeroizing<[u8; KEY_LEN]> {
        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        derive_master_key(password, header, &mut master_key).unwrap();
        master_key
    }

    #[test]
    fn with_enc_key_lends_the_subkey_in_place() {
        let key = [7u8; 32];
        let secret = LockedSecret::new(&key).unwrap();
        // The closure sees the bytes inside the locked region, not a copy:
        // the address it is given is the one `with_bytes` hands out.
        let locked_addr = secret.with_bytes(|bytes| bytes.as_ptr() as usize);
        let lent_addr = with_enc_key(&secret, |lent| {
            assert_eq!(lent, &key);
            Ok(lent.as_ptr() as usize)
        })
        .unwrap();
        assert_eq!(lent_addr, locked_addr);
    }

    #[test]
    fn with_enc_key_propagates_the_closure_result() {
        let secret = LockedSecret::new(&[7u8; 32]).unwrap();
        assert_eq!(with_enc_key(&secret, |key| Ok(key.len())).unwrap(), 32);
        assert!(matches!(
            with_enc_key(&secret, |_| -> Result<(), VaultError> {
                Err(VaultError::InvalidInput("from the closure".to_string()))
            }),
            Err(VaultError::InvalidInput(_))
        ));
    }

    #[test]
    fn with_enc_key_rejects_wrong_length_subkey() {
        // A subkey that is not exactly 32 bytes must be a hard error rather
        // than a silent fall-through that would lead to encryption under a
        // truncated or padded key. The closure must not run at all.
        for len in [16usize, 31, 33, 64] {
            let secret = LockedSecret::new(&vec![1u8; len]).unwrap();
            let mut called = false;
            let result = with_enc_key(&secret, |_| {
                called = true;
                Ok(())
            });
            assert!(matches!(result, Err(VaultError::CryptoError(_))));
            assert!(!called, "closure ran for a {}-byte subkey", len);
        }
    }

    #[test]
    fn derive_master_key_writes_only_into_the_caller_buffer_and_is_deterministic() {
        let header = VaultHeader::new([0x33; 16], MIN_KDF_ITERATIONS, MIN_KDF_MEMORY, 32);
        let mut first = Zeroizing::new([0u8; KEY_LEN]);
        derive_master_key(b"same-password", &header, &mut first).unwrap();
        assert_ne!(*first, [0u8; KEY_LEN]);

        // A buffer that already holds other bytes is fully overwritten.
        let mut second = Zeroizing::new([0xFFu8; KEY_LEN]);
        derive_master_key(b"same-password", &header, &mut second).unwrap();
        assert_eq!(*first, *second);
    }

    #[test]
    fn derive_master_key_selects_kdf_by_format_version() {
        // Same password, salt, and parameters: format 1 uses Argon2i,
        // format 2 Argon2id, and the two must not agree.
        let mut legacy = VaultHeader::new([7u8; 16], MIN_KDF_ITERATIONS, MIN_KDF_MEMORY, 32);
        legacy.version = LEGACY_VAULT_VERSION_1;
        let current = VaultHeader::new([7u8; 16], MIN_KDF_ITERATIONS, MIN_KDF_MEMORY, 32);
        assert_eq!(current.version, VAULT_VERSION);
        let k1 = master_key_for(b"kdf-password", &legacy);
        let k2 = master_key_for(b"kdf-password", &current);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_master_key_argon2id_known_answer() {
        // Pins the Argon2id configuration (version 0x13, one lane, 32-byte
        // output) so a silent parameter change breaks the test rather than
        // every existing vault.
        let header = VaultHeader::new([0x5A; 16], MIN_KDF_ITERATIONS, MIN_KDF_MEMORY, 32);
        let key = master_key_for(b"known-answer-password", &header);
        assert_eq!(key_to_hex(key.as_slice()), ARGON2ID_KAT);
    }

    const ARGON2ID_KAT: &str = "99042566ff7a3da22162503ab2b2d089c071ec7b836c2eb1e395effde97bd229";

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
    fn with_secret_borrows_plaintext_and_returns_callback_value() {
        let mut vault = Vault::create(b"test-password").unwrap();
        vault.store("api_key", b"sk-secret-12345").unwrap();

        let observed = vault
            .with_secret("api_key", |secret| {
                assert_eq!(secret, b"sk-secret-12345");
                secret.len()
            })
            .unwrap();

        assert_eq!(observed, Some(15));
    }

    #[test]
    fn with_secret_missing_does_not_invoke_callback() {
        let vault = Vault::create(b"test-password").unwrap();
        let mut invoked = false;

        let result = vault
            .with_secret("missing", |_| {
                invoked = true;
            })
            .unwrap();

        assert_eq!(result, None);
        assert!(!invoked);
    }

    #[test]
    fn with_secret_supports_empty_plaintext() {
        let mut vault = Vault::create(b"test-password").unwrap();
        vault.store("empty", b"").unwrap();

        let is_empty = vault
            .with_secret("empty", |secret| secret.is_empty())
            .unwrap();

        assert_eq!(is_empty, Some(true));
    }

    #[test]
    fn with_secret_preserves_fallible_callback_result() {
        let mut vault = Vault::create(b"test-password").unwrap();
        vault.store("number", b"42").unwrap();

        let parsed = vault
            .with_secret("number", |secret| {
                if secret == b"42" {
                    Ok(42_u8)
                } else {
                    Err("unexpected value")
                }
            })
            .unwrap()
            .transpose()
            .unwrap();

        assert_eq!(parsed, Some(42));
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.seal");

        let mut vault = Vault::create(b"file-password").unwrap();
        vault.store("secret", b"file-stored-value").unwrap();
        vault.save(&path).unwrap();

        let loaded = Vault::load(&path, b"file-password").unwrap();
        assert_eq!(
            loaded.retrieve("secret").unwrap(),
            Some(b"file-stored-value".to_vec())
        );
    }

    #[test]
    fn load_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.seal");

        let mut vault = Vault::create(b"correct!").unwrap();
        vault.save(&path).unwrap();

        assert!(matches!(
            Vault::load(&path, b"wrong!!!"),
            Err(VaultError::InvalidPassword)
        ));
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
    fn change_password_wrong_current_fails_without_side_effects() {
        let mut vault = Vault::create(b"real-pwd!").unwrap();
        vault.store("key", b"value").unwrap();
        let nonce_before = vault.index.nonce;
        let counter_before = vault.index.nonce_counter;

        assert!(matches!(
            vault.change_password(b"wrong!!!", b"new-pwd!"),
            Err(VaultError::InvalidPassword)
        ));

        // The vault is untouched: same keys, same nonce state, entries
        // still readable, and the old password still opens an export.
        assert_eq!(vault.index.nonce, nonce_before);
        assert_eq!(vault.index.nonce_counter, counter_before);
        assert_eq!(vault.retrieve("key").unwrap(), Some(b"value".to_vec()));
        let exported = vault.export().unwrap();
        assert!(Vault::open(b"real-pwd!", &exported).is_ok());
    }

    #[test]
    fn change_password_rejects_short_new_password() {
        let mut vault = Vault::create(b"real-pwd!").unwrap();
        assert!(matches!(
            vault.change_password(b"real-pwd!", b"short"),
            Err(VaultError::InvalidInput(_))
        ));
        assert_eq!(vault.index.nonce_counter, 0);
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
    fn header_validation_rejects_iterations_above_max() {
        let bad = VaultHeader::new([0; 16], MAX_KDF_ITERATIONS + 1, 131_072, 32);
        assert!(validate_header(&bad).is_err());
    }

    #[test]
    fn header_validation_rejects_iterations_below_min() {
        let bad = VaultHeader::new([0; 16], MIN_KDF_ITERATIONS - 1, 131_072, 32);
        assert!(validate_header(&bad).is_err());
    }

    #[test]
    fn header_validation_accepts_inclusive_bounds_and_defaults() {
        // The defaults every vault is written with must sit inside the
        // accepted range, and both ends of the range are inclusive.
        for (iterations, memory) in [
            (argon2::ITERATIONS, argon2::MEMORY_COST),
            (MIN_KDF_ITERATIONS, MIN_KDF_MEMORY),
            (MAX_KDF_ITERATIONS, MAX_KDF_MEMORY),
        ] {
            let header = VaultHeader::new([0; 16], iterations, memory, 32);
            assert!(validate_header(&header).is_ok());
        }
    }

    #[test]
    fn short_password_rejected() {
        assert!(matches!(
            Vault::create(b"short"),
            Err(VaultError::InvalidInput(_))
        ));
    }

    #[test]
    fn long_entry_name_rejected() {
        let mut vault = Vault::create(b"password").unwrap();
        let long_name = "x".repeat(MAX_ENTRY_NAME_LEN + 1);
        assert!(matches!(
            vault.store(&long_name, b"data"),
            Err(VaultError::InvalidInput(_))
        ));
    }

    #[test]
    fn full_vault_rejects_new_name_as_invalid_input() {
        let mut vault = Vault::create(b"password").unwrap();
        let max = crate::constants::vault_index_constants::MAX_INDEX_ENTRIES;
        for i in 0..max {
            vault.store(&format!("k{}", i), b"v").unwrap();
        }
        let counter_before = vault.index.data_nonce_counter;
        assert!(matches!(
            vault.store("one-more", b"v"),
            Err(VaultError::InvalidInput(_))
        ));
        // The refusal comes before any work: no data counter is consumed.
        assert_eq!(vault.index.data_nonce_counter, counter_before);
        // Overwriting an existing name is still allowed at the cap.
        vault.store("k0", b"v2").unwrap();
        assert_eq!(vault.retrieve("k0").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(vault.index.data_nonce_counter, counter_before + 1);
    }

    #[test]
    fn store_keeps_one_exactly_sized_allocation_per_blob() {
        // Each blob is nonce || ciphertext || tag, sealed in place: the
        // allocation the index keeps has no slack and no second copy.
        let mut vault = Vault::create(b"password-blobs").unwrap();
        let payload = vec![0x5Au8; 1000];
        vault.store("name", &payload).unwrap();

        let entry = vault.index.files.values().next().unwrap();
        let overhead = XCHACHA20_NONCE_LEN + POLY1305_OUTSIZE;
        assert_eq!(entry.encrypted_data.len(), payload.len() + overhead);
        assert_eq!(entry.encrypted_data.capacity(), payload.len() + overhead);
        assert_eq!(entry.encrypted_name.len(), "name".len() + overhead);
        assert_eq!(entry.encrypted_name.capacity(), "name".len() + overhead);
        assert_eq!(vault.retrieve("name").unwrap(), Some(payload));
    }

    #[test]
    fn header_len_overflow_rejected() {
        let mut data = vec![0u8; 100];
        data[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Vault::open(b"password", &data).is_err());
    }

    // Direct test of the pre-authentication parser. It runs without
    // Argon2; the end-to-end variants below exercise the same checks through
    // open(). The index decoders have their own tests in index_codec.

    #[test]
    fn parse_envelope_splits_a_valid_export() {
        let mut vault = Vault::create(b"password-env").unwrap();
        vault.store("k", b"v").unwrap();
        let data = vault.export().unwrap();

        let envelope = parse_envelope(&data).unwrap();
        assert_eq!(envelope.header.version, VAULT_VERSION);
        assert_eq!(
            envelope.header.to_aad_bytes().unwrap(),
            vault.header.to_aad_bytes().unwrap()
        );
        assert_eq!(envelope.nonce, vault.index.nonce);
        let header_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        assert_eq!(
            envelope.encrypted_index.len(),
            data.len() - (4 + header_len + XCHACHA20_NONCE_LEN)
        );
    }

    // Format version 1 compatibility. The fixture was written by memseal
    // 0.2.1 (JSON index, 8-byte counter after the nonce) and holds four
    // entries; a fifth was stored and removed before saving.

    const V1_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/vault_v1.seal");
    const V1_PASSWORD: &[u8] = b"fixture-password-v1";

    fn assert_fixture_entries(vault: &Vault) {
        assert_eq!(vault.index.files.len(), 4);
        assert_eq!(
            vault.retrieve("api_key").unwrap(),
            Some(b"sk-fixture-12345-v2".to_vec())
        );
        assert_eq!(vault.retrieve("empty").unwrap(), Some(Vec::new()));
        assert_eq!(
            vault.retrieve(&"n".repeat(255)).unwrap(),
            Some(b"longest name".to_vec())
        );
        let payload: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 251) as u8).collect();
        assert_eq!(vault.retrieve("blob").unwrap(), Some(payload));
        assert_eq!(vault.retrieve("gone").unwrap(), None);
    }

    #[test]
    fn v1_fixture_opens_and_is_rewritten_as_current_format() {
        let envelope = parse_envelope(V1_FIXTURE).unwrap();
        assert_eq!(envelope.header.version, LEGACY_VAULT_VERSION_1);

        let mut vault = Vault::open(V1_PASSWORD, V1_FIXTURE).unwrap();
        assert_fixture_entries(&vault);
        // The in-memory vault is upgraded and re-keyed with Argon2id under a
        // fresh salt: the next export writes version 2.
        assert_eq!(vault.header.version, VAULT_VERSION);
        assert_ne!(vault.header.kdf_salt, envelope.header.kdf_salt);

        let exported = vault.export().unwrap();
        assert_eq!(
            parse_envelope(&exported).unwrap().header.version,
            VAULT_VERSION
        );
        // Same secrets, binary index instead of JSON number arrays: far
        // smaller than the original.
        assert!(exported.len() < V1_FIXTURE.len() / 2);

        let reopened = Vault::open(V1_PASSWORD, &exported).unwrap();
        assert_fixture_entries(&reopened);

        // Still writable after migration.
        let mut reopened = reopened;
        reopened.store("new", b"after migration").unwrap();
        let again = Vault::open(V1_PASSWORD, &reopened.export().unwrap()).unwrap();
        assert_eq!(
            again.retrieve("new").unwrap(),
            Some(b"after migration".to_vec())
        );
        assert_eq!(again.index.files.len(), 5);
    }

    #[test]
    fn v1_fixture_rejects_wrong_password() {
        assert!(matches!(
            Vault::open(b"wrong-password!", V1_FIXTURE),
            Err(VaultError::InvalidPassword)
        ));
    }

    #[test]
    fn v1_fixture_ignores_the_unauthenticated_counter_bytes() {
        // Format 1 wrote 8 bytes of nonce counter after the nonce that were
        // never read back; the legacy reader skips them, so flipping every
        // bit must not change the outcome.
        let header_len = u32::from_le_bytes(V1_FIXTURE[..4].try_into().unwrap()) as usize;
        let counter_start = 4 + header_len + XCHACHA20_NONCE_LEN;
        let mut tampered = V1_FIXTURE.to_vec();
        for b in &mut tampered[counter_start..counter_start + 8] {
            *b ^= 0xFF;
        }
        let vault = Vault::open(V1_PASSWORD, &tampered).unwrap();
        assert_fixture_entries(&vault);
    }

    #[test]
    fn v1_fixture_truncated_inside_counter_is_rejected() {
        let header_len = u32::from_le_bytes(V1_FIXTURE[..4].try_into().unwrap()) as usize;
        let cut = 4 + header_len + XCHACHA20_NONCE_LEN + 4;
        assert!(matches!(
            Vault::open(V1_PASSWORD, &V1_FIXTURE[..cut]),
            Err(VaultError::CorruptedData(_))
        ));
    }

    #[test]
    fn current_format_export_does_not_carry_the_legacy_counter() {
        // A version 2 envelope goes straight from the nonce to the
        // ciphertext. Reading it as if the 8 legacy bytes were present (or
        // flipping the bytes right after the nonce) must fail the AEAD.
        let password: &[u8] = b"password-v2-layout";
        let valid = make_valid_export(password);
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let after_nonce = 4 + header_len + XCHACHA20_NONCE_LEN;

        let mut tampered = valid.clone();
        tampered[after_nonce] ^= 0xFF;
        assert!(matches!(
            Vault::open(password, &tampered),
            Err(VaultError::InvalidPassword)
        ));
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
        let mut data = vec![0u8; 4 + XCHACHA20_NONCE_LEN];
        data[..4].copy_from_slice(&0u32.to_le_bytes());
        let result = Vault::open(b"password", &data);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_header_len_exceeding_available_bytes() {
        // header_len within MAX_HEADER_JSON_LEN but larger than provided bytes.
        // Exercises the size branch, distinct from the
        // `header_len > MAX_HEADER_JSON_LEN` branch covered by
        // `header_len_overflow_rejected` and the cap tests below.
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(&1_000u32.to_le_bytes());
        let result = Vault::open(b"password", &data);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_header_len_above_cap_before_parsing() {
        // Enough bytes are present for the declared header, so the only
        // reason to fail is the cap itself; the JSON must never be parsed.
        let header_len = MAX_HEADER_JSON_LEN + 1;
        let mut data = vec![b'{'; 4 + header_len + XCHACHA20_NONCE_LEN];
        data[..4].copy_from_slice(&(header_len as u32).to_le_bytes());
        match Vault::open(b"password", &data) {
            Err(VaultError::CorruptedData(msg)) => {
                assert!(msg.contains("Header length"), "unexpected message: {}", msg)
            }
            Err(e) => panic!("unexpected error: {}", e),
            Ok(_) => panic!("oversized header accepted"),
        }
    }

    #[test]
    fn open_accepts_header_len_at_cap_then_fails_on_json() {
        // Exactly at the cap the length check passes and the (garbage)
        // header reaches the JSON parser, which rejects it.
        let header_len = MAX_HEADER_JSON_LEN;
        let mut data = vec![b'{'; 4 + header_len + XCHACHA20_NONCE_LEN];
        data[..4].copy_from_slice(&(header_len as u32).to_le_bytes());
        match Vault::open(b"password", &data) {
            Err(VaultError::CorruptedData(msg)) => {
                assert!(
                    msg.contains("Invalid header JSON"),
                    "unexpected message: {}",
                    msg
                )
            }
            Err(e) => panic!("unexpected error: {}", e),
            Ok(_) => panic!("garbage header accepted"),
        }
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
    fn open_rejects_missing_ciphertext_after_nonce() {
        // Header and nonce present, but the ciphertext region is empty (no
        // AEAD tag). Nothing that short can hold an index, so it is a
        // structural error reported before Argon2 runs, not an
        // authentication failure.
        let valid = make_valid_export(b"password-cccc");
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let cut = 4 + header_len + XCHACHA20_NONCE_LEN;
        let truncated = &valid[..cut];
        let result = Vault::open(b"password-cccc", truncated);
        match result {
            Err(VaultError::CorruptedData(msg)) => {
                assert!(msg.contains("Encrypted index"), "{}", msg)
            }
            _ => panic!("empty ciphertext region accepted or misreported"),
        }
    }

    #[test]
    fn parse_envelope_enforces_the_minimum_index_length() {
        // The smallest genuine file is an empty vault: its encrypted index
        // is exactly the 22-byte preamble plus the tag.
        let mut vault = Vault::create(b"password-min").unwrap();
        let empty = vault.export().unwrap();
        let header_len = u32::from_le_bytes(empty[..4].try_into().unwrap()) as usize;
        let index_start = 4 + header_len + XCHACHA20_NONCE_LEN;
        assert_eq!(empty.len() - index_start, MIN_ENCRYPTED_INDEX_LEN);
        assert_eq!(MIN_ENCRYPTED_INDEX_LEN, 38);
        assert!(parse_envelope(&empty).is_ok());

        // Every shorter index is rejected by the parser itself, which never
        // derives a key.
        for len in 0..MIN_ENCRYPTED_INDEX_LEN {
            match parse_envelope(&empty[..index_start + len]) {
                Err(VaultError::CorruptedData(msg)) => {
                    assert!(msg.contains("Encrypted index"), "{}", msg)
                }
                _ => panic!("encrypted index of {} bytes accepted", len),
            }
        }
    }

    #[test]
    fn parse_envelope_enforces_the_legacy_minimum_index_length() {
        // A version 1 envelope: header, nonce, the 8 skipped counter bytes,
        // then the encrypted JSON index.
        let mut header = VaultHeader::generate().unwrap();
        header.version = LEGACY_VAULT_VERSION_1;
        let header_json = header.to_aad_bytes().unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        data.extend_from_slice(&header_json);
        data.extend_from_slice(&[0u8; XCHACHA20_NONCE_LEN + 8]);
        let index_start = data.len();
        data.extend_from_slice(&[0u8; MIN_ENCRYPTED_INDEX_LEN_V1]);

        let envelope = parse_envelope(&data).unwrap();
        assert_eq!(envelope.encrypted_index.len(), MIN_ENCRYPTED_INDEX_LEN_V1);
        for len in 0..MIN_ENCRYPTED_INDEX_LEN_V1 {
            assert!(
                matches!(
                    parse_envelope(&data[..index_start + len]),
                    Err(VaultError::CorruptedData(_))
                ),
                "legacy encrypted index of {} bytes accepted",
                len
            );
        }

        // The fixture written by 0.2.1 is far above the floor.
        let fixture = parse_envelope(V1_FIXTURE).unwrap();
        assert!(fixture.encrypted_index.len() > MIN_ENCRYPTED_INDEX_LEN_V1);
    }

    #[test]
    fn open_reports_authentication_failure_at_the_minimum_index_length() {
        // The floor is exact: an index of the minimum length reaches the
        // AEAD, so a forged one fails authentication rather than parsing.
        let password: &[u8] = b"password-floor";
        let mut vault = Vault::create(password).unwrap();
        let mut forged = vault.export().unwrap();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert!(matches!(
            Vault::open(password, &forged),
            Err(VaultError::InvalidPassword)
        ));
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

    /// Re-encodes an edited header value in canonical form (struct field
    /// order), so the edit reaches the AEAD instead of being rejected by
    /// the canonical-form check. `serde_json::Value` alone would emit the
    /// fields in alphabetical order.
    fn canonical_header_json(value: &serde_json::Value) -> Vec<u8> {
        let header: VaultHeader = serde_json::from_value(value.clone()).unwrap();
        header.to_aad_bytes().unwrap()
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
    fn open_rejects_version_downgrade_in_header() {
        // Rewriting a version 2 header as version 1 changes the AAD (and
        // would make the reader skip 8 bytes of ciphertext), so the AEAD
        // must fail: a legacy-format downgrade cannot be forged.
        let valid = make_valid_export(b"password-downgrade");
        let mut value = extract_header_value(&valid);
        value.as_object_mut().unwrap().insert(
            "version".to_string(),
            serde_json::Value::Number(LEGACY_VAULT_VERSION_1.into()),
        );
        let new_json = canonical_header_json(&value);
        let tampered = replace_header_json(&valid, &new_json);
        assert!(matches!(
            Vault::open(b"password-downgrade", &tampered),
            Err(VaultError::InvalidPassword)
        ));
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
    fn open_rejects_header_with_out_of_range_kdf_iterations() {
        let valid = make_valid_export(b"password-iiii");
        let mut value = extract_header_value(&valid);
        value.as_object_mut().unwrap().insert(
            "kdf_iterations".to_string(),
            serde_json::Value::Number((MAX_KDF_ITERATIONS + 1).into()),
        );
        let new_json = serde_json::to_vec(&value).unwrap();
        let tampered = replace_header_json(&valid, &new_json);
        let result = Vault::open(b"password-iiii", &tampered);
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
        let new_json = canonical_header_json(&value);
        let tampered = replace_header_json(&valid, &new_json);
        let result = Vault::open(b"password-hhhh", &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn open_rejects_header_with_unknown_field() {
        // The AAD is the canonical serialization of the parsed header, so an
        // unknown field would be ignored by the parser and never
        // authenticated. It must be rejected before Argon2 runs.
        let valid = make_valid_export(b"password-ffff");
        let mut value = extract_header_value(&valid);
        value.as_object_mut().unwrap().insert(
            "injected".to_string(),
            serde_json::Value::String("unauthenticated".to_string()),
        );
        let new_json = serde_json::to_vec(&value).unwrap();
        let tampered = replace_header_json(&valid, &new_json);
        let result = Vault::open(b"password-ffff", &tampered);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_non_canonical_header_json() {
        // Same fields and values, different bytes (pretty-printed with the
        // same field order): the parsed header would reproduce the original
        // AAD, so the edit would otherwise go unnoticed.
        let valid = make_valid_export(b"password-gggg");
        let header_len = u32::from_le_bytes(valid[..4].try_into().unwrap()) as usize;
        let value = extract_header_value(&valid);
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        assert_ne!(pretty.as_slice(), &valid[4..4 + header_len]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&pretty).unwrap(),
            value
        );
        let tampered = replace_header_json(&valid, &pretty);
        let result = Vault::open(b"password-gggg", &tampered);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
    }

    #[test]
    fn open_rejects_data_above_file_size_cap() {
        // `open` takes bytes from anywhere, so it enforces the same 256 MiB
        // cap as `load`, before parsing anything.
        let data = vec![0u8; MAX_VAULT_FILE_SIZE as usize + 1];
        let result = Vault::open(b"password-hhhh", &data);
        assert!(matches!(result, Err(VaultError::CorruptedData(_))));
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

    // Tampering group C: nonce region tampering. The nonce is part of the
    // AEAD construction; tampering must surface as an AEAD failure.

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

    // Tampering group D: ciphertext region tampering.
    // The ciphertext is XChaCha20-Poly1305 sealed: any modification to
    // either the encrypted payload or the 16-byte authentication tag must
    // cause AEAD verification to fail.

    const POLY1305_TAG_LEN: usize = 16;

    fn ciphertext_offset(export: &[u8]) -> usize {
        let header_len = u32::from_le_bytes(export[..4].try_into().unwrap()) as usize;
        4 + header_len + XCHACHA20_NONCE_LEN
    }

    #[test]
    fn open_rejects_bit_flip_in_ciphertext_body() {
        // Flip a bit at the start of the AEAD ciphertext (before the trailing
        // tag). This targets the encrypted payload, not the tag.
        let password: &[u8] = b"password-llll";
        let valid = make_valid_export(password);
        let ct_start = ciphertext_offset(&valid);
        // Sanity: there must be at least one byte of body before the 16-byte tag.
        assert!(valid.len() > ct_start + POLY1305_TAG_LEN);

        let mut tampered = valid.clone();
        tampered[ct_start] ^= 0x01;

        let result = Vault::open(password, &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn open_rejects_bit_flip_in_poly1305_tag() {
        // Flip a bit in the middle of the 16-byte Poly1305 tag. Distinct from
        // the existing `tampered_export_fails_open` test which flips the very
        // last byte; here we hit a non-edge byte of the tag region.
        let password: &[u8] = b"password-mmmm";
        let valid = make_valid_export(password);
        let tag_mid = valid.len() - POLY1305_TAG_LEN + (POLY1305_TAG_LEN / 2);

        let mut tampered = valid.clone();
        tampered[tag_mid] ^= 0x40;

        let result = Vault::open(password, &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn open_rejects_ciphertext_with_tag_stripped() {
        // Remove the trailing 16-byte Poly1305 tag entirely. AEAD must reject.
        let password: &[u8] = b"password-nnnn";
        let valid = make_valid_export(password);
        let truncated = &valid[..valid.len() - POLY1305_TAG_LEN];

        let result = Vault::open(password, truncated);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn open_rejects_ciphertext_with_trailing_garbage_appended() {
        // Append junk after the tag. Without the original tag positioned at
        // end-of-input, AEAD verification reads the wrong bytes as the tag
        // and fails.
        let password: &[u8] = b"password-oooo";
        let valid = make_valid_export(password);

        let mut tampered = valid.clone();
        tampered.extend_from_slice(&[0xAB, 0xCD, 0xEF]);

        let result = Vault::open(password, &tampered);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    // Tampering group E: authenticated but out-of-bounds indexes.
    // `open()` must reject an index whose decoded contents exceed the format
    // bounds, even though the bytes are validly sealed under the correct
    // key. This guards against a crafted index forcing a larger in-memory
    // map or larger blobs than the format allows.

    /// Forges a vault export whose encrypted index holds exactly `entries`
    /// (declaring `declared_count` of them), sealed correctly under the key
    /// derived from `password`. Entries must use `data_counter` 0.
    fn forge_export(
        password: &[u8],
        declared_count: u32,
        entries: &[([u8; ENTRY_KEY_LEN], IndexEntry)],
    ) -> Vec<u8> {
        use crate::vault::index_codec::tests::raw_encode;

        let header = VaultHeader::generate().unwrap();
        let master_key = master_key_for(password, &header);
        let mut enc_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        let mut hmac_sub = Zeroizing::new([0u8; SUBKEY_LEN]);
        derive_subkeys(
            master_key.as_slice(),
            &header.kdf_salt,
            &mut enc_sub,
            &mut hmac_sub,
        )
        .unwrap();

        // Any unique nonce works: open() reads the nonce from the file and
        // never re-derives it.
        let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
        secure_bytes_fill(&mut nonce).unwrap();

        // All forged entries use data_counter 0, so data_nonce_counter must be
        // at least 1 to satisfy the counter invariant enforced on open.
        let index_bytes = raw_encode(
            crate::constants::vault_index_constants::VAULT_INDEX_VERSION,
            1,
            1,
            declared_count,
            entries,
        );

        let aad = header.to_aad_bytes().unwrap();
        let mut encrypted_index = vec![0u8; index_bytes.len() + POLY1305_OUTSIZE];
        seal_into(&enc_sub, &nonce, &index_bytes, &aad, &mut encrypted_index).unwrap();

        let header_json = serde_json::to_vec(&header).unwrap();
        let mut output = Vec::new();
        output.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        output.extend_from_slice(&header_json);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&encrypted_index);
        output
    }

    fn forge_export_with_entries(password: &[u8], entry_count: usize) -> Vec<u8> {
        use crate::vault::index_codec::tests::entry;
        let entries: Vec<([u8; ENTRY_KEY_LEN], IndexEntry)> = (0..entry_count)
            .map(|i| {
                let mut key = [0u8; ENTRY_KEY_LEN];
                key[..8].copy_from_slice(&(i as u64).to_le_bytes());
                (key, entry(0, MIN_ENCRYPTED_LEN, MIN_ENCRYPTED_LEN))
            })
            .collect();
        forge_export(password, entry_count as u32, &entries)
    }

    #[test]
    fn open_accepts_index_at_entry_cap() {
        let password: &[u8] = b"password-cap-ok";
        let max = crate::constants::vault_index_constants::MAX_INDEX_ENTRIES;
        let data = forge_export_with_entries(password, max);
        // Sealed correctly and at the cap: open must succeed.
        let vault = Vault::open(password, &data).unwrap();
        assert_eq!(vault.index.files.len(), max);
    }

    #[test]
    fn open_rejects_index_over_entry_cap() {
        let password: &[u8] = b"password-cap-no";
        let max = crate::constants::vault_index_constants::MAX_INDEX_ENTRIES;
        let data = forge_export_with_entries(password, max + 1);
        // One past the cap: open must reject as corrupted, not build the map.
        assert!(matches!(
            Vault::open(password, &data),
            Err(VaultError::CorruptedData(_))
        ));
    }

    #[test]
    fn open_rejects_entry_name_ciphertext_over_bound() {
        use crate::vault::index_codec::tests::entry;
        let password: &[u8] = b"password-name-big";
        let entries = [(
            [1u8; ENTRY_KEY_LEN],
            entry(0, MAX_ENCRYPTED_NAME_LEN + 1, MIN_ENCRYPTED_LEN),
        )];
        let data = forge_export(password, 1, &entries);
        assert!(matches!(
            Vault::open(password, &data),
            Err(VaultError::CorruptedData(_))
        ));
    }

    #[test]
    fn open_accepts_entry_ciphertexts_at_bound() {
        use crate::vault::index_codec::tests::entry;
        // Sizes exactly at the bound pass the structural check; the blobs
        // are garbage, so a later retrieve fails on the AEAD, not on open.
        let password: &[u8] = b"password-name-max";
        let entries = [(
            [1u8; ENTRY_KEY_LEN],
            entry(0, MAX_ENCRYPTED_NAME_LEN, MIN_ENCRYPTED_LEN),
        )];
        let data = forge_export(password, 1, &entries);
        let vault = Vault::open(password, &data).unwrap();
        assert_eq!(vault.index.files.len(), 1);
    }

    #[test]
    fn open_rejects_index_with_trailing_bytes() {
        use crate::vault::index_codec::tests::entry;
        // Declares one entry but carries two: the decoder must not ignore
        // the bytes after the last declared entry.
        let password: &[u8] = b"password-trailing";
        let entries = [
            (
                [1u8; ENTRY_KEY_LEN],
                entry(0, MIN_ENCRYPTED_LEN, MIN_ENCRYPTED_LEN),
            ),
            (
                [2u8; ENTRY_KEY_LEN],
                entry(0, MIN_ENCRYPTED_LEN, MIN_ENCRYPTED_LEN),
            ),
        ];
        let data = forge_export(password, 1, &entries);
        assert!(matches!(
            Vault::open(password, &data),
            Err(VaultError::CorruptedData(_))
        ));
    }

    // Group F: export size bound and nonce freshness.

    #[test]
    fn export_size_validation_boundary() {
        assert!(validate_export_size(MAX_VAULT_FILE_SIZE).is_ok());
        assert!(matches!(
            validate_export_size(MAX_VAULT_FILE_SIZE + 1),
            Err(VaultError::SerializationError(_))
        ));
    }

    /// Slowest test in the suite (tens of seconds in debug, several hundred
    /// MiB of memory): it fills a vault just above the 256 MiB cap to pin
    /// the guarantee end to end. The binary index adds only a few bytes per
    /// entry, so four entries of the maximum size are needed. The oversized
    /// export itself is refused from the computed size, before anything is
    /// encoded; the memory goes to the entries and to the export that
    /// succeeds afterwards.
    #[test]
    fn export_rejects_vault_exceeding_max_file_size() {
        fn pseudo_bytes(len: usize, seed: u64) -> Vec<u8> {
            (0..len)
                .map(|i| ((i as u64 ^ seed).wrapping_mul(2654435761) >> 7) as u8)
                .collect()
        }

        let mut vault = Vault::create(b"password-size-cap").unwrap();
        for (i, name) in ["a", "b", "c", "d"].iter().enumerate() {
            let payload = Zeroizing::new(pseudo_bytes(MAX_ENTRY_DATA_SIZE, i as u64 + 1));
            vault.store(name, &payload).unwrap();
        }

        let nonce_before = vault.index.nonce;
        let nonce_counter_before = vault.index.nonce_counter;
        assert!(matches!(
            vault.export(),
            Err(VaultError::SerializationError(_))
        ));
        // The refusal leaves the vault exactly as it was: the index nonce
        // and its counter have not moved.
        assert_eq!(vault.index.nonce, nonce_before);
        assert_eq!(vault.index.nonce_counter, nonce_counter_before);

        // The vault stays intact and usable: dropping one entry brings the
        // export back under the cap.
        assert!(vault.remove("d").unwrap());
        let exported = vault.export().unwrap();
        assert!(exported.len() as u64 <= MAX_VAULT_FILE_SIZE);
        assert_eq!(vault.index.nonce_counter, nonce_counter_before + 1);
        let reopened = Vault::open(b"password-size-cap", &exported).unwrap();
        assert_eq!(
            reopened.with_secret("a", |p| p.len()).unwrap(),
            Some(MAX_ENTRY_DATA_SIZE)
        );
    }

    #[test]
    fn storing_same_name_twice_uses_fresh_nonces() {
        // Entry nonces are random per store(), never a function of the
        // counter alone; re-storing a name must produce new nonce prefixes.
        let mut vault = Vault::create(b"password-nonces").unwrap();
        vault.store("k", b"v1").unwrap();
        let first: Vec<Vec<u8>> = vault
            .index
            .files
            .values()
            .map(|e| e.encrypted_data[..XCHACHA20_NONCE_LEN].to_vec())
            .collect();
        vault.store("k", b"v1").unwrap();
        let second: Vec<Vec<u8>> = vault
            .index
            .files
            .values()
            .map(|e| e.encrypted_data[..XCHACHA20_NONCE_LEN].to_vec())
            .collect();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_ne!(first[0], second[0]);
    }

    // Group G: change_password with an inconsistent in-memory entry.

    #[test]
    fn change_password_rejects_entry_with_undersized_ciphertext() {
        let mut vault = Vault::create(b"old-password").unwrap();
        vault.store("real", b"payload").unwrap();
        // An entry whose name blob cannot even hold a nonce: the index is
        // inconsistent and the password change must fail, not silently drop.
        // (The decoders never produce such an entry; this is the in-memory
        // guard.)
        vault.index.files.insert(
            format!("{:064x}", 1),
            IndexEntry {
                data_counter: 0,
                encrypted_name: vec![0u8; 3],
                encrypted_data: vec![0u8; 40],
            },
        );

        assert!(matches!(
            vault.change_password(b"old-password", b"new-password"),
            Err(VaultError::CorruptedData(_))
        ));
        // The failed change leaves the original vault usable.
        assert_eq!(vault.retrieve("real").unwrap(), Some(b"payload".to_vec()));
    }
}
