#![allow(unsafe_code)]
//! In-memory container for the vault's 32-byte subkeys.
//!
//! The plaintext is encrypted with a fresh streaming XChaCha20-Poly1305 key
//! and kept in one heap allocation together with that key and its nonce. The
//! whole allocation is `mlock`'d for the container's lifetime (on Linux
//! `memsec` also excludes it from core dumps) and zeroized on drop, so the
//! key that decrypts the buffer gets the same protection as the buffer.
use crate::constants::SECURE_MEMORY_VAULT_CHUNK_SIZE;
use crate::crypto::utils::secure_bytes_fill;
use crate::mem::secure_memory_vault::MemoryVaultError::GenericError;
use memsec::{mlock, munlock};
use orion::hazardous::aead::streaming::{ABYTES, StreamTag, StreamXChaCha20Poly1305};
use orion::hazardous::stream::chacha20::{CHACHA_KEYSIZE, SecretKey};
use orion::hazardous::stream::xchacha20::{Nonce, XCHACHA_NONCESIZE};
use std::fmt::Debug;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Offset of the stream nonce inside the locked region (right after the key).
const NONCE_OFFSET: usize = CHACHA_KEYSIZE;
/// Offset of the first ciphertext chunk inside the locked region.
const CIPHERTEXT_OFFSET: usize = CHACHA_KEYSIZE + XCHACHA_NONCESIZE;

/// Errors that can occur in the `SecureMemoryVault`.
#[derive(Debug, Error)]
pub enum MemoryVaultError {
    /// Error during cryptographic operations.
    #[error("crypto error")]
    Crypto,
    /// Error when locking memory using `mlock`.
    #[error("memsec lock failed")]
    Lock,
    /// Error when unlocking memory using `munlock`.
    #[error("memsec unlock failed")]
    Unlock,
    /// Error when acquiring a mutex lock.
    #[error("mutex lock failed")]
    MutexLockFailed,
    #[error("Generic error: {0}")]
    GenericError(String),
}

impl From<&'static str> for MemoryVaultError {
    fn from(error: &'static str) -> Self {
        MemoryVaultError::GenericError(error.to_string())
    }
}

/// A secure memory vault for encrypting and storing sensitive data in memory.
///
/// Layout of `region`, a single `mlock`'d allocation:
///
/// ```text
/// [ stream key (32) | stream nonce (24) | ciphertext chunk 0 | chunk 1 | ... ]
/// ```
///
/// Each ciphertext chunk carries the streaming AEAD's 17-byte overhead. The
/// region is empty when the plaintext was empty. No raw pointers are kept, so
/// `Send` and `Sync` follow from the field types without `unsafe impl`s.
pub struct SecureMemoryVault {
    region: Vec<u8>,
    /// Length passed to `mlock`, reused for `munlock` in `Drop`.
    locked_len: usize,
    chunk_size: usize,
    plaintext_len: usize,
    is_locked: AtomicBool,
    sync: Mutex<()>,
}

impl SecureMemoryVault {
    /// Encrypts `plaintext` in memory using streaming XChaCha20-Poly1305 and
    /// keeps key, nonce, and ciphertext in one `mlock`'d allocation.
    pub fn new(plaintext: &[u8]) -> Result<Self, MemoryVaultError> {
        let chunk_size = SECURE_MEMORY_VAULT_CHUNK_SIZE;
        if plaintext.is_empty() {
            return Ok(Self {
                region: Vec::new(),
                locked_len: 0,
                chunk_size,
                plaintext_len: 0,
                is_locked: AtomicBool::new(false),
                sync: Mutex::new(()),
            });
        }

        let num_chunks = plaintext.len().div_ceil(chunk_size);
        let region_len = CIPHERTEXT_OFFSET + plaintext.len() + num_chunks * ABYTES;
        let mut vault = Self {
            region: vec![0u8; region_len],
            locked_len: 0,
            chunk_size,
            plaintext_len: plaintext.len(),
            is_locked: AtomicBool::new(false),
            sync: Mutex::new(()),
        };

        // Lock before any secret is written so the stream key never touches
        // an unlocked page. The region holds only zeros at this point, so a
        // failure here can simply drop it.
        if !unsafe { mlock(vault.region.as_mut_ptr(), region_len) } {
            return Err(MemoryVaultError::Lock);
        }
        vault.locked_len = region_len;
        vault.is_locked.store(true, Ordering::SeqCst);

        // From here on any error drops `vault`, whose Drop zeroizes and
        // unlocks the region.
        vault.seal_into_region(plaintext)?;
        Ok(vault)
    }

    /// Generates the stream key and nonce directly inside the locked region
    /// and seals `plaintext` after them, chunk by chunk.
    fn seal_into_region(&mut self, plaintext: &[u8]) -> Result<(), MemoryVaultError> {
        let chunk_size = self.chunk_size;
        let (prefix, ciphertext) = self.region.split_at_mut(CIPHERTEXT_OFFSET);
        let (key_bytes, nonce_bytes) = prefix.split_at_mut(NONCE_OFFSET);
        secure_bytes_fill(key_bytes)?;
        secure_bytes_fill(nonce_bytes)?;

        // orion copies the key into its own (zeroize-on-drop) types for the
        // duration of the operation; the long-lived copy stays in the region.
        let key = SecretKey::from_slice(key_bytes).map_err(|_| MemoryVaultError::Crypto)?;
        let nonce = Nonce::from_slice(nonce_bytes).map_err(|_| MemoryVaultError::Crypto)?;
        let mut encr = StreamXChaCha20Poly1305::new(&key, &nonce);

        let num_chunks = plaintext.len().div_ceil(chunk_size);
        let mut ct_offset = 0;
        for (i, chunk) in plaintext.chunks(chunk_size).enumerate() {
            let tag = if i + 1 == num_chunks {
                StreamTag::Finish
            } else {
                StreamTag::Message
            };
            let out_len = chunk.len() + ABYTES;
            encr.seal_chunk(
                chunk,
                None,
                &mut ciphertext[ct_offset..ct_offset + out_len],
                &tag,
            )
            .map_err(|_| MemoryVaultError::Crypto)?;
            ct_offset += out_len;
        }
        Ok(())
    }

    /// Creates a vault from a closure that produces key material, zeroizing it after encryption.
    pub fn safe_new<F, const N: usize>(f: F) -> Result<Self, MemoryVaultError>
    where
        F: FnOnce() -> Result<[u8; N], &'static str>,
    {
        let mut key = f().map_err(|e| GenericError(e.to_string()))?;
        let result = Self::new(&key);
        key.zeroize();
        result
    }

    /// Decrypts the data and passes each chunk to `f`.
    ///
    /// The plaintext scratch buffer is wrapped in `Zeroizing`, so it is wiped
    /// when this function returns, on error, and when `f` panics and unwinds.
    pub fn access<F>(&self, mut f: F) -> Result<(), MemoryVaultError>
    where
        F: FnMut(&[u8], StreamTag) -> Result<(), MemoryVaultError>,
    {
        if self.plaintext_len == 0 {
            return f(&[], StreamTag::Finish);
        }
        let _g = self
            .sync
            .lock()
            .map_err(|_| MemoryVaultError::MutexLockFailed)?;

        let key = SecretKey::from_slice(&self.region[..NONCE_OFFSET])
            .map_err(|_| MemoryVaultError::Crypto)?;
        let nonce = Nonce::from_slice(&self.region[NONCE_OFFSET..CIPHERTEXT_OFFSET])
            .map_err(|_| MemoryVaultError::Crypto)?;
        let mut reader = StreamXChaCha20Poly1305::new(&key, &nonce);
        let ciphertext = &self.region[CIPHERTEXT_OFFSET..];

        let buf_size = self.plaintext_len.min(self.chunk_size);
        let mut out = Zeroizing::new(vec![0u8; buf_size]);

        let mut offset = 0;
        while offset < ciphertext.len() {
            let remaining = ciphertext.len() - offset;
            let chunk_len = remaining.min(self.chunk_size + ABYTES);
            let ct_chunk = &ciphertext[offset..offset + chunk_len];
            offset += chunk_len;
            let out_len = chunk_len - ABYTES;
            let tag = reader
                .open_chunk(ct_chunk, None, &mut out[..out_len])
                .map_err(|_| MemoryVaultError::Crypto)?;

            f(&out[..out_len], tag)?;
        }
        Ok(())
    }

    /// Returns `true` if the region holding key, nonce, and ciphertext is currently mlock'd.
    pub fn is_locked(&self) -> bool {
        self.is_locked.load(Ordering::SeqCst)
    }

    /// Returns the length of the original plaintext in bytes.
    pub fn len(&self) -> usize {
        self.plaintext_len
    }

    /// Returns `true` if the vault holds no plaintext data.
    pub fn is_empty(&self) -> bool {
        self.plaintext_len == 0
    }
}

impl Drop for SecureMemoryVault {
    fn drop(&mut self) {
        let was_locked = self.is_locked.swap(false, Ordering::SeqCst);
        let ptr = self.region.as_mut_ptr();
        let len = self.locked_len;

        // Wipe while the pages are still locked. Vec::zeroize clears the
        // whole capacity in place without reallocating, so `ptr` remains
        // valid for the munlock below.
        self.region.zeroize();
        std::sync::atomic::compiler_fence(Ordering::SeqCst);

        if was_locked && len > 0 {
            unsafe { munlock(ptr, len) };
        }
    }
}

impl Debug for SecureMemoryVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureMemoryVault")
            .field("content", &"[REDACTED]")
            .field("length", &"[REDACTED]")
            .field("is_locked", &self.is_locked())
            .finish()
    }
}

#[cfg(test)]
mod tests {

    use super::{ABYTES, CIPHERTEXT_OFFSET};
    use crate::mem::secure_memory_vault::{MemoryVaultError, SecureMemoryVault};
    use orion::aead::streaming::StreamTag;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_send_and_sync_hold_without_unsafe_impls() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SecureMemoryVault>();
    }

    #[test]
    fn test_region_holds_key_nonce_and_ciphertext_and_is_locked() {
        let data = b"abcd";
        let vault = SecureMemoryVault::new(data).unwrap();
        assert_eq!(vault.region.len(), CIPHERTEXT_OFFSET + data.len() + ABYTES);
        assert_eq!(vault.locked_len, vault.region.len());
        assert!(vault.is_locked());
        // The key and nonce were generated in place: not all zeros.
        assert!(vault.region[..CIPHERTEXT_OFFSET].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_empty_plaintext_has_no_region_and_is_not_locked() {
        let vault = SecureMemoryVault::new(b"").unwrap();
        assert!(vault.region.is_empty());
        assert_eq!(vault.locked_len, 0);
        assert!(!vault.is_locked());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"This is a very important secret message!";
        let vault = SecureMemoryVault::new(data).expect("Vault creation failed");

        let mut result = Vec::new();
        vault
            .access(|chunk, tag| {
                result.extend_from_slice(chunk);
                assert_eq!(tag, StreamTag::Finish);
                Ok(())
            })
            .expect("Vault access failed");

        assert_eq!(result, data);
    }

    #[test]
    fn test_large_data_chunked() {
        let data = vec![42u8; 10_000];
        let vault = SecureMemoryVault::new(&data).expect("Vault creation failed");

        let chunks_num = data.len().div_ceil(vault.chunk_size);
        let mut count = 0;
        let mut total = 0;
        vault
            .access(|chunk, tag| {
                count += 1;
                total += chunk.len();
                if count < chunks_num {
                    assert_eq!(tag, StreamTag::Message, "Expected Message tag");
                } else {
                    assert_eq!(tag, StreamTag::Finish, "Expected Finish tag");
                }
                Ok(())
            })
            .expect("Vault access failed");

        assert!(count > 1, "Should process in multiple chunks");
        assert_eq!(total, data.len());
    }

    #[test]
    fn test_callback_error_propagation() {
        let data = b"test";
        let vault = SecureMemoryVault::new(data).unwrap();

        let err = vault.access(|_, _| Err(MemoryVaultError::Crypto));
        assert!(matches!(err, Err(MemoryVaultError::Crypto)));
    }

    #[test]
    fn test_integrity_failure() {
        let data = b"test";
        let mut vault = SecureMemoryVault::new(data).unwrap();
        // Corrupt the first ciphertext byte after the key and nonce.
        vault.region[CIPHERTEXT_OFFSET] ^= 0xFF;
        let err = vault.access(|_, _| Ok(()));
        assert!(matches!(err, Err(MemoryVaultError::Crypto)));
    }

    #[test]
    fn test_concurrent_access() {
        let data = b"concurrent test data";
        let vault = Arc::new(SecureMemoryVault::new(data).unwrap());
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut buf = Vec::new();
                vault
                    .access(|chunk, _| {
                        buf.extend_from_slice(chunk);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(buf, data);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_len() {
        let data = b"1234567890";
        let vault = SecureMemoryVault::new(data).unwrap();
        assert_eq!(vault.len(), data.len());
    }

    #[test]
    fn test_empty_plaintext() {
        let data = b"";
        let vault = SecureMemoryVault::new(data).unwrap();
        let mut buf = Vec::new();
        vault
            .access(|chunk, _| {
                buf.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(buf, data);
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn test_orion_stream_minimal() {
        use orion::hazardous::aead::streaming::{StreamTag, StreamXChaCha20Poly1305};
        use orion::hazardous::stream::chacha20::SecretKey;
        use orion::hazardous::stream::xchacha20::Nonce;

        let key = SecretKey::generate();
        let nonce = Nonce::generate();
        let mut encr = StreamXChaCha20Poly1305::new(&key, &nonce);

        let pt = b"test";
        let mut ct = vec![0u8; pt.len() + 17];
        let tag = StreamTag::Finish;
        let res = encr.seal_chunk(pt, None, &mut ct, &tag);
        println!("seal_chunk result: {:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_safe_new_success() {
        let vault = SecureMemoryVault::safe_new(|| {
            // Generate a valid key
            Ok([1u8; 32])
        });

        assert!(vault.is_ok());
    }
}
