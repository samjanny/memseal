#![allow(unsafe_code)]
use crate::constants::SECURE_MEMORY_VAULT_CHUNK_SIZE;
use crate::mem::secure_memory_vault::MemoryVaultError::GenericError;
use memsec::{mlock, munlock};
use orion::hazardous::aead::streaming::{StreamTag, StreamXChaCha20Poly1305};
use orion::hazardous::stream::chacha20::SecretKey;
use orion::hazardous::stream::xchacha20::Nonce;
use std::fmt::Debug;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use thiserror::Error;
use zeroize::Zeroize;

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
/// The vault encrypts data in chunks and locks the memory to prevent it from being swapped to disk.
pub struct SecureMemoryVault {
    key: SecretKey,
    nonce: Nonce,
    ciphertext: Vec<u8>,
    chunk_size: usize,
    plaintext_len: usize,
    /// Saved at construction time so Drop can munlock even after zeroize clears the Vec.
    ciphertext_ptr: *mut u8,
    ciphertext_capacity: usize,
    is_locked: AtomicBool,
    sync: Mutex<()>,
}

// SAFETY: SecureMemoryVault already uses a Mutex for interior synchronization,
// and ciphertext_ptr/ciphertext_capacity are only used in Drop (single-threaded).
unsafe impl Send for SecureMemoryVault {}
unsafe impl Sync for SecureMemoryVault {}

impl SecureMemoryVault {
    /// Encrypts `plaintext` in memory using streaming XChaCha20-Poly1305 and locks the ciphertext with `mlock`.
    pub fn new(plaintext: &[u8]) -> Result<Self, MemoryVaultError> {
        if plaintext.is_empty() {
            return Ok(Self {
                key: SecretKey::generate(),
                nonce: Nonce::generate(),
                ciphertext: Vec::new(),
                chunk_size: SECURE_MEMORY_VAULT_CHUNK_SIZE,
                plaintext_len: 0,
                ciphertext_ptr: std::ptr::null_mut(),
                ciphertext_capacity: 0,
                is_locked: AtomicBool::new(false),
                sync: Mutex::new(()),
            });
        }

        let plaintext_len = plaintext.len();
        let key = SecretKey::generate();
        let nonce = Nonce::generate();

        let chunk_size = SECURE_MEMORY_VAULT_CHUNK_SIZE;
        let num_chunks = plaintext.len().div_ceil(chunk_size);
        let total_ct_len = plaintext.len() + num_chunks * 17;
        let mut ciphertext = vec![0u8; total_ct_len];
        let mut encr = StreamXChaCha20Poly1305::new(&key, &nonce);
        let mut ct_offset = 0;

        for (i, chunk) in plaintext.chunks(chunk_size).enumerate() {
            let tag = if i + 1 == num_chunks {
                StreamTag::Finish
            } else {
                StreamTag::Message
            };
            let out_len = chunk.len() + 17;
            encr.seal_chunk(
                chunk,
                None,
                &mut ciphertext[ct_offset..ct_offset + out_len],
                &tag,
            )
            .map_err(|_| MemoryVaultError::Crypto)?;
            ct_offset += out_len;
        }

        if !unsafe { mlock(ciphertext.as_mut_ptr(), ciphertext.len()) } {
            return Err(MemoryVaultError::Lock);
        }

        let ciphertext_ptr = ciphertext.as_mut_ptr();
        let ciphertext_capacity = ciphertext.len();

        Ok(Self {
            key,
            nonce,
            ciphertext,
            chunk_size,
            plaintext_len,
            ciphertext_ptr,
            ciphertext_capacity,
            is_locked: AtomicBool::new(true),
            sync: Mutex::new(()),
        })
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

    /// Decrypts the data and passes each chunk to `f`. Output buffer is zeroized even on error.
    pub fn access<F>(&self, mut f: F) -> Result<(), MemoryVaultError>
    where
        F: FnMut(&[u8], StreamTag) -> Result<(), MemoryVaultError>,
    {
        if self.ciphertext.is_empty() {
            return f(&self.ciphertext, StreamTag::Finish);
        }
        let _g = self
            .sync
            .lock()
            .map_err(|_| MemoryVaultError::MutexLockFailed)?;

        let mut reader = StreamXChaCha20Poly1305::new(&self.key, &self.nonce);
        let mut offset = 0;

        let buf_size = self.plaintext_len.min(self.chunk_size);
        let mut out = vec![0u8; buf_size];

        let result = (|| -> Result<(), MemoryVaultError> {
            while offset < self.ciphertext.len() {
                let remaining = self.ciphertext.len() - offset;
                let chunk_len = if remaining > self.chunk_size + 17 {
                    self.chunk_size + 17
                } else {
                    remaining
                };
                let ct_chunk = &self.ciphertext[offset..offset + chunk_len];
                offset += chunk_len;
                let out_len = chunk_len - 17;
                let tag = reader
                    .open_chunk(ct_chunk, None, &mut out[..out_len])
                    .map_err(|_| MemoryVaultError::Crypto)?;

                f(&out[..out_len], tag)?;
            }
            Ok(())
        })();

        out.zeroize();
        result
    }

    /// Returns `true` if the ciphertext memory is currently mlock'd.
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
        let ptr = self.ciphertext_ptr;
        let len = self.ciphertext_capacity;

        self.ciphertext.zeroize();
        std::sync::atomic::compiler_fence(Ordering::SeqCst);

        // munlock using the saved pointer/length — zeroize clears the Vec
        // so we can't rely on ciphertext.as_ptr()/len() after zeroize.
        if was_locked && !ptr.is_null() && len > 0 {
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

    use crate::mem::secure_memory_vault::{MemoryVaultError, SecureMemoryVault};
    use orion::aead::streaming::StreamTag;
    use std::sync::{Arc, Barrier};
    use std::thread;

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
        // Corrupt the ciphertext
        if !vault.ciphertext.is_empty() {
            vault.ciphertext[0] ^= 0xFF;
        }
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
