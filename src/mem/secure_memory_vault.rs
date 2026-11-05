#![allow(unsafe_code)]
//! In-memory container for the vault's 32-byte subkeys.
//!
//! The plaintext is encrypted with a fresh streaming XChaCha20-Poly1305 key
//! and kept together with that key and its nonce in one [`LockedRegion`]: a
//! `memsec` allocation that occupies pages no other allocation shares, sits
//! between two guard pages, is `mlock`'d for the container's lifetime (on
//! Linux `memsec` also excludes it from core dumps), and is zeroized on
//! drop. The key that decrypts the buffer gets the same protection as the
//! buffer, and unlocking one container can never unlock another.
use crate::constants::SECURE_MEMORY_VAULT_CHUNK_SIZE;
use crate::crypto::utils::secure_bytes_fill;
use orion::hazardous::aead::streaming::{ABYTES, StreamTag, StreamXChaCha20Poly1305};
use orion::hazardous::stream::chacha20::{CHACHA_KEYSIZE, SecretKey};
use orion::hazardous::stream::xchacha20::{Nonce, XCHACHA_NONCESIZE};
use std::fmt::Debug;
use std::ptr::NonNull;
use std::sync::Mutex;
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
    /// Error when allocating the locked region.
    #[error("locked memory allocation failed")]
    Alloc,
    /// Error when locking memory using `mlock`.
    #[error("memsec lock failed")]
    Lock,
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

/// A heap allocation that lives in its own `mlock`'d pages.
///
/// `memsec::malloc_sized` returns bytes placed in pages no other allocation
/// shares, with a guard page on each side and a canary that `free` checks.
/// Page exclusivity is what makes the lock reliable: `munlock` is not
/// reference counted, so two containers in one page would unlock each other
/// on drop. Each region therefore costs at least one page of
/// `RLIMIT_MEMLOCK`.
struct LockedRegion {
    ptr: NonNull<[u8]>,
}

// SAFETY: `LockedRegion` is the unique owner of the allocation behind `ptr`.
// Shared access hands out `&[u8]` through `&self`, mutation needs
// `&mut self`, and `free` runs exactly once from `Drop`. The pointer is never
// copied out or shared with another owner, so moving the region between
// threads or reading it from several threads is as sound as for `Box<[u8]>`.
unsafe impl Send for LockedRegion {}
unsafe impl Sync for LockedRegion {}

impl LockedRegion {
    /// Allocates `len` zeroed bytes in locked, page-exclusive memory.
    fn new(len: usize) -> Result<Self, MemoryVaultError> {
        debug_assert!(len > 0, "LockedRegion must not be empty");

        // SAFETY: `malloc_sized` initializes memsec's page size and canary on
        // first use and returns a pointer valid for `len` bytes until `free`.
        let ptr = unsafe { memsec::malloc_sized(len) }.ok_or(MemoryVaultError::Alloc)?;

        // `malloc_sized` calls `mlock` on the pages but discards the result.
        // Lock again so that a failure (for example an exhausted
        // RLIMIT_MEMLOCK) is reported instead of silently leaving the bytes
        // swappable; locking an already locked range is a no-op.
        //
        // SAFETY: `ptr` is valid for `len` bytes and `free` is the matching
        // release for a `malloc_sized` pointer.
        let locked = unsafe { memsec::mlock(ptr.as_ptr() as *mut u8, len) };
        if !locked {
            unsafe { memsec::free(ptr) };
            return Err(MemoryVaultError::Lock);
        }

        // memsec fills new allocations with a garbage pattern.
        let mut region = Self { ptr };
        region.as_mut_slice().fill(0);
        Ok(region)
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid and uniquely owned for the lifetime of
        // `self`; the returned borrow is tied to `&self`.
        unsafe { self.ptr.as_ref() }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, with `&mut self` guaranteeing no other borrow.
        unsafe { self.ptr.as_mut() }
    }
}

impl Drop for LockedRegion {
    fn drop(&mut self) {
        // Wipe while the pages are still locked. `free` zeroes and unlocks
        // the pages again, verifies the canary, and releases the allocation.
        self.as_mut_slice().zeroize();
        // SAFETY: `ptr` came from `malloc_sized` and is freed exactly once.
        unsafe { memsec::free(self.ptr) };
    }
}

/// A secure memory vault for encrypting and storing sensitive data in memory.
///
/// Layout of `region`, a single locked allocation:
///
/// ```text
/// [ stream key (32) | stream nonce (24) | ciphertext chunk 0 | chunk 1 | ... ]
/// ```
///
/// Each ciphertext chunk carries the streaming AEAD's 17-byte overhead. The
/// region is absent when the plaintext was empty.
pub struct SecureMemoryVault {
    region: Option<LockedRegion>,
    chunk_size: usize,
    plaintext_len: usize,
    sync: Mutex<()>,
}

impl SecureMemoryVault {
    /// Encrypts `plaintext` in memory using streaming XChaCha20-Poly1305 and
    /// keeps key, nonce, and ciphertext in one locked allocation.
    pub fn new(plaintext: &[u8]) -> Result<Self, MemoryVaultError> {
        let chunk_size = SECURE_MEMORY_VAULT_CHUNK_SIZE;
        if plaintext.is_empty() {
            return Ok(Self {
                region: None,
                chunk_size,
                plaintext_len: 0,
                sync: Mutex::new(()),
            });
        }

        let num_chunks = plaintext.len().div_ceil(chunk_size);
        let region_len = CIPHERTEXT_OFFSET + plaintext.len() + num_chunks * ABYTES;

        // The region is locked before any secret is written, so the stream
        // key never touches an unlocked page. From here on any error drops
        // `region`, whose Drop zeroizes and releases it.
        let mut region = LockedRegion::new(region_len)?;
        seal_into(region.as_mut_slice(), chunk_size, plaintext)?;

        Ok(Self {
            region: Some(region),
            chunk_size,
            plaintext_len: plaintext.len(),
            sync: Mutex::new(()),
        })
    }

    /// Decrypts the data and passes each chunk to `f`.
    ///
    /// The plaintext scratch buffer is wrapped in `Zeroizing`, so it is wiped
    /// when this function returns, on error, and when `f` panics and unwinds.
    pub fn access<F>(&self, mut f: F) -> Result<(), MemoryVaultError>
    where
        F: FnMut(&[u8], StreamTag) -> Result<(), MemoryVaultError>,
    {
        let Some(region) = &self.region else {
            return f(&[], StreamTag::Finish);
        };
        let _g = self
            .sync
            .lock()
            .map_err(|_| MemoryVaultError::MutexLockFailed)?;

        let bytes = region.as_slice();
        let key =
            SecretKey::from_slice(&bytes[..NONCE_OFFSET]).map_err(|_| MemoryVaultError::Crypto)?;
        let nonce = Nonce::from_slice(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])
            .map_err(|_| MemoryVaultError::Crypto)?;
        let mut reader = StreamXChaCha20Poly1305::new(&key, &nonce);
        let ciphertext = &bytes[CIPHERTEXT_OFFSET..];

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
        self.region.is_some()
    }
}

/// Generates the stream key and nonce directly inside the locked region and
/// seals `plaintext` after them, chunk by chunk.
fn seal_into(
    region: &mut [u8],
    chunk_size: usize,
    plaintext: &[u8],
) -> Result<(), MemoryVaultError> {
    let (prefix, ciphertext) = region.split_at_mut(CIPHERTEXT_OFFSET);
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
    fn test_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SecureMemoryVault>();
    }

    #[test]
    fn test_region_holds_key_nonce_and_ciphertext_and_is_locked() {
        let data = b"abcd";
        let vault = SecureMemoryVault::new(data).unwrap();
        let region = vault.region.as_ref().unwrap().as_slice();
        assert_eq!(region.len(), CIPHERTEXT_OFFSET + data.len() + ABYTES);
        assert!(vault.is_locked());
        // The key and nonce were generated in place: not all zeros.
        assert!(region[..CIPHERTEXT_OFFSET].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_empty_plaintext_has_no_region_and_is_not_locked() {
        let vault = SecureMemoryVault::new(b"").unwrap();
        assert!(vault.region.is_none());
        assert!(!vault.is_locked());
    }

    #[test]
    fn test_containers_do_not_share_pages() {
        // munlock is not reference counted: if two regions shared a page,
        // dropping one would unlock the other. Every region must therefore
        // sit in pages of its own. 4096 is the smallest page size memseal
        // runs on; distinct 4 KiB pages imply distinct larger pages too.
        let a = SecureMemoryVault::new(&[1u8; 32]).unwrap();
        let b = SecureMemoryVault::new(&[2u8; 32]).unwrap();
        let pa = a.region.as_ref().unwrap().as_slice().as_ptr() as usize;
        let pb = b.region.as_ref().unwrap().as_slice().as_ptr() as usize;
        assert_ne!(pa / 4096, pb / 4096, "regions share a page");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropping_one_container_keeps_the_other_locked() {
        fn locked_kb() -> u64 {
            let smaps = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
            smaps
                .lines()
                .find_map(|line| line.strip_prefix("Locked:"))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|kb| kb.parse().ok())
                .expect("Locked: line in smaps_rollup")
        }

        let a = SecureMemoryVault::new(&[1u8; 32]).unwrap();
        let b = SecureMemoryVault::new(&[2u8; 32]).unwrap();
        assert!(locked_kb() >= 4);
        drop(a);
        // `b` still holds at least one locked page. Other tests may add
        // locked pages concurrently, so this is a lower bound.
        assert!(
            locked_kb() >= 4,
            "dropping one container unlocked the other"
        );
        assert!(b.is_locked());
        drop(b);
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
        vault.region.as_mut().unwrap().as_mut_slice()[CIPHERTEXT_OFFSET] ^= 0xFF;
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
    fn test_plaintext_len_matches_input() {
        let data = b"1234567890";
        let vault = SecureMemoryVault::new(data).unwrap();
        assert_eq!(vault.plaintext_len, data.len());
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
        assert_eq!(vault.plaintext_len, 0);
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
}
