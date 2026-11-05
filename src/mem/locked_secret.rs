#![allow(unsafe_code)]
//! Locked in-memory container for the vault's 32-byte subkeys.
//!
//! The bytes live in a [`LockedRegion`]: a `memsec` allocation that occupies
//! pages no other allocation shares, sits between two guard pages, is
//! `mlock`'d for the container's lifetime (on Linux `memsec` also excludes
//! it from core dumps), and is zeroized on drop. Because the pages are
//! exclusive, unlocking one container can never unlock another.
//!
//! The bytes are stored in the clear inside the locked region. Encrypting
//! them in memory would need a key, and that key would have to live in
//! memory with the same protection, so it would add nothing an attacker who
//! can read the region does not already get.
use std::fmt::Debug;
use std::ptr::NonNull;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors that can occur when building a `LockedSecret`.
#[derive(Debug, Error)]
pub enum LockedSecretError {
    /// The secret was empty.
    #[error("locked secret must not be empty")]
    Empty,
    /// Allocating the locked region failed.
    #[error("locked memory allocation failed")]
    Alloc,
    /// `mlock` on the region failed, for example because `RLIMIT_MEMLOCK`
    /// is exhausted.
    #[error("memsec lock failed")]
    Lock,
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
    fn new(len: usize) -> Result<Self, LockedSecretError> {
        debug_assert!(len > 0, "LockedRegion must not be empty");

        // SAFETY: `malloc_sized` initializes memsec's page size and canary on
        // first use and returns a pointer valid for `len` bytes until `free`.
        let ptr = unsafe { memsec::malloc_sized(len) }.ok_or(LockedSecretError::Alloc)?;

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
            return Err(LockedSecretError::Lock);
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

/// A secret kept in a locked, zeroize-on-drop allocation of its own.
pub struct LockedSecret {
    region: LockedRegion,
}

impl LockedSecret {
    /// Copies `secret` into a fresh locked region.
    ///
    /// The caller still owns `secret` and is responsible for wiping it.
    pub fn new(secret: &[u8]) -> Result<Self, LockedSecretError> {
        if secret.is_empty() {
            return Err(LockedSecretError::Empty);
        }
        let mut region = LockedRegion::new(secret.len())?;
        region.as_mut_slice().copy_from_slice(secret);
        Ok(Self { region })
    }

    /// Lends the secret bytes to `f` for the duration of the call.
    ///
    /// The borrow cannot escape the closure; any copy `f` makes is the
    /// caller's to wipe.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(self.region.as_slice())
    }
}

impl Debug for LockedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{LockedSecret, LockedSecretError};
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LockedSecret>();
    }

    #[test]
    fn roundtrip() {
        let data = b"This is a very important secret!";
        let secret = LockedSecret::new(data).unwrap();
        secret.with_bytes(|bytes| assert_eq!(bytes, data));
    }

    #[test]
    fn with_bytes_returns_closure_value() {
        let secret = LockedSecret::new(&[7u8; 32]).unwrap();
        let sum: u32 = secret.with_bytes(|bytes| bytes.iter().map(|&b| b as u32).sum());
        assert_eq!(sum, 7 * 32);
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(matches!(
            LockedSecret::new(&[]),
            Err(LockedSecretError::Empty)
        ));
    }

    #[test]
    fn containers_do_not_share_pages() {
        // munlock is not reference counted: if two regions shared a page,
        // dropping one would unlock the other. Every region must therefore
        // sit in pages of its own. 4096 is the smallest page size memseal
        // runs on; distinct 4 KiB pages imply distinct larger pages too.
        let a = LockedSecret::new(&[1u8; 32]).unwrap();
        let b = LockedSecret::new(&[2u8; 32]).unwrap();
        let pa = a.region.as_slice().as_ptr() as usize;
        let pb = b.region.as_slice().as_ptr() as usize;
        assert_ne!(pa / 4096, pb / 4096, "regions share a page");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dropping_one_container_keeps_the_other_locked() {
        /// Whether the mapping that contains `addr` carries the `lo`
        /// (locked) VM flag in `/proc/self/smaps`. Checking the specific
        /// mapping, rather than the process-wide `Locked:` total, keeps the
        /// test meaningful while other tests hold locked pages in parallel.
        fn mapping_is_locked(addr: usize) -> bool {
            let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
            let mut in_range = false;
            for line in smaps.lines() {
                if let Some((range, _)) = line.split_once(' ')
                    && let Some((start, end)) = range.split_once('-')
                    && let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(end, 16),
                    )
                {
                    in_range = start <= addr && addr < end;
                    continue;
                }
                if in_range && let Some(flags) = line.strip_prefix("VmFlags:") {
                    return flags.split_whitespace().any(|f| f == "lo");
                }
            }
            panic!("no smaps mapping contains {addr:#x}");
        }

        let a = LockedSecret::new(&[1u8; 32]).unwrap();
        let b = LockedSecret::new(&[2u8; 32]).unwrap();
        let addr_b = b.region.as_slice().as_ptr() as usize;
        assert!(mapping_is_locked(addr_b));
        drop(a);
        // munlock is not reference counted: `b`'s page must still be
        // locked after its neighbour is freed.
        assert!(
            mapping_is_locked(addr_b),
            "dropping one container unlocked the other"
        );
        b.with_bytes(|bytes| assert_eq!(bytes, &[2u8; 32]));
    }

    #[test]
    fn concurrent_reads() {
        let data = b"concurrent test data";
        let secret = Arc::new(LockedSecret::new(data).unwrap());
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let secret = Arc::clone(&secret);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                secret.with_bytes(|bytes| assert_eq!(bytes, data));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let secret = LockedSecret::new(b"top secret").unwrap();
        let rendered = format!("{:?}", secret);
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("top secret"));
    }
}
