# memseal

[![CI](https://github.com/samjanny/memseal/actions/workflows/ci.yml/badge.svg)](https://github.com/samjanny/memseal/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/memseal.svg)](https://crates.io/crates/memseal)
[![docs.rs](https://docs.rs/memseal/badge.svg)](https://docs.rs/memseal)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small password-based encrypted vault for named secrets, with authenticated encryption, bounded parsing, and explicit memory-hygiene trade-offs.

> **Status:** `memseal` is an experimental `0.x` crate and has **not** been independently audited.

> **Note:** This crate is not a wrapper around Linux `mseal(2)`. "memseal" refers to sealing secrets in an encrypted in-memory vault.

## Overview

`memseal` stores named secrets in an encrypted vault protected by a password.

It is designed for applications that need a small, self-contained encrypted vault that can be kept in memory, exported to bytes, or saved to disk.

It is **not** a replacement for OS keyrings, HSMs, cloud secret managers, or mature password managers.

## Quick Start

```rust
use memseal::Vault;

let mut vault = Vault::create(b"my-password-here").unwrap();

// Store secrets
vault.store("api_key", b"sk-secret-12345").unwrap();
vault.store("db_url", b"postgres://user:pass@host/db").unwrap();

// Export to bytes
let bytes = vault.export().unwrap();

// Reopen with the same password
let vault = Vault::open(b"my-password-here", &bytes).unwrap();
let matches = vault
    .with_secret("api_key", |secret| secret == b"sk-secret-12345")
    .unwrap();

assert_eq!(matches, Some(true));
```

## File Persistence

```rust
use memseal::{Vault, VaultError};
use std::path::Path;

fn main() -> Result<(), VaultError> {
    let mut vault = Vault::create(b"my-password-here")?;

    vault.store("api_key", b"sk-secret-12345")?;

    // Save to disk
    vault.save(Path::new("secrets.seal"))?;

    // Later: load and retrieve
    let vault = Vault::load(Path::new("secrets.seal"), b"my-password-here")?;
    let matches = vault.with_secret("api_key", |secret| {
        secret == b"sk-secret-12345"
    })?;
    assert_eq!(matches, Some(true));

    Ok(())
}
```

## API

```rust
use memseal::{Vault, VaultError};
use std::path::Path;

fn main() -> Result<(), VaultError> {
    let password = b"my-password-here";

    // Create
    let mut vault = Vault::create(password)?;

    // Store, access, remove
    vault.store("name", b"secret")?;
    let matches = vault.with_secret("name", |secret| secret == b"secret")?;
    assert_eq!(matches, Some(true));
    let existed = vault.remove("name")?; // bool
    assert!(existed);

    // Change password
    vault.change_password(password, b"new-password-here")?;

    // Export to bytes, then reopen with the new password
    let bytes = vault.export()?;
    let reopened = Vault::open(b"new-password-here", &bytes)?;
    assert_eq!(reopened.retrieve("name")?, None);

    // File I/O
    vault.save(Path::new("vault.seal"))?;
    let loaded = Vault::load(Path::new("vault.seal"), b"new-password-here")?;
    let _ = loaded;

    Ok(())
}
```

### Limits

| Item | Limit |
|------|-------|
| Password length | Minimum 8 bytes |
| Entry name | Maximum 255 bytes |
| Entry data | Maximum 64 MiB |
| Vault file | Maximum 256 MiB |
| Index entries | Maximum 1024 |
| Header JSON | Maximum 4 KiB |
| KDF parameters accepted by `open()` | 32 MiB to 256 MiB memory, 3 to 10 iterations |

The 256 MiB file bound is enforced on both sides: `load()` refuses larger
files and `export()`/`save()` refuse to produce them. Encrypted entry
bytes are stored in the index JSON as number arrays (roughly 3.6 output
bytes per stored byte), so the practical bound on total stored plaintext
across all entries is about 70 MiB; `export()` fails cleanly when it is
exceeded and the vault stays usable. See `DESIGN.md` section 9.3.

### Errors

Every fallible call returns `VaultError`. The enum is `#[non_exhaustive]`,
so a `match` on it needs a wildcard arm:

```rust
use memseal::{Vault, VaultError};

fn main() {
    let bytes = {
        let mut vault = Vault::create(b"my-password-here").unwrap();
        vault.store("api_key", b"sk-secret-12345").unwrap();
        vault.export().unwrap()
    };

    match Vault::open(b"wrong-password", &bytes) {
        Ok(_) => unreachable!("the password is wrong"),
        // Wrong password, or the bytes were tampered with: the AEAD gives a
        // single verdict, so the library cannot tell the two apart. Do not
        // retry in a loop; every attempt repeats the Argon2 derivation.
        Err(VaultError::InvalidPassword) => {}
        // Length fields, header, or index are malformed or out of bounds.
        Err(VaultError::CorruptedData(msg)) => panic!("corrupted vault: {msg}"),
        Err(other) => panic!("unexpected error: {other}"),
    }
}
```

| Variant | Meaning |
|---------|---------|
| `InvalidPassword` | The encrypted index failed to authenticate: wrong password, or a tampered, truncated, or corrupted vault. |
| `CorruptedData(String)` | The vault bytes violate the format or a documented bound (header length, KDF parameters, index version, entry count, entry sizes). |
| `CryptoError(String)` | A cryptographic operation failed, or an input violated a limit (password, entry name, entry data). |
| `SerializationError(String)` | Serializing the vault failed, or the export exceeds 256 MiB. |
| `IoError(std::io::Error)` | A file operation in `load()` or `save()` failed. |
| `InvalidKey` | The in-memory encryption subkey is unavailable (internal invariant). |

A missing entry is not an error: `retrieve()` and `with_secret()` return
`Ok(None)`, and `remove()` returns `Ok(false)`.

Upgrading from 0.1.x or 0.2.0: the variants `InvalidHeader`, `InvalidIndex`,
`InvalidDataBlock`, `InvalidMetaBlock`, `InvalidPath`, `InvalidVersion`,
`InvalidFormat`, and `EntryNotFound` were removed in 0.2.1. None of them was
ever returned, so only exhaustive `match` expressions need to change.

## Handling Plaintext

Prefer `with_secret()` when plaintext only needs to be used temporarily. It
decrypts the requested value, lends it to a closure as `&[u8]`, then zeroizes
the library-owned plaintext allocation as soon as the closure returns:

```rust
use memseal::{Vault, VaultError};

fn main() -> Result<(), VaultError> {
    let mut vault = Vault::create(b"my-password-here")?;
    vault.store("api_key", b"sk-secret-12345")?;

    let authenticated = vault.with_secret("api_key", |secret| {
        // Use the borrowed plaintext only inside this closure.
        secret == b"sk-secret-12345"
    })?;
    assert_eq!(authenticated, Some(true));

    Ok(())
}
```

The callback is not called for a missing entry and `with_secret()` returns
`Ok(None)`. Its return value may leave the closure, but borrowed plaintext
cannot. A caller can still explicitly copy the bytes inside the callback; any
such copy is caller-owned and cannot be cleared by the vault.

For convenience and backwards compatibility, `retrieve()` returns decrypted
data as `Option<Vec<u8>>`.

This is convenient, but it means the caller owns the returned plaintext and is responsible for handling it carefully.

In particular, caller code should avoid:

- logging returned secrets;
- cloning or converting them unnecessarily;
- keeping plaintext alive longer than needed;
- assuming returned plaintext is protected by `mlock`.

Internal temporary plaintext and key material are zeroized where possible, but
plaintext returned by `retrieve()` belongs to the caller.

If the caller wants drop-time zeroization, the returned `Vec<u8>` can be wrapped by the caller using `zeroize::Zeroizing`:

```rust
use memseal::{Vault, VaultError};
use zeroize::Zeroizing;

fn main() -> Result<(), VaultError> {
    let mut vault = Vault::create(b"my-password-here")?;
    vault.store("api_key", b"sk-secret-12345")?;

    if let Some(secret) = vault.retrieve("api_key")? {
        let secret = Zeroizing::new(secret);

        // Use secret here.
        assert_eq!(secret.as_slice(), b"sk-secret-12345");

        // This allocation will be zeroized when `secret` is dropped.
    }

    Ok(())
}
```

This only zeroizes that returned allocation on drop. It does not prevent accidental copies made by caller code or by the allocator/runtime.

## What memseal is

- A small embedded vault for named secrets.
- Password-based: vault keys are derived from a caller-provided password.
- Self-contained: vaults can be exported to bytes or saved to disk.
- Authenticated: encrypted data is protected against tampering.
- Explicit about its limitations and memory-hygiene trade-offs.

## What memseal is not

- Not independently audited.
- Not an OS keyring wrapper.
- Not a cloud secret manager.
- Not an HSM.
- Not a password manager.
- Not a general secure-memory allocator.
- Not related to Linux `mseal(2)`.

## Intended Use Cases

- **Embedded encrypted vaults** - Store named secrets in an application-managed encrypted vault.
- **Portable secret bundles** - Export/load a password-protected vault without relying on an OS credential store.
- **Credential caches** - Keep secrets encrypted at rest in memory and on disk, while accepting explicit caller-owned plaintext boundaries.
- **Application-managed secret storage** - Store small sets of API keys, tokens, or credentials where a lightweight Rust-native vault is appropriate.

## Threat Model

For the exact byte format, key derivation chain, nonce derivation, and AAD bindings that back these claims, see [DESIGN.md](DESIGN.md).

### Intended mitigations

| Threat | Mitigation |
|--------|------------|
| **Tampered vault data** | The vault header is authenticated as AAD for index decryption; the index JSON and every per-entry payload are encrypted and authenticated with XChaCha20-Poly1305. Bit flips in authenticated header fields, nonces, ciphertext, or Poly1305 tags are detected during `open()` or entry retrieval. |
| **Entry swap attacks** | Each entry's data and name ciphertexts share an AAD made of the entry's HMAC-derived key and its `data_counter`. Swapping either the encrypted data or the encrypted name across entries causes AEAD verification to fail. |
| **Entry name leakage in serialized vaults** | Entry names are not stored in plaintext. Index keys are derived with HMAC-SHA256. |
| **KDF parameter downgrade** | The vault header is authenticated as AAD, so tampering with persisted KDF parameters is detected. Header KDF fields are also bounded before they reach Argon2i: `open()` accepts only 32 MiB to 256 MiB of memory and 3 to 10 iterations, so a forged header can neither make password guessing cheap nor force more than one 256 MiB, 10-pass derivation before the file is rejected. See `DESIGN.md` section 10.1. |
| **Nonce reuse** | All XChaCha20 nonces are 24-byte values drawn from the OS CSPRNG and stored next to the ciphertext they protect: a fresh index nonce on every `export()`, fresh entry data/name nonces on every `store()`. Random generation also covers state forks: two vault instances opened from the same persisted bytes cannot repeat a nonce when both export, which counter-derived nonces would. Monotonic counters remain as authenticated state, are bound into entry AAD, and overflow at `u64::MAX` is a hard error. |
| **Key reuse across roles** | The Argon2i-derived master key is never used directly. HKDF-SHA256 derives two 32-byte subkeys with disjoint `info` strings: one for XChaCha20-Poly1305, one for HMAC-SHA256 entry-name hashing. The master key is zeroized as soon as both subkeys exist. |
| **Plaintext lifetime inside the library** | Internal temporary plaintext and key material are zeroized where possible, including error paths. |
| **Resource exhaustion from crafted files** | Vault file size (256 MiB), header JSON length (4 KiB), KDF parameters, entry name length, entry data size, per-entry ciphertext sizes, and the decoded index entry count are bounded before processing. `open()` rejects an index whose entry count exceeds the 1024 cap or whose entries are larger than `store()` can produce. The residual, deliberate cost of opening a hostile file is one bounded Argon2i derivation. |
| **Swap and core-dump exposure of in-memory subkeys** | Each subkey lives in a `SecureMemoryVault`: it is encrypted under a fresh stream key, and the key, its nonce, and the ciphertext share one allocation locked with `mlock` via `memsec` where supported (on Linux also excluded from core dumps) and zeroized on drop. |

### Out of scope / limitations

| Threat | Reason |
|--------|--------|
| **Kernel-level or root attacker** | A privileged attacker can read process memory regardless of user-space protections. |
| **Debugger-based extraction** | A debugger attached to the process can read decrypted data while it is being processed, including inside a `with_secret()` callback, or after it has been returned by `retrieve()`. |
| **Caller-owned plaintext leaks** | `with_secret()` keeps the library-owned buffer scoped to a callback and zeroizes it afterward, but cannot prevent the callback from making copies. `retrieve()` returns `Vec<u8>` directly. The caller remains responsible for avoiding logs, copies, long-lived plaintext, and unsafe conversions. |
| **Side-channel attacks** | `memseal` does not attempt to mitigate Spectre, cache timing, power analysis, or other side channels. This includes the timing difference between a hit and a miss in `retrieve()`/`with_secret()`, which reveals whether a name exists to anyone who can time calls. |
| **Compromised dependencies** | The crate trusts its dependency chain, including `orion`, `memsec`, and `zeroize`. |
| **Denial of service** | memseal detects corruption and refuses to open tampered files, but it cannot recover from them. An attacker with write or delete access to the vault file can deny access until a clean copy is restored. Backups and replication are the integrator's responsibility. |
| **Full swap protection** | Only the two `SecureMemoryVault` allocations that hold the subkeys are locked. Transient copies made during each operation, allocator metadata, returned plaintext, and caller-owned copies are outside that guarantee. |
| **Rollback protection** | memseal does not provide rollback protection. An attacker who can replace a vault file with an older valid copy can cause the application to load older data unless the application stores freshness/version information externally. |
| **File permissions on Windows** | `save()` creates the file with mode `0600` on Unix only. On Windows the file inherits the DACL of its directory; restricting it is the caller's job. |
| **Untrusted paths** | `load()` and `save()` follow symbolic links like any `std::fs` call and do not validate the path. Callers that accept paths from untrusted sources must validate them first; `open()`/`load()` bound the work a hostile file can cause but do not make it free. |
| **Formal cryptographic assurance** | The crate has not been independently audited. The integration layer should be reviewed before high-risk use. |

## Architecture

```text
            Password (>= 8 bytes)
               |
           Argon2i
      128 MiB, 4 iterations
      random 16-byte salt
               |
          Master Key (32B)
               |
         HKDF-SHA256
         salt = KDF salt
          /         \
    enc_subkey    hmac_subkey
      (32B)         (32B)
        |              |
        |              +--> HMAC-SHA256 entry-name hashing
        |
        +--> XChaCha20-Poly1305 encryption

Per-entry encryption:
  nonce = random 24 bytes (OsRng), stored as the ciphertext prefix
  aad   = hex(HMAC-SHA256(hmac_subkey, plaintext_name)) || data_counter (u64 LE)
  ct    = XChaCha20-Poly1305(enc_subkey, nonce, plaintext, aad)

Index encryption:
  fresh random index nonce on every export, stored in the file
  vault header is authenticated as AAD
```

Note: `mlock` is applied only to the `SecureMemoryVault` allocations that hold the two subkeys (each one stream key, nonce, and ciphertext). It does not lock every secret-related allocation.

## Cryptographic Primitives

| Primitive | Implementation | Purpose |
|-----------|----------------|---------|
| Argon2i | `orion` | Password-based key derivation |
| HKDF-SHA256 | `orion` | Subkey derivation |
| XChaCha20-Poly1305 | `orion` | Authenticated encryption |
| HMAC-SHA256 | `orion` | Entry-name hashing |
| OsRng | `rand_core` | Random salt and nonce generation |
| `mlock` / `munlock` | `memsec` | Best-effort locking of the in-memory subkey containers |
| Zeroization | `zeroize` | Clearing internal temporary secrets where possible |

## Security Properties

- **Small public API.** The crate exposes `Vault` and `VaultError`; internal modules are private.
- **Unsafe code is isolated.** The crate uses `#![deny(unsafe_code)]` at the crate root. The memory-locking module explicitly allows unsafe code for the `mlock`/`munlock` calls only; it keeps no raw pointers, so `Send`/`Sync` need no `unsafe impl`.
- **Domain separation.** Subkey derivation uses distinct HKDF `info` labels for the encryption and HMAC keys.
- **Authenticated encryption.** Vault index data and entries are encrypted with AEAD.
- **Bounded parsing.** Untrusted vault data is checked against size and parameter bounds before processing; a hostile file can cost at most one bounded Argon2i derivation (256 MiB, 10 passes) before it is rejected.
- **Atomic file writes.** `save()` writes to a temporary file, fsyncs it, renames it, and uses `0600` permissions on Unix (Windows inherits the directory ACL).
- **Best-effort memory hygiene.** Internal temporary key material and plaintext are zeroized where possible.
- **Partial swap protection.** The in-memory subkey containers (stream key, nonce, and ciphertext together) are locked with `mlock` where supported, but this does not cover every allocation.

## Comparison

`memseal` is not a replacement for lower-level memory-hygiene crates such as `zeroize`, `secrecy`, or `memsec`.

It is also not an OS credential-store wrapper like `keyring`.

`memseal` is useful when an application wants a small, portable, self-contained encrypted vault for named secrets that it can export, save, and load directly.

## Development

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Run benchmarks with:

```bash
cargo bench --bench full_bench
```

## CI

GitHub Actions runs on every push and PR to `main`:

- `cargo check --all-targets`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `rustsec/audit-check` action

## MSRV

`memseal` currently targets the Rust stable toolchain and uses the Rust 2024 edition.

## Security

This crate has not been independently audited.

Please report security issues privately. See [SECURITY.md](SECURITY.md).

## License

MIT - see [LICENSE](LICENSE).
