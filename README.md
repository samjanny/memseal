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
let api_key = vault.retrieve("api_key").unwrap();

assert_eq!(api_key, Some(b"sk-secret-12345".to_vec()));
```

## File Persistence

```rust
use memseal::Vault;
use std::path::Path;

let mut vault = Vault::create(b"my-password-here")?;

vault.store("api_key", b"sk-secret-12345")?;

// Save to disk
vault.save(Path::new("secrets.seal"))?;

// Later: load and retrieve
let vault = Vault::load(Path::new("secrets.seal"), b"my-password-here")?;
let api_key = vault.retrieve("api_key")?;
# Ok::<(), memseal::VaultError>(())
```

## API

```rust
use memseal::{Vault, VaultError};
use std::path::Path;

// Create & open
let mut vault = Vault::create(password)?;
let vault = Vault::open(password, &bytes)?;

// File I/O
vault.save(Path::new("vault.seal"))?;
let vault = Vault::load(Path::new("vault.seal"), password)?;

// Store, retrieve, remove
vault.store("name", b"secret")?;
let data = vault.retrieve("name")?;  // Option<Vec<u8>>
let existed = vault.remove("name")?; // bool

// Export to bytes
let bytes = vault.export()?;

// Change password
vault.change_password(b"old-password", b"new-password")?;
```

### Limits

| Item | Limit |
|------|-------|
| Password length | Minimum 8 bytes |
| Entry name | Maximum 255 bytes |
| Entry data | Maximum 64 MiB |
| Vault file | Maximum 256 MiB |
| Index entries | Maximum 1024 |

## Handling Plaintext

`retrieve()` returns decrypted data as `Option<Vec<u8>>`.

This is convenient, but it means the caller owns the returned plaintext and is responsible for handling it carefully.

In particular, caller code should avoid:

- logging returned secrets;
- cloning or converting them unnecessarily;
- keeping plaintext alive longer than needed;
- assuming returned plaintext is protected by `mlock`.

Internal temporary plaintext and key material are zeroized where possible, but returned plaintext belongs to the caller.

If the caller wants drop-time zeroization, the returned `Vec<u8>` can be wrapped by the caller using `zeroize::Zeroizing`:

```rust
use zeroize::Zeroizing;

if let Some(secret) = vault.retrieve("api_key")? {
    let secret = Zeroizing::new(secret);

    // Use secret here.
    // This allocation will be zeroized when `secret` is dropped.
}
# Ok::<(), memseal::VaultError>(())
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
| **KDF parameter downgrade** | The vault header is authenticated as AAD, so tampering with persisted KDF parameters is detected. Header KDF fields are also bounded before they reach Argon2i: out-of-range values (for example, below-minimum memory cost or zero iterations) are rejected by `validate_header()` during `open()`, blocking forged headers that would make password guessing artificially cheap. |
| **Nonce reuse** | Nonces are derived deterministically via HKDF-SHA256 from monotonic counters. The index stream uses its own counter; entry data and entry name nonces use the entry `data_counter` with disjoint HKDF `info` prefixes for domain separation. Counter overflow at `u64::MAX` is a hard error. The index nonce is rotated on every `export()`. |
| **Key reuse across roles** | The Argon2i-derived master key is never used directly. HKDF-SHA256 derives two 32-byte subkeys with disjoint `info` strings: one for XChaCha20-Poly1305, one for HMAC-SHA256 entry-name hashing. The master key is zeroized as soon as both subkeys exist. |
| **Plaintext lifetime inside the library** | Internal temporary plaintext and key material are zeroized where possible, including error paths. |
| **Resource exhaustion from crafted files** | Vault file size, header length, KDF parameters, entry name length, and entry data size are bounded before processing. |
| **Swap exposure of ciphertext buffers** | Internal ciphertext buffers in `SecureMemoryVault` are locked with `mlock` via `memsec` where supported. |

### Out of scope / limitations

| Threat | Reason |
|--------|--------|
| **Kernel-level or root attacker** | A privileged attacker can read process memory regardless of user-space protections. |
| **Debugger-based extraction** | A debugger attached to the process can read decrypted data while it is being processed or after it has been returned by `retrieve()`. |
| **Caller-owned plaintext leaks** | `retrieve()` returns `Vec<u8>`. The caller is responsible for avoiding logs, copies, long-lived plaintext, and unsafe conversions. |
| **Side-channel attacks** | `memseal` does not attempt to mitigate Spectre, cache timing, power analysis, or other side channels. |
| **Compromised dependencies** | The crate trusts its dependency chain, including `orion`, `memsec`, and `zeroize`. |
| **Denial of service** | memseal detects corruption and refuses to open tampered files, but it cannot recover from them. An attacker with write or delete access to the vault file can deny access until a clean copy is restored. Backups and replication are the integrator's responsibility. |
| **Full swap protection** | Only internal ciphertext buffers are locked. Internal keys, nonces, allocator metadata, returned plaintext, and caller-owned copies are outside that guarantee. |
| **Rollback protection** | memseal does not provide rollback protection. An attacker who can replace a vault file with an older valid copy can cause the application to load older data unless the application stores freshness/version information externally. |
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
  nonce = HKDF(enc_subkey, counter, domain)
  aad   = hex(HMAC-SHA256(hmac_subkey, plaintext_name)) || data_counter (u64 LE)
  ct    = XChaCha20-Poly1305(enc_subkey, nonce, plaintext, aad)

Index encryption:
  index nonce rotates on every export
  vault header is authenticated as AAD
```

Note: `mlock` is applied only to internal ciphertext buffers inside `SecureMemoryVault`. It does not lock every secret-related allocation.

## Cryptographic Primitives

| Primitive | Implementation | Purpose |
|-----------|----------------|---------|
| Argon2i | `orion` | Password-based key derivation |
| HKDF-SHA256 | `orion` | Subkey derivation and nonce derivation |
| XChaCha20-Poly1305 | `orion` | Authenticated encryption |
| HMAC-SHA256 | `orion` | Entry-name hashing |
| OsRng | `rand_core` | Random salt generation |
| `mlock` / `munlock` | `memsec` | Best-effort locking of internal ciphertext buffers |
| Zeroization | `zeroize` | Clearing internal temporary secrets where possible |

## Security Properties

- **Small public API.** The crate exposes `Vault` and `VaultError`; internal modules are private.
- **Unsafe code is isolated.** The crate uses `#![deny(unsafe_code)]` at the crate root. The memory-locking module explicitly allows unsafe code for `mlock`/`munlock` and `unsafe impl Send/Sync`.
- **Domain separation.** Key derivation and nonce derivation use distinct domain labels.
- **Authenticated encryption.** Vault index data and entries are encrypted with AEAD.
- **Bounded parsing.** Untrusted vault data is checked against size and parameter bounds before processing.
- **Atomic file writes.** `save()` writes to a temporary file, fsyncs it, renames it, and uses `0600` permissions on Unix.
- **Best-effort memory hygiene.** Internal temporary key material and plaintext are zeroized where possible.
- **Partial swap protection.** Internal ciphertext buffers are locked with `mlock` where supported, but this does not cover every allocation.

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
