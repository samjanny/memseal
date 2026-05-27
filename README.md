# memseal

[![CI](https://github.com/samjanny/valackey_vault/actions/workflows/ci.yml/badge.svg)](https://github.com/samjanny/valackey_vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Encrypt and store secrets in memory with password-based key derivation, authenticated encryption, and automatic zeroization.

> **Disclaimer**: This library has **not been independently audited**. While it uses well-established cryptographic primitives (XChaCha20-Poly1305, Argon2i, HKDF-SHA256 via [orion](https://crates.io/crates/orion)), the integration has not been reviewed by a third-party security firm. Use at your own risk in production environments. If you find a vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure.

## Quick Start

```rust
use memseal::Vault;

let mut vault = Vault::create(b"my-password-here").unwrap();

// Store secrets
vault.store("api_key", b"sk-secret-12345").unwrap();
vault.store("db_url", b"postgres://user:pass@host/db").unwrap();

// Export to bytes (for persistence or transmission)
let bytes = vault.export().unwrap();

// Reopen with the same password
let vault = Vault::open(b"my-password-here", &bytes).unwrap();
let api_key = vault.retrieve("api_key").unwrap();
assert_eq!(api_key, Some(b"sk-secret-12345".to_vec()));
```

## API

```rust
use memseal::{Vault, VaultError};
use std::path::Path;

// Create & open (password must be >= 8 bytes)
let mut vault = Vault::create(password)?;
let vault = Vault::open(password, &bytes)?;

// File I/O
vault.save(Path::new("vault.seal"))?;          // &mut self (rotates nonce)
let vault = Vault::load(Path::new("vault.seal"), password)?;

// Store, retrieve, remove
vault.store("name", b"secret")?;               // name max 255B, data max 64 MiB
let data = vault.retrieve("name")?;            // Option<Vec<u8>>
let existed = vault.remove("name")?;           // bool

// Export to bytes
let bytes = vault.export()?;                   // &mut self (rotates nonce)

// Change password (re-derives keys, re-encrypts all entries one-at-a-time)
vault.change_password(b"old-pass", b"new-pass")?;
```

## Use Cases

- **Secret management** -- Hold API keys, database credentials, or signing keys in memory without exposing plaintext to swap, core dumps, or memory scanners.
- **Encrypted vaults** -- Store secrets with authenticated encryption. The index hides entry names behind HMAC and protects KDF parameters against downgrade attacks.
- **Key derivation pipelines** -- Derive purpose-specific subkeys from a master secret using HKDF with domain separation.
- **Credential caches** -- Cache decrypted credentials with automatic zeroization on drop. Memory is locked with `mlock` to prevent paging to disk.

## Threat Model

### What memseal protects against

| Threat | Mitigation |
|--------|------------|
| **Memory disclosure via swap** | Ciphertext is `mlock`'d to prevent the OS from paging it to disk. |
| **Cold boot / memory dump** | Data is encrypted at rest in memory with XChaCha20-Poly1305. Plaintext exists only briefly inside `access()` callbacks and is zeroized immediately after. |
| **Key reuse across operations** | Master key is never used directly. Two distinct subkeys (encryption, HMAC) are derived via HKDF-SHA256 with domain-separated info labels and the KDF salt. |
| **Nonce reuse** | Nonces are derived deterministically from a monotonic counter via HKDF, not generated randomly. Counter overflow is checked. Index nonce rotated on every export. |
| **KDF parameter downgrade** | The `VaultHeader` (containing Argon2i params) is passed as AAD to AEAD encryption. Tampering with iterations or memory cost causes authenticated decryption to fail. Header validated against bounds before KDF runs. |
| **Entry swap attacks** | Each entry's ciphertext is bound to its HMAC'd key and data counter via AAD. Swapping encrypted blobs between entries is detected. |
| **Entry name leakage** | Index keys are `HMAC-SHA256(hmac_key, name)`, not plaintext. An attacker with access to the serialized index cannot enumerate entry names without the key. |
| **Use-after-free of secrets** | `SecureMemoryVault` implements `Drop` with zeroization of ciphertext, followed by `munlock`. All temporary key material and plaintext is zeroized on every code path, including errors. |
| **Tampered ciphertext** | All encryption uses authenticated AEAD (Poly1305 tag). Any bit flip in ciphertext or AAD is detected and rejected. |
| **Resource exhaustion via crafted files** | Header length, KDF parameters, file size, entry name length, and entry data size are all bounded before processing. |
| **Weak passwords** | Minimum password length (8 bytes) enforced on vault creation and password change. |

### What memseal does NOT protect against

| Threat | Reason |
|--------|--------|
| **Kernel-level attacker** | A root/kernel attacker can read process memory regardless of mlock. This is a user-space library. |
| **Side-channel attacks** | No countermeasures against Spectre, cache timing, or power analysis. The crypto primitives (orion) are constant-time where possible. |
| **Compromised dependencies** | The library trusts its dependency chain (orion, memsec, zeroize). CI runs `cargo audit` on every push. |
| **Denial of service** | An attacker who can write to the vault data can corrupt it. Integrity is detected, but availability is not guaranteed. |
| **Debugger-based extraction** | A debugger attached to the process can read decrypted data during `access()` callbacks. Use OS-level protections (`prctl(PR_SET_DUMPABLE, 0)`) to mitigate. |

## Architecture

```
            Password (>= 8 bytes)
               |
           Argon2i (128 MiB, 4 iterations, random 16B salt)
               |
          Master Key (32B)
               |
         HKDF-SHA256 (salt = kdf_salt)
          /         \
    enc_subkey    hmac_subkey
      (32B)         (32B)
        |              |
  SecureMemoryVault  SecureMemoryVault
  (XChaCha20-Poly1305  (HMAC-SHA256
   streaming AEAD,      entry name hashing)
   mlock'd memory)
        |
  derive_nonce(enc_key, counter, salt)
  via HKDF with domain separation
        |
  Per-entry: seal_with_aad(key, nonce, data, hmac_key || counter)
```

## Cryptographic Primitives

| Primitive | Implementation | Purpose |
|-----------|---------------|---------|
| XChaCha20-Poly1305 (streaming) | orion | In-memory encryption in 4KB chunks |
| XChaCha20-Poly1305 (single-shot) | orion | AAD-protected encryption of vault index and entries |
| HKDF-SHA256 | orion | Subkey derivation (with KDF salt), nonce derivation from counter |
| HMAC-SHA256 | orion | Entry name hashing in vault index |
| Argon2i | orion | Password-based key derivation |
| OsRng | rand_core | Cryptographically secure random generation |

## Security Properties

- **`#![deny(unsafe_code)]`** at crate level. Only `secure_memory_vault.rs` allows unsafe for `mlock`/`munlock`.
- **Domain separation** for all key derivation: `MEMSEAL_SUBKEY_ENC_v1`, `MEMSEAL_SUBKEY_HMAC_v1`, `MEMSEAL_NONCE_CTR_v1`, `MEMSEAL_DATA_NONCE_v1`, `MEMSEAL_NAME_NONCE_v1`.
- **Minimal key exposure.** Facade-level crypto operations execute inside `SecureMemoryVault::access()` callbacks. Note: the internal encryption key and nonce of each `SecureMemoryVault` instance reside on the heap without `mlock` (only the ciphertext buffer is locked).
- **Authenticated encryption everywhere.** No unauthenticated ciphertext path exists. Per-entry AAD prevents entry-swap attacks.
- **Version validation** on deserialization of `VaultIndex` and `VaultHeader`.
- **Bounded input processing.** Header length, KDF parameters, file size (256 MiB), entry name (255B), and entry data (64 MiB) are all validated before use.
- **Zeroization on all paths.** Key material, plaintext, and entry names are zeroized even on error returns.

## Building

```bash
cargo build
cargo test
cargo bench --bench full_bench
```

## CI

GitHub Actions runs on every push and PR to `main` (actions SHA-pinned, stable toolchain):
- `cargo check` -- compilation
- `cargo fmt --check` -- formatting
- `cargo clippy -D warnings` -- lints
- `cargo test` -- 78 tests (74 unit + 4 doctest)
- `cargo audit` -- vulnerability scanning

## MSRV

Rust 2024 edition. CI runs stable toolchain.

## License

MIT -- see [LICENSE](LICENSE).
