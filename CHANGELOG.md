# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) while in the `0.x` development series.

## [Unreleased]

## [0.2.0] - 2026-09-10

### Added

* Added `Vault::with_secret`, a callback-based plaintext access API. The
  decrypted buffer is borrowed only for the callback invocation and is
  zeroized immediately afterward, including during normal panic unwinding.
  Missing entries return `Ok(None)` without invoking the callback. `retrieve()`
  remains available as the caller-owned plaintext convenience API.

## [0.1.6] - 2026-06-12

### Security

* All XChaCha20 nonces (index nonce per `export()`, entry data and name nonces per `store()`) are now generated randomly from the OS CSPRNG instead of being derived via HKDF from monotonic counters. Counter-derived nonces could repeat if the same persisted vault state was opened by two `Vault` instances and both exported ("state fork"), reusing a (key, nonce) pair across the two outputs. Random 192-bit nonces make this impossible. Existing vault files remain fully readable: nonces were always stored in the file and as the prefix of each entry ciphertext, and reading never re-derives them. The counters are retained as authenticated state, stay bound into the per-entry AAD, and are still checked for monotonic consistency on `open()`.
* `change_password` no longer silently skips a non-dummy entry whose `encrypted_name` or `encrypted_data` is missing or undersized; it now fails with `CorruptedData`, leaving the original vault intact. Entries flagged `is_dummy` are skipped explicitly. Vaults produced by this library always populate both fields, so the behavior change is only observable on inconsistent (but authenticated) indexes.

### Fixed

* `export()` now rejects outputs larger than the 256 MiB bound that `load()` enforces, returning `SerializationError` and leaving the vault usable. Previously `save()` could write a vault that `load()` would then refuse to read: encrypted entry bytes serialize into the index JSON as number arrays at roughly 3.6 output bytes per stored byte, so about 71 MiB of aggregate plaintext was enough to cross the cap. The practical aggregate bound is now documented in the README and in `DESIGN.md` section 9.3, and a denser index encoding is scheduled for `0.2.x`.
* `insert_file` no longer rejects overwriting an existing entry when the index is at `MAX_INDEX_ENTRIES`; the cap check now only applies to inserts that would grow the map. Previously a full vault could not update any of its own entries.
* `save()` now removes the temporary file if writing or syncing it fails, instead of leaving it behind in the target directory.
* The unsigned `secure_usize_between`, `secure_u32_between`, and `secure_u64_between` helpers no longer overflow (and panic on a modulo by zero) when called with the full integer range; they now match the full-range handling that the signed variants already had.

### Documentation

* Rewrote the nonce sections of `DESIGN.md` (sections 5, 5.1, 8) and the README threat model, architecture diagram, and primitives table to describe random nonce generation, the state-fork rationale, and backward compatibility with files written by earlier releases.
* Documented the JSON number-array encoding of ciphertext bytes and the resulting ~70 MiB practical aggregate plaintext bound (`DESIGN.md` section 9.3, README limits section), and added a denser-encoding item to the `0.2.x` roadmap.

## [0.1.5] - 2026-06-05

### Changed

* Reworded the package `description` to be more conservative and aligned with the README: "A small password-based encrypted vault for named secrets".
* Added `authors` and `documentation` fields to `Cargo.toml`.

### Documentation

* Made the README code examples self-contained and runnable: wrapped the file-persistence, API-summary, and plaintext-handling snippets in `fn main() -> Result<(), VaultError>` blocks, removed the hidden rustdoc `# Ok::<...>` lines, and defined previously undefined `password`/`bytes` bindings in the API summary. The examples now compile cleanly under `-D warnings` (no unused bindings) and their assertions hold when run.

## [0.1.4] - 2026-06-05

### Security

* The decrypted index buffer in `Vault::open` and the serialized header and index buffers in `Vault::export` are now wrapped in `zeroize::Zeroizing`, so index metadata (HMAC-derived entry names, nonce counters, structure) is cleared from memory on scope exit instead of lingering in freed allocations. This brings these buffers in line with the existing zeroization of key material.
* `Vault::open` now rejects an index whose decoded `files` map exceeds `MAX_INDEX_ENTRIES` (1024), closing a denial-of-service gap where a crafted vault file could force a larger in-memory map than the format allows. The cap was previously enforced only on `insert_file`.
* On reopen, `VaultIndex::from_master_key_and_data` now enforces that `data_nonce_counter` is strictly greater than the largest stored `data_counter`. This prevents a later `store` from reusing a per-entry data nonce when the (authenticated) index is inconsistent.
* The encryption subkey extraction in `Vault::store`, `retrieve`, `export`, and `change_password` now fails hard if the subkey is shorter than 32 bytes instead of silently leaving the key buffer all-zero, removing a latent path to encryption under a known zero key. The duplicated extraction logic is consolidated into a single helper.

### Added

* Added `ROADMAP.md` outlining planned milestones for the `0.1.x` through `0.5.x` lines.
* Added `DESIGN.md` describing the on-disk vault format, the key and nonce derivation chains, the AAD bindings, per-entry encryption, bounded parsing rules, and the current format oddities.

### Tests

* Added tampering and boundary tests for `Vault::open`, covering: raw-bytes
  truncation and length checks; header JSON tampering (malformed JSON,
  missing fields, unsupported version, out-of-range KDF parameters);
  AAD divergence via salt modification and cross-vault header swap; nonce
  bit-flips and nonce replay between exports.

### Notes

* The 8-byte `nonce_counter` field that `export()` writes at offset
  `4 + header_len + 24` is currently never read by `open()`. The
  authoritative counter is recovered from the encrypted index JSON. The
  field is wire-format dead weight; a test now pins this behavior. Cleanup
  is scheduled for `0.2.x` because removing the field is a vault format
  break.

### Documentation

* Documented that `memseal` does not provide rollback protection. An attacker who can replace a vault file with an older valid copy can cause the application to load older data unless freshness is tracked externally.
* Refined the threat model wording in `README.md`: clarified what is authenticated vs encrypted, made the AAD binding explicit for entry-swap and entry-name-swap, made the rationale for KDF parameter bounds explicit, described nonce derivation in terms of HKDF streams with disjoint `info` prefixes, and reframed the DoS limitation as a backup/replication responsibility for integrators.
* Linked the `README.md` threat model to `DESIGN.md` so that each claim points to the byte-level construction that backs it.

## [0.1.3] - 2026-05-27

### Documentation

* Revised README overview, API documentation, and threat model wording for clarity.
* Made security claims more explicit about caller-owned plaintext and memory-hygiene limitations.

## [0.1.2] - 2026-05-27

### Documentation

* Documented that `change_password()` advances the index nonce counter when verifying the current password via `export()`, even if the supplied current password is wrong. The vault remains intact and functional.
* Removed a hardcoded test count from the README to avoid documentation drift.

## [0.1.1] - 2026-05-27

### Changed

* Made internal modules private so that only the documented public API is exposed.

### Documentation

* Clarified `retrieve()` semantics: returned plaintext is caller-owned and must be handled carefully by the caller.
* Clarified `mlock` semantics: only internal ciphertext buffers are locked, not every secret-related allocation.
* Clarified the `unsafe impl Send/Sync` rationale for the memory-locking module.
* Fixed CI badge links to point to the `memseal` repository.
* Added crates.io and docs.rs badges.

## [0.1.0] - 2026-05-27

Initial release.

### Added

* Password-based vault using Argon2i for key derivation, with 128 MiB memory cost and 4 iterations by default.
* HKDF-SHA256 subkey derivation for separate encryption and HMAC keys.
* XChaCha20-Poly1305 AEAD encryption for vault index data and entries.
* Vault header authentication as additional authenticated data for index encryption.
* HMAC-SHA256 entry-name hashing so entry names are not stored in plaintext.
* Per-entry AAD binding using the HMAC-derived entry key and data counter to detect entry-swap/tampering attacks.
* Per-export index nonce rotation driven by a monotonic counter, with overflow checks.
* Internal ciphertext buffers locked with `mlock` via `memsec` where supported.
* Zeroization of internal temporary key material and plaintext where possible.
* File persistence with atomic writes using a temporary file, rename, fsync, and `0600` permissions on Unix.
* Bounded parsing for vault file size, header length, KDF parameters, entry name length, entry data size, and index entry count.
* Public API: `Vault::create`, `Vault::open`, `Vault::load`, `Vault::save`, `Vault::store`, `Vault::retrieve`, `Vault::remove`, `Vault::change_password`, and `Vault::export`.

[Unreleased]: https://github.com/samjanny/memseal/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/samjanny/memseal/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/samjanny/memseal/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/samjanny/memseal/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/samjanny/memseal/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/samjanny/memseal/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/samjanny/memseal/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/samjanny/memseal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/samjanny/memseal/releases/tag/v0.1.0
