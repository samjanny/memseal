# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) while in the `0.x` development series.

## [Unreleased]

### Added

* Added `ROADMAP.md` outlining planned milestones for the `0.1.x` through `0.5.x` lines.

### Documentation

* Documented that `memseal` does not provide rollback protection. An attacker who can replace a vault file with an older valid copy can cause the application to load older data unless freshness is tracked externally.

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

[Unreleased]: https://github.com/samjanny/memseal/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/samjanny/memseal/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/samjanny/memseal/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/samjanny/memseal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/samjanny/memseal/releases/tag/v0.1.0
