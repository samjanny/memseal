# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ROADMAP.md` outlining planned milestones for the 0.1.x through 0.5.x lines.

### Documentation
- Threat model: documented that memseal does not provide rollback protection.

## [0.1.3] - 2026-05-27

### Documentation
- README: clarity and detail revisions across overview, API, and threat model sections.

## [0.1.2] - 2026-05-27

### Documentation
- Documented that `change_password` advances the index nonce counter even when the
  supplied current password is wrong; the vault remains intact and functional.
- Removed a hardcoded test count from the README to avoid drift.

## [0.1.1] - 2026-05-27

### Changed
- Made internal modules private so that only the documented public API is exposed.

### Documentation
- README clarifications on `retrieve()`, mlock semantics, and `Send`/`Sync` guarantees.
- Badges now point to the memseal repository; added crates.io and docs.rs badges.

## [0.1.0] - 2026-05-27

Initial release.

### Added
- Password-based vault using Argon2i for key derivation (128 MiB, 4 iterations by default).
- XChaCha20-Poly1305 AEAD encryption with the vault header bound as additional authenticated data.
- Encrypted index with HMAC-SHA256 filename hashing so entry names are not exposed in the file.
- Per-export nonce rotation driven by a monotonic counter, with overflow checks.
- mlock-backed ciphertext buffers via `memsec` to reduce swap exposure of secret material.
- File persistence with atomic write (temp file + rename) and `0600` permissions on Unix.
- Public API: `Vault::new`, `open`, `load`, `save`, `store`, `retrieve`, `change_password`, `export`.

[Unreleased]: https://github.com/samjanny/memseal/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/samjanny/memseal/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/samjanny/memseal/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/samjanny/memseal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/samjanny/memseal/releases/tag/v0.1.0
