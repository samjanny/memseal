# Roadmap

## 0.1.x - Stabilization

- Improve documentation and threat model wording.
- Add `CHANGELOG.md`.
- Document known limitations, including lack of rollback protection.
- Add `DESIGN.md` describing the vault format, key derivation, nonce derivation, and AAD.
- Expand tampering/corruption tests.

## 0.2.x - Plaintext access API

- Add a callback-based access API for short-lived plaintext use.
- Keep `retrieve()` for convenience, but document it as caller-owned plaintext.
- Improve examples around plaintext handling.
- Done: format version 2 drops the unread 8-byte `nonce_counter` from the
  envelope and replaces the JSON index with a length-prefixed binary
  encoding (see `DESIGN.md` sections 7 and 12). Version 1 files are read
  and rewritten on the next save.

## 0.3.x - KDF configuration and review

- Done: format version 2 uses Argon2id (RustCrypto `argon2`); version 1
  files are re-keyed on open (see `DESIGN.md` sections 4 and 12).
- Add safe KDF configuration options.
- Allow callers to choose Argon2 memory cost and iteration count through bounded presets or a validated builder API.
- Preserve secure defaults for casual users.
- Store KDF parameters in the vault header and authenticate them as AAD.
- Revisit the fixed bounds `open()` enforces today (32 MiB to 256 MiB, 3 to 10 iterations) once presets exist, keeping the worst-case cost of opening a hostile file small.
- Preserve compatibility with existing vault formats where possible.

## 0.4.x - Format and threat-model documentation

- Publish a precise vault format document.
- Document serialization, authenticated data, counters, nonce derivation, KDF parameters, and versioning.
- Add test vectors.

## 0.5.x - Hardening

- Add fuzzing for vault parsing.
- Improve error taxonomy.
- Add additional corruption/tampering tests.
- Review `unsafe` boundaries and `Send`/`Sync` invariants.

## Future

- Optional application-provided context/AAD.
- Optional freshness/rollback integration hooks.
- External review before considering `1.0`.