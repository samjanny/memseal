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
- Clean up the on-disk vault format: drop the 8-byte `nonce_counter` field
  written by `export()` at offset `4 + header_len + 24`. It is never read
  back by `open()` (the authoritative counter is recovered from the
  encrypted index JSON), so it is dead weight. Requires a `VAULT_VERSION`
  bump and is acceptable here because 0.2.x already ships an API break.

## 0.3.x - KDF configuration and review

- Revisit Argon2i vs Argon2id.
- Decide whether to keep Argon2i as a documented trade-off or introduce Argon2id for new vaults.
- Add safe KDF configuration options.
- Allow callers to choose Argon2 memory cost and iteration count through bounded presets or a validated builder API.
- Preserve secure defaults for casual users.
- Store KDF parameters in the vault header and authenticate them as AAD.
- Reject unsafe, malformed, or resource-exhaustive KDF parameters when opening vaults.
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