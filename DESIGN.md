# memseal Design

This document describes the on-disk vault format, the key derivation chain,
nonce handling, the AAD bindings that protect against tampering, and the
bounded-parsing rules enforced when opening a vault.

It targets format version `VAULT_VERSION = 1` and index version
`VAULT_INDEX_VERSION = 1` (see `src/constants.rs`). Anything called out as
"current" here is fixed for this version; format changes are reserved for
future major or minor bumps as described under `Versioning` below.


## 1. Scope and non-goals

memseal is a password-based encrypted vault for small named secrets. The
format is designed for:

* Authenticated encryption of every byte that affects decryption outcome.
* Resistance to single-file tampering: bit flips, truncation, header
  swapping, and ciphertext substitution must be detected.
* Bounded parsing: a malformed file cannot cause unbounded memory
  allocation or excessive CPU work before being rejected.

It is explicitly NOT designed for:

* Rollback protection (see README threat model). An attacker who can
  replace the file with an older valid copy cannot be detected by the
  format alone.
* Streaming or random access; the entire vault is parsed at once.
* Multi-writer concurrency on the same file.


## 2. On-disk format

The vault file is a single blob produced by `Vault::export()` and consumed
by `Vault::open()` / `Vault::load()`. Layout, in declaration order:

```
offset  length        field                          notes
------  ------------  -----------------------------  -------------------------
0       4             header_len (u32 little-endian) length of the header JSON
4       header_len    header_json                    UTF-8 JSON, see section 3
H       24            index_nonce                    XChaCha20 nonce (random per export)
H+24    8             nonce_counter (u64 LE)         see section 9 (oddity)
H+32    *             encrypted_index                XChaCha20-Poly1305 with AAD
```

Where `H = 4 + header_len`. The trailing `encrypted_index` is the
ciphertext with a 16-byte Poly1305 tag appended.

Total file size is bounded by `MAX_VAULT_FILE_SIZE = 256 MiB`, enforced on
both sides: `Vault::load` refuses to read a larger file, and
`Vault::export` refuses to produce one (so anything `export()`/`save()`
emits can be loaded back). The `header_len` field is also bounded by this
value; values larger than `MAX_VAULT_FILE_SIZE` are rejected before any
allocation.

### 2.1 Parsing rules enforced by `Vault::open`

In order, `Vault::open(password, data)` enforces:

1. `data.len() >= 4` (room for `header_len`).
2. `header_len <= MAX_VAULT_FILE_SIZE`.
3. `4 + header_len` does not overflow `usize`.
4. `data.len() >= 4 + header_len + 24 + 8` (room for nonce and counter).
5. `header_json` parses as valid `VaultHeader` JSON.
6. `validate_header(&header)` succeeds (see section 3).
7. XChaCha20-Poly1305 verification of `encrypted_index` succeeds with the
   serialized header JSON as AAD.
8. The decrypted index JSON parses and its `version` is in
   `SUPPORTED_VAULT_INDEX_VERSIONS`.

Failures at steps 1-6 return `VaultError::CorruptedData(...)`. Failure at
step 7 returns `VaultError::InvalidPassword` (the AEAD does not
distinguish "wrong key" from "tampered ciphertext or AAD" by design).
Failure at step 8 returns `VaultError::CorruptedData(...)`.


## 3. Header (`VaultHeader`)

Serialized as JSON. Fields (all required, no serde defaults):

| field             | type     | meaning                                         |
| ----------------- | -------- | ----------------------------------------------- |
| `version`         | u16      | must equal `VAULT_VERSION` (currently `1`)      |
| `kdf_salt`        | [u8; 16] | random salt for Argon2i                         |
| `kdf_iterations`  | u32      | Argon2i `t`, in `[MIN_KDF_ITERATIONS, 100]`     |
| `kdf_memory_cost` | u32      | Argon2i `m` in KiB, in `[MIN_KDF_MEMORY, 4 GiB]`|
| `key_length`      | usize    | must equal `KEY_LEN` (currently `32`)           |

The header has two responsibilities:

* Carry the parameters needed to re-derive the master key from a password
  on `open()`.
* Authenticate itself as AAD against the encrypted index. Any byte
  modification to the serialized JSON causes index decryption to fail.

The exact bytes used as AAD are produced by `serde_json::to_vec(&header)`,
not the bytes read from the file. This means semantically-equal JSON
encodings that differ in formatting (whitespace, field order) would
diverge from the canonical AAD. The reference implementation always
produces the same canonical encoding via `serde_json::to_vec`, so this is
not a problem in practice for files produced by memseal; it is a property
to be aware of if a third party ever re-encodes the header.


## 4. Key derivation chain

```
password (>= 8 bytes)
    |
    | Argon2i (orion):
    |   t = header.kdf_iterations  (default 4)
    |   m = header.kdf_memory_cost (default 131072 KiB = 128 MiB)
    |   p = 1 (fixed; orion limitation)
    |   salt = header.kdf_salt (16 bytes, random per vault)
    |   output = 32 bytes
    v
master_key (32 bytes)
    |
    | HKDF-SHA256:
    |   salt = header.kdf_salt
    |   ikm  = master_key
    |   info = "MEMSEAL_SUBKEY_ENC_v1"   |   info = "MEMSEAL_SUBKEY_HMAC_v1"
    v                                    v
enc_key (32 bytes)                  hmac_key (32 bytes)
```

The `enc_key` is used for all XChaCha20-Poly1305 operations on the index
and on per-entry payloads. The `hmac_key` is used exclusively for
HMAC-SHA256 of entry names (see section 7).

Both subkeys are stored in `SecureMemoryVault` (mlock'd ciphertext
buffers) for the lifetime of the `Vault` and zeroized on drop. The raw
master key is zeroized as soon as the subkeys are derived.


## 5. Nonce generation

All 24-byte XChaCha20 nonces are generated randomly from the OS CSPRNG
(`OsRng`) at encryption time and stored next to the ciphertext they
protect:

| stream       | generated by                  | stored at                                   |
| ------------ | ----------------------------- | ------------------------------------------- |
| index nonce  | `advance_nonce()` per export  | file offset `H` (section 2)                 |
| entry data   | `Vault::store()` per call     | first 24 bytes of `encrypted_data`          |
| entry name   | `Vault::store()` per call     | first 24 bytes of `encrypted_name`          |

Nonces are never re-derived when reading: `open()` uses the nonce read
from the file, and `with_secret()` / `retrieve()` / `change_password()` use
the nonce prefixed to each entry ciphertext. XChaCha20's 192-bit nonce is
sized precisely so that random generation makes collisions negligible.

Random generation (rather than derivation from a monotonic counter, as in
formats up to 0.1.5) also covers the state-fork case: if the same
persisted vault bytes are opened by two `Vault` instances and both
export, counter-derived nonces would repeat across the two exports under
the same key, while random nonces cannot. Files produced by earlier
releases remain fully readable, since reading never re-derives a nonce.

### 5.1 Counters and nonce rotation on export

The counters survive the switch to random nonces as authenticated,
monotonic state:

* `nonce_counter` is incremented (with checked overflow) by
  `advance_nonce()` on every `Vault::export()`, before a fresh random
  index nonce is generated and the index is re-encrypted.
* `data_nonce_counter` is incremented per stored entry; the per-entry
  `data_counter` is bound into the entry AAD (section 6) and checked for
  monotonic consistency on `open()` (section 7).

Counter overflow at `u64::MAX` is treated as a hard error, not a wrap.


## 6. AAD bindings

memseal binds context to ciphertext via XChaCha20-Poly1305's AAD field
in three places:

| ciphertext           | AAD                                            | purpose                                           |
| -------------------- | ---------------------------------------------- | ------------------------------------------------- |
| `encrypted_index`    | `serde_json::to_vec(&header)`                  | header tampering detection                        |
| per-entry data       | `hmac_key_hex(plaintext_name) || data_counter`| entry-swap and counter-replay detection           |
| per-entry name       | same as per-entry data                         | name and data ciphertexts share the binding       |

`hmac_key_hex(name)` is HMAC-SHA256(hmac_key, name) hex-encoded to lower
case. Because the AAD contains both the entry's HMAC key and its
`data_counter`, an attacker who copies the encrypted blob of entry A into
the slot of entry B cannot decrypt it: B's AAD differs (different HMAC of
the plaintext name), and the AEAD will reject.


## 7. Encrypted index

After AEAD verification, the index decrypts to a JSON document with the
shape:

```json
{
  "version": 1,
  "nonce": [24 bytes],
  "nonce_counter": 7,
  "data_nonce_counter": 42,
  "files": {
    "<hmac_key_hex of plaintext name>": {
      "location": "Inline" | { "SmallFileInPack": { ... } } | { "LargeFile": { ... } },
      "created": 0,
      "modified": 0,
      "is_dummy": false,
      "encrypted_data": [bytes] | null,
      "encrypted_name": [bytes] | null,
      "data_counter": 17
    },
    ...
  }
}
```

The map keys are HMAC-SHA256 of plaintext entry names, hex-encoded. This
prevents leaking entry names through the serialized vault. Entry name
lookup at runtime always re-derives the HMAC of the plaintext name with
the in-memory `hmac_key` before consulting the map.

`MAX_INDEX_ENTRIES = 1024` is enforced on `insert_file` and again on
`open()`: after the index JSON is decrypted and parsed, an index whose
`files` map holds more than `MAX_INDEX_ENTRIES` entries is rejected with
`VaultError::CorruptedData` before the in-memory `VaultIndex` is built.
The file-size and ciphertext-size bounds upstream already make it
impractical to embed many more than this in a single 256 MiB file; the
explicit cap on `open()` closes the gap so a crafted index cannot force a
larger map than the format allows.


## 8. Per-entry encryption

For each stored secret, the in-memory metadata holds two ciphertext
blobs (`encrypted_data` and `encrypted_name`), each prefixed with its
24-byte nonce:

```
encrypted_data = data_nonce (24B) || XChaCha20-Poly1305(enc_key, data_nonce, plaintext_data, aad=entry_aad)
encrypted_name = name_nonce (24B) || XChaCha20-Poly1305(enc_key, name_nonce, plaintext_name, aad=entry_aad)
entry_aad      = hmac_key_hex(plaintext_name) bytes || data_counter as u64 LE
```

`data_nonce` and `name_nonce` are independent random values generated by
`store()` (section 5). The `data_counter` no longer drives nonce
derivation; it remains in the AAD so that ciphertexts cannot be replayed
across counter generations of the same entry name.

Limits:

* `MAX_ENTRY_NAME_LEN = 255` bytes.
* `MAX_ENTRY_DATA_SIZE = 64 MiB`.

Note that the aggregate bound across all entries is tighter than these
per-entry limits suggest, because of the JSON encoding of ciphertext
bytes (see section 9.3): total stored plaintext beyond roughly 70 MiB
makes the export exceed `MAX_VAULT_FILE_SIZE` and fail.


## 9. Known oddities (current format)

These behaviors are pinned by tests and documented here so future format
revisions can address them deliberately.

### 9.1 Unused exported `nonce_counter` field

`Vault::export()` writes `index.nonce_counter` as 8 bytes (LE u64) at
offset `4 + header_len + 24`. `Vault::open()` skips those 8 bytes; the
authoritative `nonce_counter` is recovered from the encrypted index JSON
(see section 7). The on-disk field is therefore wire-format dead weight.
It does not affect security (the encrypted-index counter is authenticated
via AAD), but the format would be tidier without it.

Cleanup is scheduled for `0.2.x` because removing the field is a vault
format break (`VAULT_VERSION` bump). See `ROADMAP.md`.

### 9.2 Header JSON canonicalization

As noted in section 3, the AAD used for index encryption is the bytes
returned by `serde_json::to_vec(&header)` at encryption time, and at
open() the same call is made on the deserialized header. Both
serializations are produced by the same code path so they agree, but a
hand-edited header file with semantically-equal but textually-different
JSON would not round-trip.

### 9.3 JSON number-array encoding of ciphertext bytes

`encrypted_data` and `encrypted_name` are serialized into the index JSON
as arrays of integers (`[31, 254, ...]`), which costs roughly 3.6 output
bytes per ciphertext byte for uniformly distributed values. The practical
consequence is that the aggregate plaintext a vault can hold is about
70 MiB before the export crosses `MAX_VAULT_FILE_SIZE`, far below what
`MAX_ENTRY_DATA_SIZE * MAX_INDEX_ENTRIES` would suggest. `Vault::export`
enforces the bound and fails cleanly rather than producing a file that
`Vault::load` would refuse.

A denser encoding (base64 or a binary index format) is scheduled for
`0.2.x` together with the other format cleanup, since changing the index
JSON structure is a `VAULT_INDEX_VERSION` break. See `ROADMAP.md`.


## 10. Bounded parsing summary

All inputs that affect parsing memory or CPU are bounded before use:

| field                     | bound                        | enforced by                  |
| ------------------------- | ---------------------------- | ---------------------------- |
| file size (reading)       | `MAX_VAULT_FILE_SIZE = 256 MiB` | `Vault::load`             |
| file size (writing)       | `MAX_VAULT_FILE_SIZE = 256 MiB` | `Vault::export`           |
| `header_len`              | `<= MAX_VAULT_FILE_SIZE`     | `Vault::open` step 2         |
| `header.version`          | in `SUPPORTED_VAULT_VERSIONS`| `validate_header`            |
| `header.kdf_memory_cost`  | `[MIN_KDF_MEMORY, 4 GiB]`    | `validate_header`            |
| `header.kdf_iterations`   | `[MIN_KDF_ITERATIONS, 100]`  | `validate_header`            |
| `header.key_length`       | `== KEY_LEN (32)`            | `validate_header`            |
| index `version`           | in `SUPPORTED_VAULT_INDEX_VERSIONS` | `Vault::open` step 8  |
| entry name length         | `<= MAX_ENTRY_NAME_LEN (255)`| `Vault::store`               |
| entry data size           | `<= MAX_ENTRY_DATA_SIZE (64 MiB)` | `Vault::store`          |
| index entry count         | `<= MAX_INDEX_ENTRIES (1024)`| `VaultIndex::insert_file`, `Vault::open` |
| password length           | `>= MIN_PASSWORD_LEN (8)`    | `Vault::create`              |


## 11. Versioning

`VAULT_VERSION` (header) and `VAULT_INDEX_VERSION` (index JSON) are
independent. Either bumping signals a format break. Today both are `1`.

Changes that require a version bump:

* Adding, removing, renaming, or reordering header fields.
* Changing any HKDF `info` prefix string.
* Changing the KDF algorithm or its default parameters.
* Changing the layout of section 2 (nonce position, counter field, etc.).
* Changing the structure of the index JSON.

Changes that do NOT require a version bump:

* Adding new validation rules that only refine existing bounds (since
  older valid files remain valid).
* Internal API changes that do not affect the byte format.

When a format break ships, the new code MUST detect older versions via
the header `version` field and handle them explicitly. The one thing it
MUST NOT do is silently re-interpret older bytes as the current format:
that path leads to wrong-key derivation, AAD mismatches, or worst-case
incoherent reads that surface as ambiguous errors. Detection is cheap
(the `version` field is the second u16 read after `header_len`) and
mandatory.

How to handle a detected older version is a design choice; see the next
section.


### 11.1 Upgrade strategy

When `VAULT_VERSION` or `VAULT_INDEX_VERSION` is bumped, every existing
vault file in the wild keeps the old number. The library has three
broad options for what to do with such a file. The right one is decided
case-by-case at break time, not preemptively.

#### Option A: Read-old, write-new (transparent migration)

The new build keeps a separate code path for the old format. `open()`
detects the old `version` and dispatches to the legacy reader; the
in-memory `Vault` is identical to one created from a new file. The
next `save()` writes the new format, so any vault touched by the new
binary is upgraded in place.

Use when:

* The break is small (e.g., removing the dead-weight `nonce_counter`
  field from section 9.1, or adding a new optional header field).
* The legacy reader can be implemented in a few dozen lines without
  re-deriving crypto primitives.

Caveats:

* Legacy reader code must be kept and tested across at least one
  further release cycle.
* The first `save()` silently changes the on-disk format. This is
  surprising for callers who only meant to read. Document it in the
  release notes and in the `open()` doc comment.
* The legacy reader expands the attack surface of `open()`; it MUST
  use the same bounded-parsing rules as the current reader (section
  2.1).

#### Option B: Explicit migration function

The library exposes a one-shot function (e.g.,
`Vault::migrate(path, password)`) that reads an old file and writes a
new file. The core `open()` only understands the current format and
rejects older versions with a clear, distinct error like
`VaultError::OutdatedFormat { found: u16, expected: u16 }`.

Use when:

* The break is large (e.g., swapping the KDF from Argon2i to
  Argon2id, or changing HKDF info strings).
* The migration is expensive (re-deriving the master key, re-encrypting
  every entry) and the caller should be aware that it is happening.
* The migration could fail mid-way and the caller needs to take a
  backup or pick a recovery strategy.

Caveats:

* Worse UX: callers must call the migration explicitly. Discoverability
  via the error message is essential.
* Backups: the migration MUST write to a temp file and rename, the same
  way `save()` does, so a crash mid-migration does not destroy the only
  copy.

#### Option C: Hard break (no upgrade path)

The new build rejects older versions with no migration provided.

Use only when:

* The old format is known to be cryptographically broken or contains
  a vulnerability that cannot be re-encrypted away (e.g., a leaked
  test vector for a fixed nonce). In that case, the right path is to
  rotate keys/passwords manually, not to migrate.
* No production users exist yet (e.g., pre-`0.1.0` development).

Never use C as a shortcut to avoid writing a migration when one is
feasible. memseal is a library: silently breaking integrators is a
release-blocking bug.

#### Decision rubric for memseal

For the foreseeable `0.x` releases:

| Change                                              | Default option |
| --------------------------------------------------- | -------------- |
| Add/remove a header field                           | A              |
| Remove the dead-weight `nonce_counter` field (9.1)  | A              |
| Add a new optional index field with a default       | not a break    |
| Change a HKDF `info` prefix                         | B              |
| Swap KDF algorithm                                  | B              |
| Change AEAD (e.g., XChaCha20-Poly1305 -> something) | B              |
| Format known to be cryptographically broken         | C, with a CVE  |

Document the decision in `CHANGELOG.md` under the release that ships
the break, and in the migration function's doc comment if option B is
used.
