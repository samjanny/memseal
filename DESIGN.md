# memseal Design

This document describes the on-disk vault format, the key derivation chain,
nonce handling, the AAD bindings that protect against tampering, and the
bounded-parsing rules enforced when opening a vault.

It targets format version `VAULT_VERSION = 2` and index version
`VAULT_INDEX_VERSION = 2` (see `src/constants.rs`). Anything called out as
"current" here is fixed for this version; format changes are reserved for
future major or minor bumps as described under `Versioning` below. Files
written in format version 1 (releases up to 0.2.1) are still read; section
12 describes that format and how it is migrated.


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
H+24    *             encrypted_index                XChaCha20-Poly1305 with AAD
```

Where `H = 4 + header_len`. The trailing `encrypted_index` is the
ciphertext with a 16-byte Poly1305 tag appended; its plaintext is the
binary index of section 7.

Total file size is bounded by `MAX_VAULT_FILE_SIZE = 256 MiB`, enforced on
both sides: `Vault::load` refuses to read a larger file, and
`Vault::export` refuses to produce one (so anything `export()`/`save()`
emits can be loaded back). The `header_len` field has its own, much
tighter bound, `MAX_HEADER_JSON_LEN = 4 KiB`: the header is plaintext and
is parsed before anything has been authenticated, and a real header is
about 150 bytes. Larger values are rejected before the JSON is touched.

### 2.1 Parsing rules enforced by `Vault::open`

In order, `Vault::open(password, data)` enforces:

1. `data.len() <= MAX_VAULT_FILE_SIZE` (256 MiB), the same cap `load`
   applies to the file, so the AEAD pass and the index allocation below
   are bounded whatever the source of the bytes.
2. `data.len() >= 4` (room for `header_len`).
3. `header_len <= MAX_HEADER_JSON_LEN` (4 KiB). This also rules out any
   offset overflow in the steps below.
4. `data.len() >= 4 + header_len + 24` (room for header and nonce).
5. `header_json` parses as valid `VaultHeader` JSON with no unknown
   fields.
6. `validate_header(&header)` succeeds (see section 3).
7. `header_json` is byte-for-byte the canonical serialization of the
   parsed header (`serde_json::to_vec`), which is also the AAD of step 9.
   If `header.version` is 1, the 8 legacy counter bytes that follow the
   nonce must also be present and are skipped (section 12).
8. The bytes that remain are `encrypted_index`, and they must be able to
   hold a Poly1305 tag around the smallest index plaintext: at least 38
   bytes under a version 2 header (16 for the tag plus the 22-byte
   preamble of an empty index, section 7), at least 18 under a version 1
   header (the tag plus a two-byte JSON document, a deliberately loose
   floor). Anything shorter could not decode even if it authenticated.
   This is the last check before Argon2 runs with the parameters taken
   from the header.
9. Argon2id (Argon2i under a version 1 header) and HKDF derive the
   subkeys, then XChaCha20-Poly1305 verification of `encrypted_index`
   succeeds with the serialized header JSON as AAD.
10. The decrypted index decodes under the rules of section 7 (version
    tag, entry count, every length against the remaining bytes and the
    documented bounds, no duplicate keys, no trailing bytes). A version 1
    header selects the legacy JSON decoder of section 12 instead.
11. `data_nonce_counter` is strictly greater than every stored
    `data_counter` (section 7).

Steps 1-8 are implemented by `parse_envelope`, a pure function with no
key derivation, and step 10 by `decode_index`; both are the intended fuzz
targets. Failures at steps 1-8 return `VaultError::CorruptedData(...)`
without running Argon2: a file cut off before or inside the minimum index
is a structural error, not an authentication failure. Failure at step 9
returns `VaultError::InvalidPassword`: the AEAD does not distinguish
"wrong key" from "tampered ciphertext or AAD" by design, so the variant
means "authentication failed", not "the password was mistyped". A file
truncated further in, with at least the minimum index left, fails here
too. Failures at steps 10 and 11 return `VaultError::CorruptedData(...)`.


## 3. Header (`VaultHeader`)

Serialized as JSON. Fields (all required, no serde defaults):

| field             | type     | meaning                                         |
| ----------------- | -------- | ----------------------------------------------- |
| `version`         | u16      | one of `SUPPORTED_VAULT_VERSIONS` (`1` or `2`); `export` always writes `VAULT_VERSION` (`2`) |
| `kdf_salt`        | [u8; 16] | random salt for Argon2                          |
| `kdf_iterations`  | u32      | Argon2 `t`, in `[3, 10]`                        |
| `kdf_memory_cost` | u32      | Argon2 `m` in KiB, in `[32 MiB, 256 MiB]`       |
| `key_length`      | usize    | must equal `KEY_LEN` (currently `32`)           |

The KDF variant is implied by `version`: Argon2id for version 2, Argon2i
for version 1 (section 12). It is not a separate header field because a
different variant is by definition a different format version (section
11).

The KDF bounds are deliberately narrow; section 10.1 explains the policy.
Every vault written by this library uses the defaults (128 MiB, 4
iterations), which sit inside both ranges.

The header has two responsibilities:

* Carry the parameters needed to re-derive the master key from a password
  on `open()`.
* Authenticate itself as AAD against the encrypted index. Any byte
  modification to the serialized JSON causes `open` to fail.

The exact bytes used as AAD are produced by `serde_json::to_vec(&header)`
from the parsed header, not the bytes read from the file. On its own that
would leave room for unauthenticated bytes: a re-encoded header with
different whitespace, field order, or extra fields parses to the same
struct and therefore the same AAD. `parse_envelope` closes that gap by
requiring the stored header bytes to equal the canonical serialization of
the parsed header (step 7 of section 2.1) and by rejecting unknown fields
at parse time. Every file memseal has written is in canonical form, so the
check costs nothing for genuine files, and any other encoding is reported
as `CorruptedData` before Argon2 runs.


## 4. Key derivation chain

```
password (>= 8 bytes)
    |
    | Argon2id, version 0x13 (RustCrypto `argon2`):
    |   t = header.kdf_iterations  (default 4)
    |   m = header.kdf_memory_cost (default 131072 KiB = 128 MiB)
    |   p = 1 (single lane)
    |   salt = header.kdf_salt (16 bytes, random per vault)
    |   output = 32 bytes
    |   (format version 1: Argon2i from orion, same t, m, p, salt)
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

Both subkeys are stored in a `LockedSecret` each for the lifetime of the
`Vault`: a single `mlock`'d allocation (on Linux also marked
`MADV_DONTDUMP` by `memsec`) that is zeroized on drop. The allocation
comes from `memsec::malloc_sized`, so it occupies pages no other
allocation shares and sits between two guard pages. Page exclusivity is
required for the lock to mean anything: `munlock` is not reference
counted, so two containers in one page would unlock each other on drop.
The cost is one page of `RLIMIT_MEMLOCK` per container, two per open
`Vault`, and briefly four while `change_password` (or the re-keying of a
version 1 file inside `open`) holds the old and the new index together; a
failed `mlock` is reported as an error rather than degraded to unlocked
memory.

The subkeys are kept in the clear inside the locked pages. Releases up to
0.2.1 encrypted them in memory under a per-container stream key, but that
key had to live in memory with the same protection as the ciphertext, so
the layer protected nothing against a reader of the pages and cost an
AEAD operation on every key use. The raw master key is zeroized as soon
as the subkeys are derived; `open()` derives them once per header, which
means twice for a version 1 file (the second time under the new header
chosen by the in-memory re-keying of section 12). HKDF writes the subkeys
straight into zeroizing buffers, and the Argon2id memory matrix is owned
by `derive_master_key` and wiped on drop: its last block is one hash away
from the master key, and the `argon2` crate's own allocating entry point
frees the matrix without clearing it.


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

Both counters belong to one generation of keys, not to the vault for its
whole life. `change_password()` and the re-keying of a version 1 file
(section 12) build a fresh index under the new keys, and that index
starts again with `nonce_counter = 0` and `data_nonce_counter = 0`; the
entries are re-encrypted under new `data_counter` values as they are
moved over. Within one generation neither counter ever decreases, and an
`export()` that is refused for size does not advance `nonce_counter`.

Nothing reads `nonce_counter` back: `open()` decodes it and the next
export writes it incremented, but no check depends on its value. It is
not a freshness or rollback signal (section 1), and a reader of the
format must not treat a lower value as evidence of an older file.


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

After AEAD verification, the index decrypts to a binary document. All
integers are little-endian:

```
u16     version            must equal VAULT_INDEX_VERSION (currently 2)
u64     nonce_counter      section 5.1
u64     data_nonce_counter section 5.1
u32     entry_count        <= MAX_INDEX_ENTRIES
entry_count times:
  [32]  hmac_key           HMAC-SHA256(hmac_key, plaintext_name), raw
  u64   data_counter       bound into the entry AAD (section 6)
  u32   name_ct_len        in [40, 24 + MAX_ENTRY_NAME_LEN + 16]
  [..]  name_ct            data of section 8, nonce prefix included
  u32   data_ct_len        in [40, 24 + MAX_ENTRY_DATA_SIZE + 16]
  [..]  data_ct            data of section 8, nonce prefix included
```

Nothing follows the last entry. Overhead is 22 bytes for the preamble and
48 bytes per entry, so the file size is the sum of the ciphertexts plus
a few hundred bytes; in format version 1 the same data cost about 3.6
bytes per ciphertext byte (section 12). Measured against the plaintext
secrets, each entry costs 128 bytes plus the length of its name: 48 bytes
of index fields plus a 24-byte nonce and a 16-byte tag for each of the two
ciphertexts.

After decoding, `open` also checks that `data_nonce_counter` is strictly
greater than every stored `data_counter`. The counter is bound into the
entry AAD (section 6); a vault written by this library always advances it
past every stored entry, so a violation means the authenticated index is
inconsistent and is reported as `CorruptedData` rather than letting a
later `store` reissue a `(name, counter)` pair under which an older
ciphertext for that name could be replayed.

The entry keys are HMAC-SHA256 of plaintext entry names. This prevents
leaking entry names through the serialized vault. Entry name lookup at
runtime always re-derives the HMAC of the plaintext name with the
in-memory `hmac_key` before consulting the map. In memory and in the
entry AAD the key is used in its lower-case hex form (section 6); the
raw 32 bytes are only a storage encoding of the same value.

The decoder (`decode_index`) checks every field before acting on it:

* the version tag must match;
* `entry_count` must not exceed `MAX_INDEX_ENTRIES = 1024`, and
  `entry_count` times the smallest possible entry (128 bytes) must fit in
  the bytes that remain, before the map is allocated;
* each length prefix must lie within the bounds above (the lower bound is
  a nonce plus a tag around an empty plaintext, the upper bound what
  `store()` can produce) and within the remaining input, before the
  corresponding bytes are copied;
* a duplicate key or trailing bytes after the last entry reject the index.

The same `MAX_INDEX_ENTRIES` cap applies to `insert_by_key` at runtime,
where exceeding it is `VaultError::InvalidInput`; on `open()` it is
`VaultError::CorruptedData`. The 256 MiB file bound already makes larger
indexes impractical; the explicit checks keep `retrieve()` and
`change_password()` from ever allocating for a blob outside the documented
limits.


## 8. Per-entry encryption

For each stored secret, the index holds two ciphertext blobs
(`encrypted_data` and `encrypted_name`), each prefixed with its 24-byte
nonce:

```
encrypted_data = data_nonce (24B) || XChaCha20-Poly1305(enc_key, data_nonce, plaintext_data, aad=entry_aad)
encrypted_name = name_nonce (24B) || XChaCha20-Poly1305(enc_key, name_nonce, plaintext_name, aad=entry_aad)
entry_aad      = hmac_key_hex(plaintext_name) bytes || data_counter as u64 LE
```

`data_nonce` and `name_nonce` are independent random values generated by
`store()` (section 5). The `data_counter` no longer drives nonce
derivation; it remains in the AAD so that ciphertexts cannot be replayed
across counter generations of the same entry name. The AAD uses the hex
form of the key, as format version 1 did; the raw 32-byte key in the
index is only its storage encoding.

Limits:

* `MAX_ENTRY_NAME_LEN = 255` bytes.
* `MAX_ENTRY_DATA_SIZE = 64 MiB`.

The aggregate bound is the file bound: total stored secrets plus 128
bytes and the name length per entry (section 7) must stay under
`MAX_VAULT_FILE_SIZE`, so a vault holds a little under 256 MiB of secrets
in total, and `Vault::export` fails cleanly rather than producing a file
that `Vault::load` would refuse. The export size follows from the entry
lengths alone, so the bound is checked before the index is encoded or
encrypted: the refusal allocates nothing and leaves the index nonce and
`nonce_counter` untouched.


## 9. Known oddities (current format)

### 9.1 Header JSON canonicalization

As noted in section 3, the AAD used for index encryption is the bytes
returned by `serde_json::to_vec(&header)` at encryption time, and at
open() the same call is made on the deserialized header. The file is
required to carry exactly those bytes, so a hand-edited header with
semantically-equal but textually-different JSON is rejected as
`CorruptedData` rather than silently accepted with unauthenticated bytes.
A third party that re-encodes the header must reproduce `serde_json`'s
compact output with the fields in declaration order.


## 10. Bounded parsing summary

All inputs that affect parsing memory or CPU are bounded before use:

| field                     | bound                        | enforced by                  |
| ------------------------- | ---------------------------- | ---------------------------- |
| file size (reading)       | `MAX_VAULT_FILE_SIZE = 256 MiB` | `Vault::load`             |
| file size (writing)       | `MAX_VAULT_FILE_SIZE = 256 MiB` | `Vault::export`           |
| `header_len`              | `<= MAX_HEADER_JSON_LEN (4 KiB)` | `Vault::open` step 3     |
| `header.version`          | in `SUPPORTED_VAULT_VERSIONS`| `validate_header`            |
| `header.kdf_memory_cost`  | `[32 MiB, 256 MiB]`          | `validate_header`            |
| `header.kdf_iterations`   | `[3, 10]`                    | `validate_header`            |
| `header.key_length`       | `== KEY_LEN (32)`            | `validate_header`            |
| `encrypted_index` length  | `>= 38` (`>= 18` under a v1 header) | `Vault::open` step 8, before Argon2 |
| index `version`           | `== VAULT_INDEX_VERSION` (or 1 under a v1 header) | `decode_index` |
| entry name length         | `<= MAX_ENTRY_NAME_LEN (255)`| `Vault::store`               |
| entry data size           | `<= MAX_ENTRY_DATA_SIZE (64 MiB)` | `Vault::store`          |
| `encrypted_data` length   | `40 <= len <= 24 + 64 MiB + 16` | `decode_index`, before copying |
| `encrypted_name` length   | `40 <= len <= 24 + 255 + 16`  | `decode_index`, before copying |
| index entry count         | `<= MAX_INDEX_ENTRIES (1024)`, and plausible for the bytes left | `VaultIndex::insert_by_key`, `decode_index` |
| index trailing bytes      | none                         | `decode_index`               |
| password length           | `>= MIN_PASSWORD_LEN (8)`    | `Vault::create`              |

### 10.1 Pre-authentication cost and KDF policy

Nothing in a vault file can be trusted until the index AEAD verifies,
and verification needs the master key, so Argon2 necessarily runs with
parameters taken from the unauthenticated header. The bounds above cap
what a forged file can make `open()` or `load()` spend before it is
rejected:

* at most 256 MiB of input is accepted at all, by `load()` on the file
  and by `open()` on the bytes;
* at most 4 KiB of header JSON is parsed;
* at most one Argon2 derivation (Argon2id, or Argon2i if the forged
  header claims version 1) with a 256 MiB working set and 10 passes,
  which is also the size of the largest input accepted (a genuine version
  1 file costs a second derivation, Argon2id this time, only after it has
  authenticated: section 12);
* HKDF and one AEAD verification over at most 256 MiB of ciphertext,
  then one linear pass over the decrypted index.

The derivation is only paid for a file that could still turn out to be a
vault: a header that fails any check of section 2.1, or an encrypted
index too short to hold even an empty one (step 8), is rejected first.

The lower bounds serve the opposite goal: any file this library agrees to
open costs an attacker at least 32 MiB and 3 passes per password guess,
so a "memseal vault" produced by a buggy or hostile writer cannot be
made cheap to brute force. 32 MiB and 3 passes match libsodium's
interactive memory limit and its Argon2i minimum operations count (RFC
9106 recommends at least 3 passes for Argon2i; for Argon2id it allows
fewer, so the floor is conservative).

Every vault written so far uses the defaults, 128 MiB and 4 iterations,
so tightening the accepted range is a compatible refinement (section 11).
When configurable KDF presets ship (see `ROADMAP.md`), the range may be
widened, but only within a policy that keeps the worst case above small.
Integrators that open attacker-supplied files should still treat
`open()` and `load()` as expensive untrusted-input parsers: bounded is
not free, and `InvalidPassword` on a tampered file means every retry
repeats the derivation.


## 11. Versioning

`VAULT_VERSION` (header) and `VAULT_INDEX_VERSION` (index) are
independent. Either bumping signals a format break. Today both are `2`;
version 1 of both is read through the legacy path of section 12.

Changes that require a version bump:

* Adding, removing, renaming, or reordering header fields.
* Changing any HKDF `info` prefix string.
* Changing the KDF algorithm or its default parameters.
* Changing the layout of section 2 (nonce position, etc.).
* Changing the structure of the binary index.

Changes that do NOT require a version bump:

* Adding new validation rules that only refine existing bounds (since
  older valid files remain valid).
* Internal API changes that do not affect the byte format.

When a format break ships, the new code MUST detect older versions via
the header `version` field and handle them explicitly. The one thing it
MUST NOT do is silently re-interpret older bytes as the current format:
that path leads to wrong-key derivation, AAD mismatches, or worst-case
incoherent reads that surface as ambiguous errors. Detection is cheap
(the `version` field of the plaintext header JSON is read before anything
else is interpreted) and mandatory.

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

* The break is small (e.g., the 1 to 2 transition of section 12, or
  adding a new optional header field).
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
| Format 1 to format 2 (section 12)                   | A (shipped)    |
| Add a new optional index field with a default       | not a break    |
| Change a HKDF `info` prefix                         | B              |
| Swap KDF algorithm                                  | B, or A when the re-keying can run in memory before anything is written (section 12) |
| Change AEAD (e.g., XChaCha20-Poly1305 -> something) | B              |
| Format known to be cryptographically broken         | C, with a CVE  |

Document the decision in `CHANGELOG.md` under the release that ships
the break, and in the migration function's doc comment if option B is
used.


## 12. Legacy format version 1

Releases up to 0.2.1 wrote `VAULT_VERSION = 1`. The current build reads
those files (option A of section 11.1) and the next `export()` or
`save()` rewrites them in format version 2; `open()` sets the in-memory
header version to 2 as soon as the file has been authenticated, so the
rewrite needs no separate migration step. The legacy reader is kept and
tested (a fixture written by 0.2.1 lives in `tests/fixtures/`) for at
least one further release cycle.

Differences from the current format:

* The envelope carries 8 extra bytes after the index nonce: a copy of
  `nonce_counter` that was never read back. `parse_envelope` requires and
  skips them when `header.version == 1`.
* The index is a JSON document:

  ```json
  {
    "version": 1,
    "nonce": [24 bytes],
    "nonce_counter": 7,
    "data_nonce_counter": 42,
    "files": {
      "<hmac_key_hex>": {
        "location": "Inline",
        "created": 0,
        "modified": 0,
        "is_dummy": false,
        "encrypted_data": [bytes] | null,
        "encrypted_name": [bytes] | null,
        "data_counter": 17
      }
    }
  }
  ```

  Ciphertext bytes are number arrays, which cost about 3.6 output bytes
  per stored byte and capped the practical aggregate plaintext at about
  70 MiB. `nonce` duplicates the envelope nonce and is ignored;
  `location`, `created`, and `modified` are accepted and ignored; entries
  flagged `is_dummy` carry no payload and are dropped. A real entry must
  hold both ciphertexts within the bounds of section 7 and a 64-character
  hex key, otherwise the (authenticated) index is inconsistent and the
  vault is rejected with `CorruptedData` rather than silently losing an
  entry.

* The master key was derived with Argon2i (the only variant `orion`
  implements); version 2 uses Argon2id (section 4). Since every subkey
  descends from the master key, a version 1 vault cannot simply be
  re-encoded: after the index has authenticated, `open()` re-keys it the
  way `change_password` does, with the same password, a fresh salt, and
  Argon2id, re-encrypting each entry one at a time. This is the "option
  B" case of section 11.1 handled as option A, which is acceptable here
  because the whole migration happens in memory and nothing is written
  until the caller saves: a failure leaves the file as it was. The price
  is one extra derivation when a legacy file is opened.

Header layout, AAD bindings, and per-entry encryption are otherwise
identical. A version 2 file whose header is rewritten to claim version 1
fails the AEAD, since the header is the AAD, so the legacy path (and its
weaker KDF) cannot be forced on a current file.
