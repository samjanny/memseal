# Fuzz targets

Fuzzing for the untrusted-input parsers of `Vault::open`, driven by
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer, nightly
toolchain). The targets call the parsers through the crate's `fuzzing`
feature, which is never enabled in a normal build.

| Target            | What it exercises                                                |
| ----------------- | ---------------------------------------------------------------- |
| `parse_envelope`  | size cap, length fields, header JSON, KDF bounds, canonical header (steps 1-7 of DESIGN 2.1) |
| `decode_index`    | the binary index decoder (format version 2)                      |
| `decode_index_v1` | the legacy JSON index decoder (format version 1)                 |

None of them runs Argon2 or the AEAD, so a fuzz iteration costs
microseconds. The property checked is the absence of panics, hangs, and
out-of-bounds allocation; accepting or rejecting an input is not an
oracle here.

```bash
cargo install cargo-fuzz
for t in parse_envelope decode_index decode_index_v1; do
  mkdir -p fuzz/corpus/$t
  cargo +nightly fuzz run $t fuzz/corpus/$t fuzz/seeds/$t -- -max_total_time=300
done
```

libFuzzer writes every new input it keeps into the first corpus directory
it is given, so pass the working corpus (`fuzz/corpus/<target>`, ignored
by git) first and the seeds second. `fuzz/seeds/` holds one valid input
per target (a format 1 and a format 2 vault for the envelope, a matching
plaintext index for each decoder) so the fuzzer starts from the accepting
path instead of discovering the layout from scratch. Crashes land in
`fuzz/artifacts/<target>/`; add the input to `fuzz/seeds/<target>/` once
fixed so it stays a regression test.
