//! Entry points for the fuzz targets in `fuzz/`, compiled only with the
//! `fuzzing` feature. They wrap the untrusted-input parsers that run before
//! (`parse_envelope`) and after (`decode_index`, `decode_index_v1`) the
//! Argon2 derivation and AEAD check in `Vault::open`, so the fuzzer never
//! pays for a key derivation. Each returns whether the input was accepted;
//! the point is that no input panics, loops, or allocates out of bounds.
//!
//! This module is not part of the public API.

/// Steps 1-5 of DESIGN.md section 2.1 on arbitrary bytes.
pub fn parse_envelope(data: &[u8]) -> bool {
    crate::vault::facade::parse_envelope(data).is_ok()
}

/// The current binary index decoder on arbitrary (already "authenticated")
/// bytes.
pub fn decode_index(bytes: &[u8]) -> bool {
    crate::vault::index_codec::decode_index(bytes).is_ok()
}

/// The legacy JSON index decoder on arbitrary bytes.
pub fn decode_index_v1(bytes: &[u8]) -> bool {
    crate::vault::index_codec::decode_index_v1(bytes).is_ok()
}
