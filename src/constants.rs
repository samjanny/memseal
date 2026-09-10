pub const VAULT_VERSION: u16 = 1;
pub const SUPPORTED_VAULT_VERSIONS: [u16; 1] = [VAULT_VERSION];

/// Argon2i parameters for password hashing.
/// Note: orion only supports Argon2i (not Argon2id) with p=1.
pub mod argon2 {
    pub const MEMORY_COST: u32 = 131_072; // 128 MiB
    pub const ITERATIONS: u32 = 4;
    pub const KEY_LEN: usize = 32;
    pub const SALT_LEN: usize = 16;
}

pub mod vault_index_constants {
    pub const VAULT_INDEX_VERSION: u16 = 1;
    pub const SUPPORTED_VAULT_INDEX_VERSIONS: [u16; 1] = [VAULT_INDEX_VERSION];
    pub const MAX_INDEX_ENTRIES: usize = 1024;
}

pub mod xchacha20_poly1305 {
    pub const XCHACHA20_NONCE_LEN: usize = 24;
}

pub const SECURE_MEMORY_VAULT_CHUNK_SIZE: usize = 4 * 1024; // 4 KiB

// Bounds enforced by `validate_header` on the KDF parameters read from an
// untrusted vault header (DESIGN.md sections 3 and 10). The header is parsed
// and its parameters are fed to Argon2i before the password can be checked,
// so the upper bounds cap the memory and CPU a forged file can make
// `Vault::open` spend before the AEAD rejects it, and the lower bounds keep
// any file this library accepts from being cheap to brute force. Every vault
// written so far uses the `argon2` defaults above, which sit inside both
// ranges.
pub const MIN_KDF_MEMORY: u32 = 32_768; // 32 MiB: libsodium's interactive Argon2i limit
pub const MAX_KDF_MEMORY: u32 = 262_144; // 256 MiB: 2x default, equal to MAX_VAULT_FILE_SIZE
pub const MIN_KDF_ITERATIONS: u32 = 3; // RFC 9106 / libsodium minimum for Argon2i
pub const MAX_KDF_ITERATIONS: u32 = 10;

// Plaintext header JSON is deserialized before anything is authenticated;
// a real header is about 150 bytes, so 4 KiB leaves room for future fields
// while keeping the pre-authentication parse trivial.
pub const MAX_HEADER_JSON_LEN: usize = 4096;
pub const MAX_VAULT_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

// Compile-time pins of the KDF policy: the defaults must stay inside the
// accepted range, and a forged header must not be able to make `open`
// allocate more than `load` already may.
const _: () = {
    assert!(MIN_KDF_MEMORY <= argon2::MEMORY_COST && argon2::MEMORY_COST <= MAX_KDF_MEMORY);
    assert!(MIN_KDF_ITERATIONS <= argon2::ITERATIONS && argon2::ITERATIONS <= MAX_KDF_ITERATIONS);
    assert!(MAX_KDF_MEMORY as u64 == MAX_VAULT_FILE_SIZE / 1024);
    assert!(MIN_KDF_ITERATIONS >= 3 && MAX_KDF_ITERATIONS <= 10);
};
pub const MIN_PASSWORD_LEN: usize = 8;
pub const MAX_ENTRY_NAME_LEN: usize = 255;
pub const MAX_ENTRY_DATA_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

pub mod subkeys {
    pub const ENCRYPTION_SUBKEY_INFO: &[u8] = b"MEMSEAL_SUBKEY_ENC_v1";
    pub const HMAC_SUBKEY_INFO: &[u8] = b"MEMSEAL_SUBKEY_HMAC_v1";
    pub const SUBKEY_LEN: usize = 32;
}
