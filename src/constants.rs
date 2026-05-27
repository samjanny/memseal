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

pub mod nonce_derivation {
    pub const NONCE_HKDF_INFO_PREFIX: &[u8] = b"MEMSEAL_NONCE_CTR_v1";
    pub const DATA_NONCE_HKDF_INFO_PREFIX: &[u8] = b"MEMSEAL_DATA_NONCE_v1";
    pub const NAME_NONCE_HKDF_INFO_PREFIX: &[u8] = b"MEMSEAL_NAME_NONCE_v1";
}

pub const MIN_KDF_MEMORY: u32 = 8; // orion Argon2i minimum: 8 * LANES KiB
pub const MIN_KDF_ITERATIONS: u32 = 1;
pub const MIN_PASSWORD_LEN: usize = 8;
pub const MAX_ENTRY_NAME_LEN: usize = 255;
pub const MAX_ENTRY_DATA_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

pub mod subkeys {
    pub const ENCRYPTION_SUBKEY_INFO: &[u8] = b"MEMSEAL_SUBKEY_ENC_v1";
    pub const HMAC_SUBKEY_INFO: &[u8] = b"MEMSEAL_SUBKEY_HMAC_v1";
    pub const SUBKEY_LEN: usize = 32;
}
