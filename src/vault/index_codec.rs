//! Serialization of the encrypted index.
//!
//! The current format (version 2, DESIGN.md section 7) is a length-prefixed
//! binary layout decoded with explicit bounds on every field. Format version
//! 1 stored the index as JSON; `decode_index_v1` still reads it so vaults
//! written by releases up to 0.2.1 open transparently and are rewritten in
//! the current format on their next export.

use crate::constants::vault_index_constants::{
    LEGACY_INDEX_VERSION_1, MAX_INDEX_ENTRIES, VAULT_INDEX_VERSION,
};
use crate::constants::xchacha20_poly1305::XCHACHA20_NONCE_LEN;
use crate::constants::{MAX_ENTRY_DATA_SIZE, MAX_ENTRY_NAME_LEN};
use crate::vault::vault_error::VaultError;
use crate::vault::vault_index::{IndexEntry, VaultIndex};
use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

/// Length of the raw HMAC-SHA256 entry key.
pub const ENTRY_KEY_LEN: usize = 32;
/// Smallest ciphertext `store` can produce: nonce prefix plus Poly1305 tag
/// around an empty plaintext.
pub const MIN_ENCRYPTED_LEN: usize = XCHACHA20_NONCE_LEN + POLY1305_OUTSIZE;
/// Largest `encrypted_data` blob `store` can produce: nonce prefix, the
/// largest accepted plaintext, and the Poly1305 tag.
pub const MAX_ENCRYPTED_DATA_LEN: usize =
    XCHACHA20_NONCE_LEN + MAX_ENTRY_DATA_SIZE + POLY1305_OUTSIZE;
/// Largest `encrypted_name` blob `store` can produce.
pub const MAX_ENCRYPTED_NAME_LEN: usize =
    XCHACHA20_NONCE_LEN + MAX_ENTRY_NAME_LEN + POLY1305_OUTSIZE;

/// Fixed-size part of the index: version, two counters, entry count.
const INDEX_PREAMBLE_LEN: usize = 2 + 8 + 8 + 4;
/// Fixed-size part of one entry: key, data counter, two length prefixes.
const ENTRY_FIXED_LEN: usize = ENTRY_KEY_LEN + 8 + 4 + 4;
/// Smallest encoding of one entry, used to reject an entry count that the
/// remaining bytes cannot possibly hold before anything is allocated.
const MIN_ENTRY_LEN: usize = ENTRY_FIXED_LEN + 2 * MIN_ENCRYPTED_LEN;

/// The decoded contents of an index, independent of the format version it
/// was read from.
pub struct IndexData {
    pub nonce_counter: u64,
    pub data_nonce_counter: u64,
    pub files: HashMap<String, IndexEntry>,
}

/// Lower-case hex encoding of an entry key, the form used for the map and
/// for the entry AAD.
pub fn key_to_hex(key: &[u8]) -> String {
    let mut hex = String::with_capacity(key.len() * 2);
    for b in key {
        write!(hex, "{:02x}", b).unwrap();
    }
    hex
}

/// Inverse of `key_to_hex` for a 32-byte key; `None` if `hex` is not exactly
/// 64 lower-case hex digits.
pub fn hex_to_key(hex: &str) -> Option<[u8; ENTRY_KEY_LEN]> {
    let bytes = hex.as_bytes();
    if bytes.len() != ENTRY_KEY_LEN * 2 {
        return None;
    }
    let mut key = [0u8; ENTRY_KEY_LEN];
    for (i, pair) in bytes.chunks(2).enumerate() {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        key[i] = (hi << 4) | lo;
    }
    Some(key)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Rejects a ciphertext whose length `store` could never have produced.
fn check_entry_sizes(entry: &IndexEntry) -> Result<(), VaultError> {
    let name_len = entry.encrypted_name.len();
    if !(MIN_ENCRYPTED_LEN..=MAX_ENCRYPTED_NAME_LEN).contains(&name_len) {
        return Err(VaultError::CorruptedData(format!(
            "Entry name ciphertext of {} bytes is outside {}..={}",
            name_len, MIN_ENCRYPTED_LEN, MAX_ENCRYPTED_NAME_LEN
        )));
    }
    let data_len = entry.encrypted_data.len();
    if !(MIN_ENCRYPTED_LEN..=MAX_ENCRYPTED_DATA_LEN).contains(&data_len) {
        return Err(VaultError::CorruptedData(format!(
            "Entry data ciphertext of {} bytes is outside {}..={}",
            data_len, MIN_ENCRYPTED_LEN, MAX_ENCRYPTED_DATA_LEN
        )));
    }
    Ok(())
}

/// Encodes the index in the current binary format.
///
/// Layout (all integers little-endian):
///
/// ```text
/// u16 version = 2
/// u64 nonce_counter
/// u64 data_nonce_counter
/// u32 entry_count
/// entry_count times:
///   [32] hmac key (raw)
///   u64  data_counter
///   u32  name_ct_len, then name_ct
///   u32  data_ct_len, then data_ct
/// ```
pub fn encode_index(index: &VaultIndex) -> Result<Vec<u8>, VaultError> {
    let entry_count = u32::try_from(index.files.len())
        .map_err(|_| VaultError::SerializationError("too many entries".to_string()))?;

    let total: usize = INDEX_PREAMBLE_LEN
        + index
            .files
            .values()
            .map(|e| ENTRY_FIXED_LEN + e.encrypted_name.len() + e.encrypted_data.len())
            .sum::<usize>();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&VAULT_INDEX_VERSION.to_le_bytes());
    out.extend_from_slice(&index.nonce_counter.to_le_bytes());
    out.extend_from_slice(&index.data_nonce_counter.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());

    for (hex_key, entry) in &index.files {
        let key = hex_to_key(hex_key).ok_or_else(|| {
            VaultError::SerializationError("entry key is not a 32-byte hex HMAC".to_string())
        })?;
        let name_len = u32::try_from(entry.encrypted_name.len())
            .map_err(|_| VaultError::SerializationError("entry name too long".to_string()))?;
        let data_len = u32::try_from(entry.encrypted_data.len())
            .map_err(|_| VaultError::SerializationError("entry data too long".to_string()))?;

        out.extend_from_slice(&key);
        out.extend_from_slice(&entry.data_counter.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&entry.encrypted_name);
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(&entry.encrypted_data);
    }

    debug_assert_eq!(out.len(), total);
    Ok(out)
}

/// Bounds-checked cursor over the decoded index bytes.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], VaultError> {
        if n > self.remaining() {
            return Err(VaultError::CorruptedData(format!(
                "Index truncated while reading {} ({} bytes needed, {} left)",
                what,
                n,
                self.remaining()
            )));
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u16(&mut self, what: &str) -> Result<u16, VaultError> {
        Ok(u16::from_le_bytes(self.take(2, what)?.try_into().unwrap()))
    }

    fn u32(&mut self, what: &str) -> Result<u32, VaultError> {
        Ok(u32::from_le_bytes(self.take(4, what)?.try_into().unwrap()))
    }

    fn u64(&mut self, what: &str) -> Result<u64, VaultError> {
        Ok(u64::from_le_bytes(self.take(8, what)?.try_into().unwrap()))
    }
}

/// Decodes a current-format index that has already been authenticated.
///
/// Every length is checked against the remaining input and the documented
/// bounds before the corresponding allocation, duplicate keys and trailing
/// bytes are rejected, and the entry count is validated against the bytes
/// left before the map is created.
pub fn decode_index(bytes: &[u8]) -> Result<IndexData, VaultError> {
    let mut r = Reader { buf: bytes, pos: 0 };

    let version = r.u16("version")?;
    if version != VAULT_INDEX_VERSION {
        return Err(VaultError::CorruptedData(format!(
            "Unsupported index version: {}",
            version
        )));
    }
    let nonce_counter = r.u64("nonce counter")?;
    let data_nonce_counter = r.u64("data nonce counter")?;
    let entry_count = r.u32("entry count")? as usize;

    if entry_count > MAX_INDEX_ENTRIES {
        return Err(VaultError::CorruptedData(format!(
            "Index entry count {} exceeds maximum {}",
            entry_count, MAX_INDEX_ENTRIES
        )));
    }
    if entry_count * MIN_ENTRY_LEN > r.remaining() {
        return Err(VaultError::CorruptedData(format!(
            "Index declares {} entries but holds {} bytes",
            entry_count,
            r.remaining()
        )));
    }

    let mut files = HashMap::with_capacity(entry_count);
    for _ in 0..entry_count {
        let key = r.take(ENTRY_KEY_LEN, "entry key")?;
        let data_counter = r.u64("entry data counter")?;

        let name_len = r.u32("entry name length")? as usize;
        if !(MIN_ENCRYPTED_LEN..=MAX_ENCRYPTED_NAME_LEN).contains(&name_len) {
            return Err(VaultError::CorruptedData(format!(
                "Entry name ciphertext of {} bytes is outside {}..={}",
                name_len, MIN_ENCRYPTED_LEN, MAX_ENCRYPTED_NAME_LEN
            )));
        }
        let encrypted_name = r.take(name_len, "entry name ciphertext")?.to_vec();

        let data_len = r.u32("entry data length")? as usize;
        if !(MIN_ENCRYPTED_LEN..=MAX_ENCRYPTED_DATA_LEN).contains(&data_len) {
            return Err(VaultError::CorruptedData(format!(
                "Entry data ciphertext of {} bytes is outside {}..={}",
                data_len, MIN_ENCRYPTED_LEN, MAX_ENCRYPTED_DATA_LEN
            )));
        }
        let encrypted_data = r.take(data_len, "entry data ciphertext")?.to_vec();

        let entry = IndexEntry {
            data_counter,
            encrypted_name,
            encrypted_data,
        };
        if files.insert(key_to_hex(key), entry).is_some() {
            return Err(VaultError::CorruptedData(
                "Duplicate entry key in index".to_string(),
            ));
        }
    }

    if r.remaining() != 0 {
        return Err(VaultError::CorruptedData(format!(
            "{} trailing bytes after the last index entry",
            r.remaining()
        )));
    }

    Ok(IndexData {
        nonce_counter,
        data_nonce_counter,
        files,
    })
}

/// Decodes the JSON index written by format version 1 (releases up to
/// 0.2.1) into the same `IndexData` the current decoder produces.
///
/// Dummy padding entries (`is_dummy`) carry no payload and are dropped; a
/// real entry must carry both ciphertexts within the documented bounds and
/// a 32-byte hex key, otherwise the (authenticated) index is inconsistent
/// and the vault is rejected rather than silently losing an entry.
pub fn decode_index_v1(json: &[u8]) -> Result<IndexData, VaultError> {
    use serde::Deserialize;
    use serde::de::IgnoredAny;

    #[derive(Deserialize)]
    struct Meta {
        // Present in every v1 index but never read back: accepted and ignored.
        #[allow(dead_code)]
        location: IgnoredAny,
        #[allow(dead_code)]
        created: IgnoredAny,
        #[allow(dead_code)]
        modified: IgnoredAny,
        is_dummy: bool,
        encrypted_data: Option<Vec<u8>>,
        encrypted_name: Option<Vec<u8>>,
        data_counter: u64,
    }

    #[derive(Deserialize)]
    struct Index {
        version: u16,
        // The index nonce was duplicated inside the ciphertext; the envelope
        // copy is the one that matters.
        #[allow(dead_code)]
        nonce: IgnoredAny,
        nonce_counter: u64,
        data_nonce_counter: u64,
        files: HashMap<String, Meta>,
    }

    let index: Index = serde_json::from_slice(json)
        .map_err(|e| VaultError::CorruptedData(format!("Invalid index JSON: {}", e)))?;

    if index.version != LEGACY_INDEX_VERSION_1 {
        return Err(VaultError::CorruptedData(format!(
            "Unsupported index version: {}",
            index.version
        )));
    }
    if index.files.len() > MAX_INDEX_ENTRIES {
        return Err(VaultError::CorruptedData(format!(
            "Index entry count {} exceeds maximum {}",
            index.files.len(),
            MAX_INDEX_ENTRIES
        )));
    }

    let mut files = HashMap::with_capacity(index.files.len());
    for (key, meta) in index.files {
        if meta.is_dummy {
            continue;
        }
        if hex_to_key(&key).is_none() {
            return Err(VaultError::CorruptedData(
                "Entry key is not a 32-byte hex HMAC".to_string(),
            ));
        }
        let (Some(encrypted_name), Some(encrypted_data)) =
            (meta.encrypted_name, meta.encrypted_data)
        else {
            return Err(VaultError::CorruptedData(
                "Entry is missing a ciphertext".to_string(),
            ));
        };
        let entry = IndexEntry {
            data_counter: meta.data_counter,
            encrypted_name,
            encrypted_data,
        };
        check_entry_sizes(&entry)?;
        files.insert(key, entry);
    }

    Ok(IndexData {
        nonce_counter: index.nonce_counter,
        data_nonce_counter: index.data_nonce_counter,
        files,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn entry(counter: u64, name_len: usize, data_len: usize) -> IndexEntry {
        IndexEntry {
            data_counter: counter,
            encrypted_name: vec![0xAA; name_len],
            encrypted_data: vec![0xBB; data_len],
        }
    }

    /// Encodes without any validation, for crafting invalid inputs.
    pub(crate) fn raw_encode(
        version: u16,
        nonce_counter: u64,
        data_nonce_counter: u64,
        declared_count: u32,
        entries: &[([u8; ENTRY_KEY_LEN], IndexEntry)],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&nonce_counter.to_le_bytes());
        out.extend_from_slice(&data_nonce_counter.to_le_bytes());
        out.extend_from_slice(&declared_count.to_le_bytes());
        for (key, e) in entries {
            out.extend_from_slice(key);
            out.extend_from_slice(&e.data_counter.to_le_bytes());
            out.extend_from_slice(&(e.encrypted_name.len() as u32).to_le_bytes());
            out.extend_from_slice(&e.encrypted_name);
            out.extend_from_slice(&(e.encrypted_data.len() as u32).to_le_bytes());
            out.extend_from_slice(&e.encrypted_data);
        }
        out
    }

    #[test]
    fn hex_roundtrip_and_rejection() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
        let hex = key_to_hex(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex_to_key(&hex), Some(key));
        assert_eq!(hex_to_key(&hex[..63]), None);
        assert_eq!(hex_to_key(&hex.to_uppercase()), None);
        assert_eq!(hex_to_key(&"zz".repeat(32)), None);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut index = VaultIndex::generate().unwrap();
        index.nonce_counter = 7;
        index.data_nonce_counter = 3;
        let k1 = index.hmac_key_for_name("a").unwrap();
        let k2 = index.hmac_key_for_name("b").unwrap();
        index.insert_by_key(k1.clone(), entry(1, 40, 40)).unwrap();
        index
            .insert_by_key(k2.clone(), entry(2, 100, 5000))
            .unwrap();

        let bytes = encode_index(&index).unwrap();
        let decoded = decode_index(&bytes).unwrap();
        assert_eq!(decoded.nonce_counter, 7);
        assert_eq!(decoded.data_nonce_counter, 3);
        assert_eq!(decoded.files.len(), 2);
        assert_eq!(decoded.files[&k1], entry(1, 40, 40));
        assert_eq!(decoded.files[&k2], entry(2, 100, 5000));
    }

    #[test]
    fn encode_is_compact() {
        // Binary overhead per entry is the fixed header only; the number
        // array JSON of format 1 cost about 3.6 bytes per ciphertext byte.
        let mut index = VaultIndex::generate().unwrap();
        let k = index.hmac_key_for_name("a").unwrap();
        index.insert_by_key(k, entry(0, 40, 10_000)).unwrap();
        let bytes = encode_index(&index).unwrap();
        assert_eq!(
            bytes.len(),
            INDEX_PREAMBLE_LEN + ENTRY_FIXED_LEN + 40 + 10_000
        );
    }

    #[test]
    fn decode_empty_index() {
        let bytes = raw_encode(VAULT_INDEX_VERSION, 1, 0, 0, &[]);
        let decoded = decode_index(&bytes).unwrap();
        assert!(decoded.files.is_empty());
        assert_eq!(decoded.nonce_counter, 1);
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let bytes = raw_encode(3, 0, 0, 0, &[]);
        match decode_index(&bytes) {
            Err(VaultError::CorruptedData(msg)) => assert!(msg.contains("version"), "{}", msg),
            _ => panic!("wrong version accepted"),
        }
    }

    #[test]
    fn decode_rejects_truncation_at_every_byte() {
        let bytes = raw_encode(
            VAULT_INDEX_VERSION,
            0,
            1,
            1,
            &[([1u8; 32], entry(0, 40, 41))],
        );
        for cut in 0..bytes.len() {
            assert!(
                matches!(
                    decode_index(&bytes[..cut]),
                    Err(VaultError::CorruptedData(_))
                ),
                "truncation at {} accepted",
                cut
            );
        }
        assert!(decode_index(&bytes).is_ok());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = raw_encode(VAULT_INDEX_VERSION, 0, 0, 0, &[]);
        bytes.push(0);
        match decode_index(&bytes) {
            Err(VaultError::CorruptedData(msg)) => assert!(msg.contains("trailing"), "{}", msg),
            _ => panic!("trailing bytes accepted"),
        }
    }

    #[test]
    fn decode_rejects_entry_count_over_cap_and_over_remaining_bytes() {
        let over_cap = raw_encode(
            VAULT_INDEX_VERSION,
            0,
            0,
            (MAX_INDEX_ENTRIES + 1) as u32,
            &[],
        );
        match decode_index(&over_cap) {
            Err(VaultError::CorruptedData(msg)) => assert!(msg.contains("maximum"), "{}", msg),
            _ => panic!("entry count over cap accepted"),
        }

        // Within the cap but impossible for the bytes that follow: rejected
        // before any entry is parsed.
        let hollow = raw_encode(VAULT_INDEX_VERSION, 0, 0, 2, &[]);
        match decode_index(&hollow) {
            Err(VaultError::CorruptedData(msg)) => assert!(msg.contains("declares"), "{}", msg),
            _ => panic!("hollow entry count accepted"),
        }
    }

    #[test]
    fn decode_rejects_ciphertext_lengths_outside_bounds() {
        for (name_len, data_len) in [
            (MIN_ENCRYPTED_LEN - 1, MIN_ENCRYPTED_LEN),
            (MAX_ENCRYPTED_NAME_LEN + 1, MIN_ENCRYPTED_LEN),
            (MIN_ENCRYPTED_LEN, MIN_ENCRYPTED_LEN - 1),
        ] {
            let bytes = raw_encode(
                VAULT_INDEX_VERSION,
                0,
                1,
                1,
                &[([1u8; 32], entry(0, name_len, data_len))],
            );
            assert!(
                matches!(decode_index(&bytes), Err(VaultError::CorruptedData(_))),
                "lengths ({}, {}) accepted",
                name_len,
                data_len
            );
        }

        // A declared data length above the bound is rejected from the length
        // field alone, before any bytes for it are required. Enough bytes
        // follow for the entry-count plausibility check to pass, so the
        // length bound is the check that fires.
        let mut bytes = raw_encode(VAULT_INDEX_VERSION, 0, 1, 1, &[]);
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&(MIN_ENCRYPTED_LEN as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; MIN_ENCRYPTED_LEN]);
        bytes.extend_from_slice(&((MAX_ENCRYPTED_DATA_LEN + 1) as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; MIN_ENCRYPTED_LEN]);
        match decode_index(&bytes) {
            Err(VaultError::CorruptedData(msg)) => assert!(msg.contains("outside"), "{}", msg),
            _ => panic!("oversized data length accepted"),
        }
    }

    #[test]
    fn decode_accepts_lengths_at_bounds() {
        let bytes = raw_encode(
            VAULT_INDEX_VERSION,
            0,
            1,
            1,
            &[(
                [1u8; 32],
                entry(0, MAX_ENCRYPTED_NAME_LEN, MIN_ENCRYPTED_LEN),
            )],
        );
        assert!(decode_index(&bytes).is_ok());
    }

    #[test]
    fn decode_rejects_duplicate_keys() {
        let bytes = raw_encode(
            VAULT_INDEX_VERSION,
            0,
            1,
            2,
            &[([1u8; 32], entry(0, 40, 40)), ([1u8; 32], entry(0, 40, 40))],
        );
        match decode_index(&bytes) {
            Err(VaultError::CorruptedData(msg)) => assert!(msg.contains("Duplicate"), "{}", msg),
            _ => panic!("duplicate key accepted"),
        }
    }

    fn v1_json(files: serde_json::Value) -> Vec<u8> {
        let nonce = vec![0u8; XCHACHA20_NONCE_LEN];
        serde_json::to_vec(&serde_json::json!({
            "version": LEGACY_INDEX_VERSION_1,
            "nonce": nonce,
            "nonce_counter": 4,
            "data_nonce_counter": 9,
            "files": files,
        }))
        .unwrap()
    }

    fn v1_meta(is_dummy: bool, name: Option<usize>, data: Option<usize>) -> serde_json::Value {
        serde_json::json!({
            "location": "Inline",
            "created": 0,
            "modified": 0,
            "is_dummy": is_dummy,
            "encrypted_name": name.map(|n| vec![1u8; n]),
            "encrypted_data": data.map(|n| vec![2u8; n]),
            "data_counter": 3,
        })
    }

    #[test]
    fn decode_v1_converts_real_entries_and_drops_dummies() {
        let key = "ab".repeat(32);
        let files = serde_json::json!({
            key.clone(): v1_meta(false, Some(40), Some(100)),
            "cd".repeat(32): v1_meta(true, None, None),
        });
        let decoded = decode_index_v1(&v1_json(files)).unwrap();
        assert_eq!(decoded.nonce_counter, 4);
        assert_eq!(decoded.data_nonce_counter, 9);
        assert_eq!(decoded.files.len(), 1);
        let e = &decoded.files[&key];
        assert_eq!(e.data_counter, 3);
        assert_eq!(e.encrypted_name.len(), 40);
        assert_eq!(e.encrypted_data.len(), 100);
    }

    #[test]
    fn decode_v1_rejects_real_entry_without_ciphertext_or_bad_key() {
        let missing = serde_json::json!({ "ab".repeat(32): v1_meta(false, Some(40), None) });
        assert!(matches!(
            decode_index_v1(&v1_json(missing)),
            Err(VaultError::CorruptedData(_))
        ));
        let bad_key = serde_json::json!({ "not-hex": v1_meta(false, Some(40), Some(40)) });
        assert!(matches!(
            decode_index_v1(&v1_json(bad_key)),
            Err(VaultError::CorruptedData(_))
        ));
        let too_short = serde_json::json!({ "ab".repeat(32): v1_meta(false, Some(39), Some(40)) });
        assert!(matches!(
            decode_index_v1(&v1_json(too_short)),
            Err(VaultError::CorruptedData(_))
        ));
    }

    #[test]
    fn decode_v1_rejects_wrong_version_and_malformed_json() {
        let nonce = vec![0u8; XCHACHA20_NONCE_LEN];
        let json = serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "nonce": nonce,
            "nonce_counter": 0,
            "data_nonce_counter": 0,
            "files": {},
        }))
        .unwrap();
        assert!(matches!(
            decode_index_v1(&json),
            Err(VaultError::CorruptedData(_))
        ));
        assert!(matches!(
            decode_index_v1(b"{not json"),
            Err(VaultError::CorruptedData(_))
        ));
    }
}
