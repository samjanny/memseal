use orion::hazardous::aead::xchacha20poly1305;
use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;
use orion::hazardous::stream::chacha20::SecretKey;
use orion::hazardous::stream::xchacha20::Nonce;
use thiserror::Error;

/// Errors from AEAD encryption/decryption with additional authenticated data.
#[derive(Debug, Error)]
pub enum AadAeadError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Ciphertext too short")]
    CiphertextTooShort,
}

/// Encrypts `plaintext` with XChaCha20-Poly1305 straight into `dst`, binding
/// `aad` to the ciphertext.
///
/// `dst` receives the ciphertext followed by the 16-byte tag and must be
/// exactly `plaintext.len() + POLY1305_OUTSIZE` bytes long. Writing into a
/// slice the caller owns lets the ciphertext land in its final buffer (an
/// entry blob behind its nonce, the export behind the header) without an
/// intermediate allocation the size of the plaintext.
pub fn seal_into(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
    dst: &mut [u8],
) -> Result<(), AadAeadError> {
    // `orion` only requires `dst` to be long enough and leaves the rest
    // untouched; an exact match keeps a caller's offset arithmetic honest.
    if plaintext.len().checked_add(POLY1305_OUTSIZE) != Some(dst.len()) {
        return Err(AadAeadError::EncryptionFailed(format!(
            "output buffer is {} bytes for a {}-byte plaintext",
            dst.len(),
            plaintext.len()
        )));
    }

    let key = SecretKey::from_slice(key_bytes)
        .map_err(|e| AadAeadError::EncryptionFailed(format!("{}", e)))?;
    let nonce = Nonce::from_slice(nonce_bytes)
        .map_err(|e| AadAeadError::EncryptionFailed(format!("{}", e)))?;

    xchacha20poly1305::seal(&key, &nonce, plaintext, Some(aad), dst)
        .map_err(|e| AadAeadError::EncryptionFailed(format!("{}", e)))
}

/// Encrypts `plaintext` and returns `nonce || ciphertext || tag` in a single
/// allocation: the stored form of an entry blob (DESIGN.md section 8).
pub fn seal_with_nonce_prefix(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AadAeadError> {
    let mut out = vec![0u8; nonce_bytes.len() + plaintext.len() + POLY1305_OUTSIZE];
    let (prefix, sealed) = out.split_at_mut(nonce_bytes.len());
    prefix.copy_from_slice(nonce_bytes);
    seal_into(key_bytes, nonce_bytes, plaintext, aad, sealed)?;
    Ok(out)
}

/// Decrypts and authenticates `ciphertext_with_tag`, verifying `aad` matches.
pub fn open_with_aad(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 24],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AadAeadError> {
    if ciphertext_with_tag.len() < POLY1305_OUTSIZE {
        return Err(AadAeadError::CiphertextTooShort);
    }

    let key = SecretKey::from_slice(key_bytes)
        .map_err(|e| AadAeadError::DecryptionFailed(format!("{}", e)))?;
    let nonce = Nonce::from_slice(nonce_bytes)
        .map_err(|e| AadAeadError::DecryptionFailed(format!("{}", e)))?;

    let mut dst_out = vec![0u8; ciphertext_with_tag.len() - POLY1305_OUTSIZE];

    xchacha20poly1305::open(&key, &nonce, ciphertext_with_tag, Some(aad), &mut dst_out).map_err(
        |e| {
            AadAeadError::DecryptionFailed(format!(
                "ciphertext or associated data did not authenticate: {}",
                e
            ))
        },
    )?;

    Ok(dst_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::utils::secure_bytes_fill;

    fn random_key_and_nonce() -> ([u8; 32], [u8; 24]) {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        secure_bytes_fill(&mut key).unwrap();
        secure_bytes_fill(&mut nonce).unwrap();
        (key, nonce)
    }

    /// Seals into a buffer of exactly the right size.
    fn seal(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut ct = vec![0u8; plaintext.len() + POLY1305_OUTSIZE];
        seal_into(key, nonce, plaintext, aad, &mut ct).unwrap();
        ct
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let (key, nonce) = random_key_and_nonce();
        let plaintext = b"hello vault";
        let aad = b"header bytes here";

        let ct = seal(&key, &nonce, plaintext, aad);
        let pt = open_with_aad(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_aad_fails_decryption() {
        let (key, nonce) = random_key_and_nonce();

        let ct = seal(&key, &nonce, b"hello vault", b"correct header");
        let result = open_with_aad(&key, &nonce, &ct, b"tampered header");
        assert!(matches!(result, Err(AadAeadError::DecryptionFailed(_))));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (key, nonce) = random_key_and_nonce();

        let mut ct = seal(&key, &nonce, b"hello vault", b"header");
        ct[0] ^= 0xFF;
        let result = open_with_aad(&key, &nonce, &ct, b"header");
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext_works() {
        let (key, nonce) = random_key_and_nonce();

        let ct = seal(&key, &nonce, &[], b"header");
        assert_eq!(ct.len(), POLY1305_OUTSIZE);
        let pt = open_with_aad(&key, &nonce, &ct, b"header").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn ciphertext_too_short_fails() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let result = open_with_aad(&key, &nonce, &[0u8; 15], b"aad");
        assert!(matches!(result, Err(AadAeadError::CiphertextTooShort)));
    }

    #[test]
    fn seal_into_requires_an_exactly_sized_buffer() {
        let (key, nonce) = random_key_and_nonce();
        let plaintext = b"hello vault";
        let exact = plaintext.len() + POLY1305_OUTSIZE;

        for len in [0, exact - 1, exact + 1] {
            let mut dst = vec![0xEEu8; len];
            assert!(
                matches!(
                    seal_into(&key, &nonce, plaintext, b"aad", &mut dst),
                    Err(AadAeadError::EncryptionFailed(_))
                ),
                "buffer of {} bytes accepted",
                len
            );
            // A rejected call must not have written anything.
            assert!(dst.iter().all(|&b| b == 0xEE));
        }
    }

    #[test]
    fn seal_with_nonce_prefix_layout_and_roundtrip() {
        let (key, nonce) = random_key_and_nonce();
        let plaintext = b"entry payload";
        let aad = b"entry aad";

        let blob = seal_with_nonce_prefix(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(blob.len(), nonce.len() + plaintext.len() + POLY1305_OUTSIZE);
        assert_eq!(&blob[..nonce.len()], &nonce);
        // The part after the prefix is exactly what `seal_into` produces.
        assert_eq!(&blob[nonce.len()..], seal(&key, &nonce, plaintext, aad));
        let pt = open_with_aad(&key, &nonce, &blob[nonce.len()..], aad).unwrap();
        assert_eq!(pt, plaintext);

        let empty = seal_with_nonce_prefix(&key, &nonce, &[], aad).unwrap();
        assert_eq!(empty.len(), nonce.len() + POLY1305_OUTSIZE);
    }
}
