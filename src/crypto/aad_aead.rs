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

/// Encrypts `plaintext` with XChaCha20-Poly1305, binding `aad` to the ciphertext.
pub fn seal_with_aad(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AadAeadError> {
    let key = SecretKey::from_slice(key_bytes)
        .map_err(|e| AadAeadError::EncryptionFailed(format!("{}", e)))?;
    let nonce = Nonce::from_slice(nonce_bytes)
        .map_err(|e| AadAeadError::EncryptionFailed(format!("{}", e)))?;

    let mut dst_out = vec![0u8; plaintext.len() + POLY1305_OUTSIZE];

    xchacha20poly1305::seal(&key, &nonce, plaintext, Some(aad), &mut dst_out)
        .map_err(|e| AadAeadError::EncryptionFailed(format!("{}", e)))?;

    Ok(dst_out)
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
                "Decryption/authentication failed (possible header tampering): {}",
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

    #[test]
    fn seal_and_open_roundtrip() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        secure_bytes_fill(&mut key).unwrap();
        secure_bytes_fill(&mut nonce).unwrap();
        let plaintext = b"hello vault";
        let aad = b"header bytes here";

        let ct = seal_with_aad(&key, &nonce, plaintext, aad).unwrap();
        let pt = open_with_aad(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_aad_fails_decryption() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        secure_bytes_fill(&mut key).unwrap();
        secure_bytes_fill(&mut nonce).unwrap();

        let ct = seal_with_aad(&key, &nonce, b"hello vault", b"correct header").unwrap();
        let result = open_with_aad(&key, &nonce, &ct, b"tampered header");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        secure_bytes_fill(&mut key).unwrap();
        secure_bytes_fill(&mut nonce).unwrap();

        let mut ct = seal_with_aad(&key, &nonce, b"hello vault", b"header").unwrap();
        ct[0] ^= 0xFF;
        let result = open_with_aad(&key, &nonce, &ct, b"header");
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext_works() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        secure_bytes_fill(&mut key).unwrap();
        secure_bytes_fill(&mut nonce).unwrap();

        let ct = seal_with_aad(&key, &nonce, &[], b"header").unwrap();
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
}
