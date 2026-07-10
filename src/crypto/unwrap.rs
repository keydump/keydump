use zeroize::Zeroizing;

use super::des3_cbc_decrypt;
use crate::error::{KdError, Result};

pub const MASTER_KEY_LEN: usize = 24;
pub const DB_KEY_LEN: usize = 24;

/// Apple CMS key-wrap magic IV (wrapKeyCms.cpp).
pub const MAGIC_CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// Decrypt DB wrapping key from metadata `DBBlob` ciphertext.
pub fn decrypt_db_key(
    master_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let plain = des3_cbc_decrypt(master_key, iv, ciphertext)?;
    if plain.len() < DB_KEY_LEN {
        return Err(KdError::WrongCredential);
    }
    Ok(Zeroizing::new(plain[..DB_KEY_LEN].to_vec()))
}

/// Unwrap a 24-byte symmetric SSGP key (RFC 3217 style, reverse first 32 bytes only).
pub fn symmetric_keyblob_decrypt(
    db_key: &[u8],
    record_iv: &[u8],
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let plain = des3_cbc_decrypt(db_key, &MAGIC_CMS_IV, encrypted)?;
    if plain.len() < 32 {
        return Err(KdError::Crypto("sym keyblob stage1 too short".into()));
    }
    let mut rev = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        rev[i] = plain[31 - i];
    }
    let final_plain = des3_cbc_decrypt(db_key, record_iv, &rev[..])?;
    if final_plain.len() < 4 + DB_KEY_LEN {
        return Err(KdError::Crypto("sym keyblob stage2 too short".into()));
    }
    let key = &final_plain[4..4 + DB_KEY_LEN];
    if key.len() != DB_KEY_LEN {
        return Err(KdError::Crypto("bad unwrapped sym key length".into()));
    }
    Ok(Zeroizing::new(key.to_vec()))
}

/// Decrypt private-key material from a file-based keychain key blob.
///
/// Stage-1 is 3DES-CBC with [`MAGIC_CMS_IV`]; the full unpadded plaintext is
/// byte-reversed, then stage-2 uses the record IV. Stage-2 plaintext is a fixed
/// 12-byte descriptive prefix followed by the private-key DER.
///
/// Returns `(descriptive_data, key_der_bytes)`.
pub fn private_key_decrypt(
    db_key: &[u8],
    record_iv: &[u8],
    encrypted: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let plain = des3_cbc_decrypt(db_key, &MAGIC_CMS_IV, encrypted)?;
    if plain.is_empty() {
        return Err(KdError::Crypto("private key stage1 empty".into()));
    }
    let rev = Zeroizing::new(plain.iter().rev().copied().collect::<Vec<_>>());
    let final_plain = des3_cbc_decrypt(db_key, record_iv, &rev)?;
    split_private_key_plaintext(&final_plain)
}

fn split_private_key_plaintext(plaintext: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if plaintext.len() < 4 {
        return Err(KdError::Crypto("private key stage2 too short".into()));
    }
    let description_len =
        u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let key_start = 4usize
        .checked_add(description_len)
        .ok_or_else(|| KdError::Crypto("private key description length overflow".into()))?;
    if key_start > plaintext.len() {
        return Err(KdError::Crypto(format!(
            "private key description length {description_len} exceeds plaintext"
        )));
    }
    let descriptive_data = plaintext[4..key_start].to_vec();
    let keyblob = Zeroizing::new(plaintext[key_start..].to_vec());
    if keyblob.is_empty() {
        return Err(KdError::Crypto("private key material empty".into()));
    }
    Ok((descriptive_data, keyblob))
}

#[cfg(test)]
mod tests {
    use super::split_private_key_plaintext;

    #[test]
    fn private_key_plaintext_supports_variable_description_length() {
        let mut plaintext = 3u32.to_be_bytes().to_vec();
        plaintext.extend_from_slice(b"tag");
        plaintext.extend_from_slice(b"private-key-der");

        let (description, key) = split_private_key_plaintext(&plaintext).unwrap();

        assert_eq!(description, b"tag");
        assert_eq!(&key[..], b"private-key-der");
    }

    #[test]
    fn private_key_plaintext_rejects_description_beyond_buffer() {
        let mut plaintext = 32u32.to_be_bytes().to_vec();
        plaintext.extend_from_slice(b"short");

        assert!(split_private_key_plaintext(&plaintext).is_err());
    }
}
