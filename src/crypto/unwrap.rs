use zeroize::Zeroizing;

use super::des3_cbc_decrypt;
use crate::error::{KdError, Result};

pub const MASTER_KEY_LEN: usize = 24;
pub const DB_KEY_LEN: usize = 24;
const PRIVATE_KEY_DESCRIPTION_LEN: usize = 12;

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
    if plain.len() != 40 {
        return Err(KdError::Crypto(format!(
            "sym keyblob stage1 must be 40 bytes, got {}",
            plain.len()
        )));
    }
    let mut rev = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        rev[i] = plain[31 - i];
    }
    let final_plain = des3_cbc_decrypt(db_key, record_iv, &rev[..])?;
    extract_symmetric_key_plaintext(&final_plain)
}

fn extract_symmetric_key_plaintext(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if plaintext.len() != 4 + DB_KEY_LEN {
        return Err(KdError::Crypto(format!(
            "sym keyblob stage2 must be {} bytes, got {}",
            4 + DB_KEY_LEN,
            plaintext.len()
        )));
    }
    if plaintext[..4] != [0, 0, 0, 0] {
        return Err(KdError::Crypto("sym keyblob header is not zero".into()));
    }
    Ok(Zeroizing::new(plaintext[4..].to_vec()))
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
    if plaintext.len() < PRIVATE_KEY_DESCRIPTION_LEN {
        return Err(KdError::Crypto("private key stage2 too short".into()));
    }
    let descriptive_data = plaintext[..PRIVATE_KEY_DESCRIPTION_LEN].to_vec();
    let keyblob = Zeroizing::new(plaintext[PRIVATE_KEY_DESCRIPTION_LEN..].to_vec());
    if keyblob.is_empty() {
        return Err(KdError::Crypto("private key material empty".into()));
    }
    Ok((descriptive_data, keyblob))
}

#[cfg(test)]
mod tests {
    use cbc::Encryptor;
    use cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use des::TdesEde3;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    use super::{
        extract_symmetric_key_plaintext, private_key_decrypt, split_private_key_plaintext,
        DB_KEY_LEN, MAGIC_CMS_IV,
    };

    type TdesCbcEnc = Encryptor<TdesEde3>;

    fn encrypt_padded(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0u8; plaintext.len() + 8];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        TdesCbcEnc::new_from_slices(key, iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .unwrap()
            .to_vec()
    }

    #[test]
    fn symmetric_key_plaintext_requires_exact_header_and_length() {
        let mut plaintext = vec![0u8; 4 + DB_KEY_LEN];
        plaintext[4..].fill(0x5a);

        let key = extract_symmetric_key_plaintext(&plaintext).unwrap();
        assert_eq!(&key[..], &[0x5a; DB_KEY_LEN]);

        plaintext[0] = 1;
        assert!(extract_symmetric_key_plaintext(&plaintext).is_err());
        assert!(extract_symmetric_key_plaintext(&plaintext[..plaintext.len() - 1]).is_err());
    }

    #[test]
    fn private_key_plaintext_splits_the_fixed_description() {
        let mut plaintext = b"twelve-bytes".to_vec();
        plaintext.extend_from_slice(b"private-key-der");

        let (description, key) = split_private_key_plaintext(&plaintext).unwrap();

        assert_eq!(description, b"twelve-bytes");
        assert_eq!(&key[..], b"private-key-der");
    }

    #[test]
    fn private_key_plaintext_requires_a_description_and_key() {
        assert!(split_private_key_plaintext(b"eleven-byte").is_err());
        assert!(split_private_key_plaintext(b"twelve-bytes").is_err());
    }

    #[test]
    fn private_key_decrypt_accepts_the_fixed_twelve_byte_description() {
        let db_key = [0x11; 24];
        let record_iv = [0x22; 8];
        let description = [
            0xae, 0x98, 0x1e, 0xdb, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        ];
        let private_der = Rsa::generate(1024).unwrap().private_key_to_der().unwrap();
        let mut final_plaintext = description.to_vec();
        final_plaintext.extend_from_slice(&private_der);
        let stage_two = encrypt_padded(&db_key, &record_iv, &final_plaintext);
        let reversed: Vec<_> = stage_two.into_iter().rev().collect();
        let encrypted = encrypt_padded(&db_key, &MAGIC_CMS_IV, &reversed);

        let (actual_description, actual_der) =
            private_key_decrypt(&db_key, &record_iv, &encrypted).unwrap();

        assert_eq!(actual_description, description);
        assert_eq!(&actual_der[..], private_der);
        assert!(PKey::private_key_from_der(&actual_der).is_ok());
    }
}
