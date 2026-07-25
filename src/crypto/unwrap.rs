use zeroize::Zeroizing;

use super::des3_cbc_decrypt;
use crate::error::{KdError, Result};

pub const MASTER_KEY_LEN: usize = 24;
pub const DB_KEY_LEN: usize = 24;
const CMS_IV_LEN: usize = 8;
const CMS_DESCRIPTION_LENGTH_LEN: usize = 4;
const MAX_CMS_DESCRIPTION_LEN: usize = 0x1_0000;

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

/// Decrypt the payload of Apple's custom CMS key-wrap format.
///
/// The outer plaintext is `reverse(embedded_iv || inner_ciphertext)`. The IV is
/// stored both in the key-blob header and inside the wrapped payload; requiring
/// them to match rejects truncated or internally inconsistent records.
fn decrypt_apple_custom_payload(
    db_key: &[u8],
    record_iv: &[u8],
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if record_iv.len() != CMS_IV_LEN {
        return Err(KdError::Crypto(format!(
            "CMS record IV must be {CMS_IV_LEN} bytes, got {}",
            record_iv.len()
        )));
    }

    let stage3 = des3_cbc_decrypt(db_key, &MAGIC_CMS_IV, encrypted)?;
    if stage3.len() <= CMS_IV_LEN {
        return Err(KdError::Crypto(format!(
            "CMS outer plaintext too short: {} bytes",
            stage3.len()
        )));
    }

    let stage2 = Zeroizing::new(stage3.iter().rev().copied().collect::<Vec<_>>());
    let (embedded_iv, inner_ciphertext) = stage2.split_at(CMS_IV_LEN);
    if inner_ciphertext.is_empty() || inner_ciphertext.len() % CMS_IV_LEN != 0 {
        return Err(KdError::Crypto(format!(
            "CMS inner ciphertext must be non-empty and 8-byte aligned, got {} bytes",
            inner_ciphertext.len()
        )));
    }
    if embedded_iv != record_iv {
        return Err(KdError::Crypto(
            "CMS embedded IV does not match key-blob record IV".into(),
        ));
    }

    des3_cbc_decrypt(db_key, embedded_iv, inner_ciphertext)
}

/// Split `u32be(description_len) || description || raw_key`.
fn split_apple_custom_payload(plaintext: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let length_bytes = plaintext
        .get(..CMS_DESCRIPTION_LENGTH_LEN)
        .ok_or_else(|| KdError::Crypto("CMS payload is missing description length".into()))?;
    let description_len = u32::from_be_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]) as usize;
    if description_len > MAX_CMS_DESCRIPTION_LEN {
        return Err(KdError::Crypto(format!(
            "CMS description too large: {description_len} bytes"
        )));
    }

    let key_start = CMS_DESCRIPTION_LENGTH_LEN
        .checked_add(description_len)
        .ok_or_else(|| KdError::Crypto("CMS description length overflow".into()))?;
    let description = plaintext
        .get(CMS_DESCRIPTION_LENGTH_LEN..key_start)
        .ok_or_else(|| {
            KdError::Crypto(format!(
                "CMS description length {description_len} exceeds payload"
            ))
        })?
        .to_vec();
    let key = plaintext
        .get(key_start..)
        .ok_or_else(|| KdError::Crypto("CMS key offset exceeds payload".into()))?;
    if key.is_empty() {
        return Err(KdError::Crypto("CMS key material empty".into()));
    }

    Ok((description, Zeroizing::new(key.to_vec())))
}

/// Unwrap a 24-byte symmetric SSGP key from Apple's custom CMS format.
pub fn symmetric_keyblob_decrypt(
    db_key: &[u8],
    record_iv: &[u8],
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let payload = decrypt_apple_custom_payload(db_key, record_iv, encrypted)?;
    let (_description, key) = split_apple_custom_payload(&payload)?;
    if key.len() != DB_KEY_LEN {
        return Err(KdError::Crypto(format!(
            "symmetric key must be {DB_KEY_LEN} bytes, got {}",
            key.len()
        )));
    }
    Ok(key)
}

/// Decrypt private-key material from a file-based keychain key blob.
///
/// Stage 1 uses [`MAGIC_CMS_IV`]. Its plaintext is reversed to recover an
/// embedded IV and the stage-2 ciphertext. The final payload is
/// `u32be(description_len) || description || private_key_der`.
///
/// Returns `(descriptive_data, key_der_bytes)`.
pub fn private_key_decrypt(
    db_key: &[u8],
    record_iv: &[u8],
    encrypted: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let payload = decrypt_apple_custom_payload(db_key, record_iv, encrypted)?;
    split_apple_custom_payload(&payload)
}

#[cfg(test)]
mod tests {
    use cbc::Encryptor;
    use cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};
    use des::TdesEde3;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    use super::{
        private_key_decrypt, split_apple_custom_payload, symmetric_keyblob_decrypt, DB_KEY_LEN,
        MAGIC_CMS_IV,
    };

    type TdesCbcEnc = Encryptor<TdesEde3>;

    fn encrypt_padded(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0u8; plaintext.len() + 8];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        TdesCbcEnc::new_from_slices(key, iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buffer, plaintext.len())
            .unwrap()
            .to_vec()
    }

    fn wrap_apple_custom(
        key: &[u8],
        record_iv: &[u8; 8],
        description: &[u8],
        raw_key: &[u8],
    ) -> Vec<u8> {
        let mut payload = u32::try_from(description.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        payload.extend_from_slice(description);
        payload.extend_from_slice(raw_key);

        let inner_ciphertext = encrypt_padded(key, record_iv, &payload);
        let mut stage2 = record_iv.to_vec();
        stage2.extend_from_slice(&inner_ciphertext);
        stage2.reverse();
        encrypt_padded(key, &MAGIC_CMS_IV, &stage2)
    }

    #[test]
    fn cms_payload_parses_variable_length_descriptions() {
        for description in [Vec::new(), vec![0x11], vec![0x22; 4], vec![0x33; 12]] {
            let mut plaintext = u32::try_from(description.len())
                .unwrap()
                .to_be_bytes()
                .to_vec();
            plaintext.extend_from_slice(&description);
            plaintext.extend_from_slice(b"raw-key");

            let (actual_description, key) = split_apple_custom_payload(&plaintext).unwrap();
            assert_eq!(actual_description, description);
            assert_eq!(&key[..], b"raw-key");
        }
    }

    #[test]
    fn cms_payload_rejects_invalid_description_and_empty_key() {
        assert!(split_apple_custom_payload(&[0, 0, 0]).is_err());
        assert!(split_apple_custom_payload(&[0, 0, 0, 2, 0xff]).is_err());
        assert!(split_apple_custom_payload(&[0, 0, 0, 0]).is_err());
        assert!(split_apple_custom_payload(&[0, 1, 0, 1, 0xff]).is_err());
    }

    #[test]
    fn cms_payload_accepts_maximum_description_length() {
        let description = vec![0xa5; super::MAX_CMS_DESCRIPTION_LEN];
        let mut plaintext = u32::try_from(description.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        plaintext.extend_from_slice(&description);
        plaintext.push(0x5a);

        let (actual_description, key) = split_apple_custom_payload(&plaintext).unwrap();
        assert_eq!(actual_description, description);
        assert_eq!(&key[..], &[0x5a]);
    }

    #[test]
    fn symmetric_keyblob_decrypt_accepts_canonical_40_byte_stage1() {
        let db_key = [0x11; 24];
        let record_iv = [0x22; 8];
        let encrypted = wrap_apple_custom(&db_key, &record_iv, &[], &[0x5a; DB_KEY_LEN]);
        // 28-byte payload -> 32-byte TEMP1 -> 40-byte TEMP2 -> 48-byte TEMP4.
        assert_eq!(encrypted.len(), 48);

        let key = symmetric_keyblob_decrypt(&db_key, &record_iv, &encrypted).unwrap();
        assert_eq!(&key[..], &[0x5a; DB_KEY_LEN]);
        assert!(symmetric_keyblob_decrypt(&[0x33; 24], &record_iv, &encrypted).is_err());
    }

    #[test]
    fn private_key_decrypt_parses_nonempty_description() {
        let db_key = [0x11; 24];
        let record_iv = [0x22; 8];
        let description = b"private ACL";
        let private_der = Rsa::generate(1024).unwrap().private_key_to_der().unwrap();
        let expected_len = private_der.len();
        let encrypted = wrap_apple_custom(&db_key, &record_iv, description, &private_der);
        // Drop the raw DER so failed assertions cannot print key material.
        drop(private_der);

        let (actual_description, actual_der) =
            private_key_decrypt(&db_key, &record_iv, &encrypted).unwrap();

        assert_eq!(actual_description, description);
        assert_eq!(actual_der.len(), expected_len);
        // Structural check only — avoid assert_eq! on full private DER in logs.
        assert!(PKey::private_key_from_der(&actual_der).is_ok());
    }

    #[test]
    fn cms_unwrap_rejects_mismatched_record_iv() {
        let db_key = [0x11; 24];
        let record_iv = [0x22; 8];
        let encrypted = wrap_apple_custom(&db_key, &record_iv, &[], &[0x5a; DB_KEY_LEN]);

        assert!(symmetric_keyblob_decrypt(&db_key, &[0x23; 8], &encrypted).is_err());
        assert!(symmetric_keyblob_decrypt(&db_key, &[0x22; 7], &encrypted).is_err());
    }
}
