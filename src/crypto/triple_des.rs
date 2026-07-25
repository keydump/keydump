use cbc::Decryptor;
use cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use des::TdesEde3;
use zeroize::Zeroizing;

use crate::error::{KdError, Result};

type TdesCbcDec = Decryptor<TdesEde3>;

/// 3DES-CBC decrypt with PKCS#7 padding validation.
pub fn des3_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 24 {
        return Err(KdError::Crypto(format!(
            "3DES key must be 24 bytes, got {}",
            key.len()
        )));
    }
    if iv.len() != 8 {
        return Err(KdError::Crypto(format!(
            "3DES IV must be 8 bytes, got {}",
            iv.len()
        )));
    }
    if ciphertext.is_empty() || ciphertext.len() % 8 != 0 {
        return Err(KdError::Crypto(
            "ciphertext empty or not 8-byte aligned".into(),
        ));
    }

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let dec = TdesCbcDec::new_from_slices(key, iv)
        .map_err(|e| KdError::Crypto(format!("init 3DES: {e}")))?;
    let plain = dec
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| KdError::WrongCredential)?;
    Ok(Zeroizing::new(plain.to_vec()))
}
