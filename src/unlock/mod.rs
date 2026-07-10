//! Unlock strategies: password, master-key hex, securityd memory scan.

mod master_key;
mod password;

#[cfg(target_os = "macos")]
mod securityd;

use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use zeroize::Zeroizing;

use crate::crypto::{decrypt_db_key, private_key_decrypt, symmetric_keyblob_decrypt};
use crate::error::{KdError, Result};
use crate::keychain::{KeychainFile, PrivateKeyRecord, SymKeyBlob};

pub use master_key::parse_master_key_hex;
pub use password::unlock_with_password;

#[cfg(target_os = "macos")]
pub use securityd::unlock_from_securityd;

#[cfg(not(target_os = "macos"))]
pub fn unlock_from_securityd(_kc: &KeychainFile) -> Result<Unlocked> {
    Err(KdError::Securityd(
        "--from-securityd is only available on macOS".into(),
    ))
}

/// Unlocked keychain DB wrapping key + helpers to decrypt private keys.
pub struct Unlocked {
    pub db_key: Zeroizing<Vec<u8>>,
    pub master_key: Option<Zeroizing<Vec<u8>>>,
    pub method: &'static str,
}

struct DbKeyValidator {
    symmetric_blobs: Vec<SymKeyBlob>,
    private_keys: Vec<PrivateKeyRecord>,
}

impl DbKeyValidator {
    fn from_keychain(kc: &KeychainFile) -> Result<Self> {
        let symmetric_blobs = kc.symmetric_keyblobs()?;
        let private_keys = kc.private_keys()?;
        if symmetric_blobs.is_empty() && private_keys.is_empty() {
            return Err(KdError::InvalidKeychain(
                "no symmetric or private key records available to validate the DB key".into(),
            ));
        }
        Ok(Self {
            symmetric_blobs,
            private_keys,
        })
    }

    fn validates(&self, db_key: &[u8]) -> bool {
        if self
            .symmetric_blobs
            .iter()
            .any(|blob| symmetric_keyblob_decrypt(db_key, &blob.iv, &blob.ciphertext).is_ok())
        {
            return true;
        }

        self.private_keys.iter().any(|record| {
            let Ok((_, der)) = private_key_decrypt(db_key, &record.iv, &record.encrypted) else {
                return false;
            };
            PKey::private_key_from_der(&der).is_ok() || Rsa::private_key_from_der(&der).is_ok()
        })
    }
}

impl Unlocked {
    pub fn from_master_key(kc: &KeychainFile, master: &[u8]) -> Result<Self> {
        let ct = kc
            .db_blob
            .ciphertext(&kc.data)
            .ok_or_else(|| KdError::InvalidKeychain("DBBlob ciphertext oob".into()))?;
        let db_key = decrypt_db_key(master, &kc.db_blob.iv, ct)?;
        let validator = DbKeyValidator::from_keychain(kc)?;
        if !validator.validates(&db_key) {
            return Err(KdError::WrongCredential);
        }
        Ok(Self {
            db_key,
            master_key: Some(Zeroizing::new(master.to_vec())),
            method: "master-key",
        })
    }

    pub fn decrypt_private_key(
        &self,
        rec: &PrivateKeyRecord,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        private_key_decrypt(&self.db_key, &rec.iv, &rec.encrypted)
    }
}

/// Try password path (classic PBKDF2). May fail on macOS 26.x blobVersion=0x200.
pub fn try_password(kc: &KeychainFile, password: &str, iterations: u32) -> Result<Unlocked> {
    unlock_with_password(kc, password.as_bytes(), iterations)
}

pub fn try_master_key_hex(kc: &KeychainFile, hex_key: &str) -> Result<Unlocked> {
    let master = parse_master_key_hex(hex_key)?;
    let mut u = Unlocked::from_master_key(kc, &master)?;
    u.method = "master-key";
    Ok(u)
}

#[cfg(test)]
mod tests {
    use cbc::Encryptor;
    use cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use des::TdesEde3;

    use super::{DbKeyValidator, SymKeyBlob};

    type TdesCbcEnc = Encryptor<TdesEde3>;
    const MAGIC_CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

    fn encrypt_padded(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0u8; plaintext.len() + 8];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        TdesCbcEnc::new_from_slices(key, iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .unwrap()
            .to_vec()
    }

    fn wrapped_symmetric_blob(db_key: &[u8], record_iv: [u8; 8]) -> SymKeyBlob {
        let mut inner_plaintext = vec![0u8; 28];
        inner_plaintext[4..].fill(0x5a);
        let inner_ciphertext = encrypt_padded(db_key, &record_iv, &inner_plaintext);
        let mut outer_plaintext: Vec<u8> = inner_ciphertext.iter().rev().copied().collect();
        outer_plaintext.extend(record_iv.iter().rev());
        let ciphertext = encrypt_padded(db_key, &MAGIC_CMS_IV, &outer_plaintext);
        SymKeyBlob {
            iv: record_iv,
            ciphertext,
        }
    }

    #[test]
    fn validator_uses_any_structurally_valid_key_record() {
        let db_key = [0x11; 24];
        let validator = DbKeyValidator {
            symmetric_blobs: vec![
                SymKeyBlob {
                    iv: [0x22; 8],
                    ciphertext: vec![0; 48],
                },
                wrapped_symmetric_blob(&db_key, [0x33; 8]),
            ],
            private_keys: Vec::new(),
        };

        assert!(validator.validates(&db_key));
        assert!(!validator.validates(&[0x44; 24]));
    }
}
