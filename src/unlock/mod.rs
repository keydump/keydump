//! Unlock strategies: password, master-key hex, securityd memory scan.

mod master_key;
mod password;

#[cfg(target_os = "macos")]
mod securityd;

use zeroize::Zeroizing;

use crate::crypto::{decrypt_db_key, private_key_decrypt, symmetric_keyblob_decrypt};
use crate::error::{KdError, Result};
use crate::keychain::{KeychainFile, PrivateKeyRecord};

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

impl Unlocked {
    pub fn from_master_key(kc: &KeychainFile, master: &[u8]) -> Result<Self> {
        let ct = kc
            .db_blob
            .ciphertext(&kc.data)
            .ok_or_else(|| KdError::InvalidKeychain("DBBlob ciphertext oob".into()))?;
        let db_key = decrypt_db_key(master, &kc.db_blob.iv, ct)?;
        // Optional: validate against a symmetric keyblob if present
        if let Ok(blobs) = kc.symmetric_keyblobs() {
            if let Some(b) = blobs.first() {
                let _ = symmetric_keyblob_decrypt(&db_key, &b.iv, &b.ciphertext)?;
            }
        }
        Ok(Self {
            db_key,
            master_key: Some(Zeroizing::new(master.to_vec())),
            method: "master-key",
        })
    }

    pub fn decrypt_private_key(&self, rec: &PrivateKeyRecord) -> Result<(Vec<u8>, Vec<u8>)> {
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
