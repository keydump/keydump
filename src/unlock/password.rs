use zeroize::Zeroizing;

use super::Unlocked;
use crate::crypto::symmetric_keyblob_decrypt;
use crate::crypto::{decrypt_db_key, derive_master_key};
use crate::error::{KdError, Result};
use crate::keychain::KeychainFile;

pub fn unlock_with_password(
    kc: &KeychainFile,
    password: &[u8],
    iterations: u32,
) -> Result<Unlocked> {
    let master = derive_master_key(password, &kc.db_blob.salt, iterations);
    let ct = kc
        .db_blob
        .ciphertext(&kc.data)
        .ok_or_else(|| KdError::InvalidKeychain("DBBlob ciphertext oob".into()))?;
    let db_key = match decrypt_db_key(&master, &kc.db_blob.iv, ct) {
        Ok(k) => k,
        Err(_) => {
            return Err(KdError::WrongCredential);
        }
    };

    // Prefer validating with a symmetric keyblob when available.
    if let Ok(blobs) = kc.symmetric_keyblobs() {
        let mut ok = blobs.is_empty();
        for b in &blobs {
            if symmetric_keyblob_decrypt(&db_key, &b.iv, &b.ciphertext).is_ok() {
                ok = true;
                break;
            }
        }
        if !ok && !blobs.is_empty() {
            // Padding may succeed spuriously; require real unwrap when we have samples.
            return Err(KdError::WrongCredential);
        }
    }

    Ok(Unlocked {
        db_key,
        master_key: Some(Zeroizing::new(master.to_vec())),
        method: "password",
    })
}
