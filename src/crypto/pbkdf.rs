use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;

use super::unwrap::MASTER_KEY_LEN;

/// Classic file-based keychain: PBKDF2-HMAC-SHA1, 1000 iterations, 24-byte key.
pub const DEFAULT_PBKDF2_ITERS: u32 = 1000;

#[must_use]
pub fn derive_master_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut key)
        .expect("pbkdf2 length is fixed and valid");
    key
}
