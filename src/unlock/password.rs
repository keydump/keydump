use super::Unlocked;
use crate::crypto::derive_master_key;
use crate::error::Result;
use crate::keychain::KeychainFile;

pub fn unlock_with_password(
    kc: &KeychainFile,
    password: &[u8],
    iterations: u32,
) -> Result<Unlocked> {
    let master = derive_master_key(password, kc.database_salt(), iterations);
    let mut unlocked = Unlocked::from_master_key(kc, &master[..])?;
    unlocked.method = "password";
    Ok(unlocked)
}
