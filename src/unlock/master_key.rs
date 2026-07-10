use crate::crypto::MASTER_KEY_LEN;
use crate::error::{KdError, Result};
use zeroize::Zeroizing;

pub fn parse_master_key_hex(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(cleaned).map_err(|e| KdError::Msg(format!("invalid hex key: {e}")))?;
    if bytes.len() != MASTER_KEY_LEN {
        return Err(KdError::Msg(format!(
            "master key must be {MASTER_KEY_LEN} bytes ({} hex chars), got {} bytes",
            MASTER_KEY_LEN * 2,
            bytes.len()
        )));
    }
    Ok(Zeroizing::new(bytes))
}
