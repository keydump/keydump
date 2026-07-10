use crate::crypto::MASTER_KEY_LEN;
use crate::error::{KdError, Result};
use zeroize::Zeroizing;

pub fn parse_master_key_hex(s: &str) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    let cleaned = s.trim().trim_start_matches("0x");
    if cleaned.len() != MASTER_KEY_LEN * 2 {
        return Err(KdError::Msg(format!(
            "master key must be {MASTER_KEY_LEN} bytes ({} hex chars), got {} bytes",
            MASTER_KEY_LEN * 2,
            cleaned.len() / 2
        )));
    }

    let mut bytes = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    hex::decode_to_slice(cleaned, &mut bytes[..])
        .map_err(|e| KdError::Msg(format!("invalid hex key: {e}")))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::parse_master_key_hex;

    #[test]
    fn parses_prefixed_master_key_without_heap_decoding() {
        let parsed =
            parse_master_key_hex("  0x00112233445566778899aabbccddeeff0011223344556677\n").unwrap();

        assert_eq!(parsed.len(), 24);
        assert_eq!(&parsed[..4], &[0x00, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn rejects_wrong_length_or_invalid_master_keys() {
        assert!(parse_master_key_hex("0011").is_err());
        assert!(parse_master_key_hex("00112233445566778899aabbccddeeff00112233445566zz").is_err());
    }
}
