use std::collections::HashMap;

pub const KEYCHAIN_SIGNATURE: &[u8; 4] = b"kych";
pub const HEADER_SIZE: usize = 20;
pub const ATOM_SIZE: usize = 4;
pub const TABLE_HEADER_SIZE: usize = 28;
pub const KEY_BLOB_MAGIC: u32 = 0xFADE_0711;

// Record / table IDs (CSSM_DL_DB_RECORD_*)
pub const CSSM_DL_DB_RECORD_PRIVATE_KEY: u32 = 0x10;
pub const CSSM_DL_DB_RECORD_SYMMETRIC_KEY: u32 = 0x11;
pub const CSSM_DL_DB_RECORD_X509_CERTIFICATE: u32 = 0x8000_1000;
pub const CSSM_DL_DB_RECORD_METADATA: u32 = 0x8000_8000;

pub const SECKEY_HEADER_SIZE: usize = 33 * 4; // 132
pub const X509_HEADER_SIZE: usize = 15 * 4; // 60
pub const KEY_BLOB_REC_HEADER_SIZE: usize = 0x84; // 4+4+0x7C
pub const KEY_BLOB_COMMON_SIZE: usize = 24; // magic+ver+start+total+iv(8)

#[derive(Debug, Clone)]
pub(super) struct DbBlob {
    pub(super) start_crypto: u32,
    pub(super) total_length: u32,
    pub(super) salt: [u8; 20],
    pub(super) iv: [u8; 8],
    /// Absolute file offset of the DBBlob structure start.
    pub(super) base_offset: usize,
}

impl DbBlob {
    pub(super) fn ciphertext<'a>(&self, file: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.base_offset.checked_add(self.start_crypto as usize)?;
        let end = self.base_offset.checked_add(self.total_length as usize)?;
        file.get(start..end)
    }
}

#[derive(Debug, Clone)]
pub struct SymKeyBlob {
    pub iv: [u8; 8],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PrivateKeyRecord {
    pub print_name: String,
    pub key_size_bits: u32,
    /// CSSM Extractable attribute (0 = non-exportable via SecItem).
    pub extractable: u32,
    pub iv: [u8; 8],
    pub encrypted: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct X509Record {
    pub print_name: String,
    pub der: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct TableIndex {
    /// table_id -> absolute file offset of table start.
    pub(super) by_id: HashMap<u32, usize>,
    pub(super) relative: HashMap<u32, u32>,
}
