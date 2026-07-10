use std::collections::HashMap;
use std::path::Path;

use super::types::*;
use crate::error::{KdError, Result};

fn be_u32(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or_else(|| KdError::InvalidKeychain(format!("oob u32 @ {off}")))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_lv(data: &[u8], base: usize, col: u32) -> Result<Vec<u8>> {
    if col == 0 {
        return Ok(Vec::new());
    }
    let p = base + (col & 0xFFFF_FFFE) as usize;
    let len = be_u32(data, p)? as usize;
    let start = p + 4;
    let end = start.saturating_add(len);
    data.get(start..end)
        .map(|s| s.to_vec())
        .ok_or_else(|| KdError::InvalidKeychain(format!("oob LV @ {p} len {len}")))
}

fn read_lv_string(data: &[u8], base: usize, col: u32) -> Result<String> {
    let raw = read_lv(data, base, col)?;
    let s = String::from_utf8_lossy(&raw);
    Ok(s.trim_end_matches('\0').to_string())
}

fn read_int_attr(data: &[u8], base: usize, col: u32) -> Result<u32> {
    if col == 0 {
        return Ok(0);
    }
    let p = base + (col & 0xFFFF_FFFE) as usize;
    be_u32(data, p)
}

pub struct KeychainFile {
    pub data: Vec<u8>,
    pub tables: TableIndex,
    pub db_blob: DbBlob,
}

impl KeychainFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path.as_ref())?;
        Self::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() < HEADER_SIZE + 8 {
            return Err(KdError::InvalidKeychain("file too small".into()));
        }
        if &data[0..4] != KEYCHAIN_SIGNATURE {
            return Err(KdError::InvalidKeychain(format!(
                "bad signature (want kych, got {:?})",
                String::from_utf8_lossy(&data[0..4])
            )));
        }

        let schema_off = be_u32(&data, 12)? as usize;
        let table_count = be_u32(&data, schema_off + 4)? as usize;

        // Table offsets sit immediately after ApplDBSchema header (8 bytes),
        // at HEADER_SIZE + 8 when schema_off == HEADER_SIZE (typical).
        let table_list_base = HEADER_SIZE + 8;
        let mut rel_offsets = Vec::with_capacity(table_count);
        for i in 0..table_count {
            let off = be_u32(&data, table_list_base + i * ATOM_SIZE)?;
            rel_offsets.push(off);
        }

        let mut by_id = HashMap::new();
        let mut relative = HashMap::new();
        for rel in &rel_offsets {
            let abs = HEADER_SIZE + *rel as usize;
            let table_id = be_u32(&data, abs + 4)?;
            by_id.insert(table_id, abs);
            relative.insert(table_id, *rel);
        }

        let tables = TableIndex { by_id, relative };
        let meta_rel = *tables
            .relative
            .get(&CSSM_DL_DB_RECORD_METADATA)
            .ok_or(KdError::TableMissing(CSSM_DL_DB_RECORD_METADATA))?;

        // Classic layout: DBBlob at table_rel + 0x38 from after-header base.
        let blob_base = HEADER_SIZE + meta_rel as usize + 0x38;
        let db_blob = parse_db_blob(&data, blob_base)?;

        Ok(Self {
            data,
            tables,
            db_blob,
        })
    }

    pub fn blob_version(&self) -> u32 {
        be_u32(&self.data, self.db_blob.base_offset + 4).unwrap_or(0)
    }

    fn table_records(&self, table_id: u32) -> Result<(usize, Vec<u32>)> {
        let abs = *self
            .tables
            .by_id
            .get(&table_id)
            .ok_or(KdError::TableMissing(table_id))?;
        let record_count = be_u32(&self.data, abs + 8)? as usize;
        let mut recs = Vec::new();
        let mut i = 0usize;
        let ro_base = abs + TABLE_HEADER_SIZE;
        while recs.len() < record_count {
            let ro = be_u32(&self.data, ro_base + i * ATOM_SIZE)?;
            if ro != 0 && ro % 4 == 0 {
                recs.push(ro);
            }
            i += 1;
            if i > record_count * 8 + 10_000 {
                break;
            }
        }
        Ok((abs, recs))
    }

    pub fn private_keys(&self) -> Result<Vec<PrivateKeyRecord>> {
        let (table_abs, recs) = self.table_records(CSSM_DL_DB_RECORD_PRIVATE_KEY)?;
        let mut out = Vec::new();
        for ro in recs {
            let base = table_abs + ro as usize;
            if let Ok(rec) = parse_private_key(&self.data, base) {
                out.push(rec);
            }
        }
        Ok(out)
    }

    pub fn certificates(&self) -> Result<Vec<X509Record>> {
        let (table_abs, recs) = self.table_records(CSSM_DL_DB_RECORD_X509_CERTIFICATE)?;
        let mut out = Vec::new();
        for ro in recs {
            let base = table_abs + ro as usize;
            if let Ok(rec) = parse_x509(&self.data, base) {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Sample symmetric keyblobs (for master-key validation / SSGP; not required for private-key path).
    pub fn symmetric_keyblobs(&self) -> Result<Vec<SymKeyBlob>> {
        let (table_abs, recs) = self.table_records(CSSM_DL_DB_RECORD_SYMMETRIC_KEY)?;
        let mut out = Vec::new();
        for ro in recs {
            let base = table_abs + ro as usize;
            if let Ok(Some(b)) = parse_sym_keyblob(&self.data, base) {
                out.push(b);
            }
        }
        Ok(out)
    }
}

fn parse_db_blob(data: &[u8], base: usize) -> Result<DbBlob> {
    let magic = be_u32(data, base)?;
    if magic != KEY_BLOB_MAGIC {
        return Err(KdError::InvalidKeychain(format!(
            "DBBlob magic {:#x} @ {base:#x}, expected {KEY_BLOB_MAGIC:#x}",
            magic
        )));
    }
    let start_crypto = be_u32(data, base + 8)?;
    let total_length = be_u32(data, base + 12)?;
    let salt_off = base + 44;
    let iv_off = base + 64;
    let salt_slice = data
        .get(salt_off..salt_off + 20)
        .ok_or_else(|| KdError::InvalidKeychain("DBBlob salt oob".into()))?;
    let iv_slice = data
        .get(iv_off..iv_off + 8)
        .ok_or_else(|| KdError::InvalidKeychain("DBBlob iv oob".into()))?;
    let mut salt = [0u8; 20];
    let mut iv = [0u8; 8];
    salt.copy_from_slice(salt_slice);
    iv.copy_from_slice(iv_slice);
    Ok(DbBlob {
        start_crypto,
        total_length,
        salt,
        iv,
        base_offset: base,
    })
}

fn parse_key_blob_enc(blob: &[u8]) -> Result<([u8; 8], Vec<u8>)> {
    if blob.len() < KEY_BLOB_COMMON_SIZE {
        return Err(KdError::InvalidKeychain("key blob too short".into()));
    }
    let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != KEY_BLOB_MAGIC {
        return Err(KdError::InvalidKeychain(format!(
            "key blob magic {magic:#x}"
        )));
    }
    let start = u32::from_be_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let total = u32::from_be_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&blob[16..24]);
    if total > blob.len() || start > total {
        return Err(KdError::InvalidKeychain("key blob bounds".into()));
    }
    Ok((iv, blob[start..total].to_vec()))
}

fn parse_private_key(data: &[u8], base: usize) -> Result<PrivateKeyRecord> {
    // CSSM SecKey-style record: big-endian attribute offset table, then key blob.
    let blob_size = be_u32(data, base + 16)? as usize;
    let print_name_off = be_u32(data, base + 28)?;
    let key_size_off = be_u32(data, base + 64)?;
    let extractable_off = be_u32(data, base + 88)?;

    let print_name = read_lv_string(data, base, print_name_off)?;
    let key_size_bits = read_int_attr(data, base, key_size_off)?;
    let extractable = read_int_attr(data, base, extractable_off)?;

    let blob_start = base + SECKEY_HEADER_SIZE;
    let blob = data
        .get(blob_start..blob_start + blob_size)
        .ok_or_else(|| KdError::InvalidKeychain("private key blob oob".into()))?;
    let (iv, encrypted) = parse_key_blob_enc(blob)?;

    Ok(PrivateKeyRecord {
        print_name,
        key_size_bits,
        extractable,
        iv,
        encrypted,
    })
}

fn parse_x509(data: &[u8], base: usize) -> Result<X509Record> {
    let cert_size = be_u32(data, base + 16)? as usize;
    let print_name_off = be_u32(data, base + 32)?;
    let print_name = read_lv_string(data, base, print_name_off)?;
    let cert_start = base + X509_HEADER_SIZE;
    let der = data
        .get(cert_start..cert_start + cert_size)
        .ok_or_else(|| KdError::InvalidKeychain("x509 der oob".into()))?
        .to_vec();
    Ok(X509Record { print_name, der })
}

fn parse_sym_keyblob(data: &[u8], base: usize) -> Result<Option<SymKeyBlob>> {
    let rec_size = be_u32(data, base)? as usize;
    if rec_size < KEY_BLOB_REC_HEADER_SIZE + KEY_BLOB_COMMON_SIZE {
        return Ok(None);
    }
    let record = data
        .get(base + KEY_BLOB_REC_HEADER_SIZE..base + rec_size)
        .ok_or_else(|| KdError::InvalidKeychain("sym record oob".into()))?;
    let magic = u32::from_be_bytes([record[0], record[1], record[2], record[3]]);
    if magic != KEY_BLOB_MAGIC {
        return Ok(None);
    }
    let start = u32::from_be_bytes([record[8], record[9], record[10], record[11]]) as usize;
    let total = u32::from_be_bytes([record[12], record[13], record[14], record[15]]) as usize;
    if total + 8 + 4 > record.len() || start >= total {
        return Ok(None);
    }
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&record[16..24]);
    let ciphertext = record[start..total].to_vec();
    if ciphertext.is_empty() || ciphertext.len() % 8 != 0 {
        return Ok(None);
    }
    Ok(Some(SymKeyBlob { iv, ciphertext }))
}
