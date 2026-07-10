use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::types::*;
use crate::error::{KdError, Result};

fn be_u32(data: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| KdError::InvalidKeychain(format!("u32 offset overflow @ {off}")))?;
    let b = data
        .get(off..end)
        .ok_or_else(|| KdError::InvalidKeychain(format!("oob u32 @ {off}")))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_lv(data: &[u8], base: usize, col: u32) -> Result<Vec<u8>> {
    if col == 0 {
        return Ok(Vec::new());
    }
    let p = base
        .checked_add((col & 0xFFFF_FFFE) as usize)
        .ok_or_else(|| KdError::InvalidKeychain("LV offset overflow".into()))?;
    let len = be_u32(data, p)? as usize;
    let start = p
        .checked_add(4)
        .ok_or_else(|| KdError::InvalidKeychain("LV start overflow".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| KdError::InvalidKeychain("LV length overflow".into()))?;
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
    let p = base
        .checked_add((col & 0xFFFF_FFFE) as usize)
        .ok_or_else(|| KdError::InvalidKeychain("integer attribute offset overflow".into()))?;
    be_u32(data, p)
}

pub struct KeychainFile {
    data: Vec<u8>,
    tables: TableIndex,
    db_blob: DbBlob,
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
        let table_count = be_u32(
            &data,
            schema_off
                .checked_add(4)
                .ok_or_else(|| KdError::InvalidKeychain("schema offset overflow".into()))?,
        )? as usize;

        // Table offsets sit immediately after the ApplDBSchema header.
        let table_list_base = schema_off
            .checked_add(8)
            .ok_or_else(|| KdError::InvalidKeychain("table list offset overflow".into()))?;
        let table_list_len = table_count
            .checked_mul(ATOM_SIZE)
            .ok_or_else(|| KdError::InvalidKeychain("table count overflow".into()))?;
        let table_list_end = table_list_base
            .checked_add(table_list_len)
            .ok_or_else(|| KdError::InvalidKeychain("table list length overflow".into()))?;
        if table_list_end > data.len() {
            return Err(KdError::InvalidKeychain(format!(
                "table list oob: count {table_count}"
            )));
        }
        let mut rel_offsets = Vec::with_capacity(table_count);
        for i in 0..table_count {
            let off = be_u32(&data, table_list_base + i * ATOM_SIZE)?;
            rel_offsets.push(off);
        }

        let mut by_id = HashMap::new();
        let mut relative = HashMap::new();
        for rel in &rel_offsets {
            let abs = schema_off
                .checked_add(*rel as usize)
                .ok_or_else(|| KdError::InvalidKeychain("table offset overflow".into()))?;
            let table_id = be_u32(&data, abs + 4)?;
            if by_id.insert(table_id, abs).is_some() || relative.insert(table_id, *rel).is_some() {
                return Err(KdError::InvalidKeychain(format!(
                    "duplicate table id {table_id:#x}"
                )));
            }
        }

        let tables = TableIndex { by_id, relative };
        let meta_rel = *tables
            .relative
            .get(&CSSM_DL_DB_RECORD_METADATA)
            .ok_or(KdError::TableMissing(CSSM_DL_DB_RECORD_METADATA))?;

        // Classic layout: DBBlob at table_rel + 0x38 from after-header base.
        let blob_base = schema_off
            .checked_add(meta_rel as usize)
            .and_then(|v| v.checked_add(0x38))
            .ok_or_else(|| KdError::InvalidKeychain("DBBlob offset overflow".into()))?;
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

    pub fn file_len(&self) -> usize {
        self.data.len()
    }

    pub fn database_salt(&self) -> &[u8; 20] {
        &self.db_blob.salt
    }

    pub fn database_iv(&self) -> &[u8; 8] {
        &self.db_blob.iv
    }

    pub fn database_ciphertext(&self) -> Result<&[u8]> {
        self.db_blob
            .ciphertext(&self.data)
            .ok_or_else(|| KdError::InvalidKeychain("DBBlob ciphertext oob".into()))
    }

    fn table_records(&self, table_id: u32) -> Result<(usize, Vec<u32>)> {
        let abs = *self
            .tables
            .by_id
            .get(&table_id)
            .ok_or(KdError::TableMissing(table_id))?;
        let record_count = be_u32(&self.data, abs + 8)? as usize;
        let table_size = be_u32(&self.data, abs)? as usize;
        if table_size < TABLE_HEADER_SIZE {
            return Err(KdError::InvalidKeychain(format!(
                "table {table_id:#x} is too small: {table_size}"
            )));
        }
        let table_end = abs
            .checked_add(table_size)
            .ok_or_else(|| KdError::InvalidKeychain("table size overflow".into()))?;
        if table_end > self.data.len() {
            return Err(KdError::InvalidKeychain(format!(
                "table {table_id:#x} extends past end of file"
            )));
        }
        let mut recs = Vec::new();
        let mut slot = TABLE_HEADER_SIZE;
        let mut first_record = table_size;
        while recs.len() < record_count {
            let slot_end = slot
                .checked_add(ATOM_SIZE)
                .ok_or_else(|| KdError::InvalidKeychain("record slot overflow".into()))?;
            if slot_end > first_record {
                return Err(KdError::InvalidKeychain(format!(
                    "table {table_id:#x} declares {record_count} records but only {} offsets exist",
                    recs.len()
                )));
            }
            let ro = be_u32(&self.data, abs + slot)?;
            if ro != 0 {
                let ro_usize = ro as usize;
                if ro % 4 != 0 || ro_usize < TABLE_HEADER_SIZE || ro_usize >= table_size {
                    return Err(KdError::InvalidKeychain(format!(
                        "invalid record offset {ro:#x} in table {table_id:#x}"
                    )));
                }
                first_record = first_record.min(ro_usize);
                recs.push(ro);
            }
            slot = slot_end;
        }

        let mut unique_offsets = HashSet::with_capacity(recs.len());
        for &record_offset in &recs {
            if (record_offset as usize) < slot {
                return Err(KdError::InvalidKeychain(format!(
                    "record offset {record_offset:#x} overlaps the index in table {table_id:#x}"
                )));
            }
            if !unique_offsets.insert(record_offset) {
                return Err(KdError::InvalidKeychain(format!(
                    "duplicate record offset {record_offset:#x} in table {table_id:#x}"
                )));
            }
        }
        Ok((abs, recs))
    }

    pub fn private_keys(&self) -> Result<Vec<PrivateKeyRecord>> {
        let (table_abs, recs) = self.table_records(CSSM_DL_DB_RECORD_PRIVATE_KEY)?;
        let mut out = Vec::new();
        for ro in recs {
            let base = table_abs + ro as usize;
            out.push(parse_private_key(&self.data, base)?);
        }
        Ok(out)
    }

    pub fn certificates(&self) -> Result<Vec<X509Record>> {
        let (table_abs, recs) = self.table_records(CSSM_DL_DB_RECORD_X509_CERTIFICATE)?;
        let mut out = Vec::new();
        for ro in recs {
            let base = table_abs + ro as usize;
            out.push(parse_x509(&self.data, base)?);
        }
        Ok(out)
    }

    /// Sample symmetric keyblobs (for master-key validation / SSGP; not required for private-key path).
    pub fn symmetric_keyblobs(&self) -> Result<Vec<SymKeyBlob>> {
        let (table_abs, recs) = self.table_records(CSSM_DL_DB_RECORD_SYMMETRIC_KEY)?;
        let mut out = Vec::new();
        for ro in recs {
            let base = table_abs + ro as usize;
            if let Some(b) = parse_sym_keyblob(&self.data, base)? {
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

    let blob_start = base
        .checked_add(SECKEY_HEADER_SIZE)
        .ok_or_else(|| KdError::InvalidKeychain("private key blob offset overflow".into()))?;
    let blob_end = blob_start
        .checked_add(blob_size)
        .ok_or_else(|| KdError::InvalidKeychain("private key blob size overflow".into()))?;
    let blob = data
        .get(blob_start..blob_end)
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
    let cert_start = base
        .checked_add(X509_HEADER_SIZE)
        .ok_or_else(|| KdError::InvalidKeychain("x509 offset overflow".into()))?;
    let cert_end = cert_start
        .checked_add(cert_size)
        .ok_or_else(|| KdError::InvalidKeychain("x509 size overflow".into()))?;
    let der = data
        .get(cert_start..cert_end)
        .ok_or_else(|| KdError::InvalidKeychain("x509 der oob".into()))?
        .to_vec();
    Ok(X509Record { print_name, der })
}

fn parse_sym_keyblob(data: &[u8], base: usize) -> Result<Option<SymKeyBlob>> {
    let rec_size = be_u32(data, base)? as usize;
    if rec_size < KEY_BLOB_REC_HEADER_SIZE + KEY_BLOB_COMMON_SIZE {
        return Ok(None);
    }
    let record_start = base
        .checked_add(KEY_BLOB_REC_HEADER_SIZE)
        .ok_or_else(|| KdError::InvalidKeychain("sym record offset overflow".into()))?;
    let record_end = base
        .checked_add(rec_size)
        .ok_or_else(|| KdError::InvalidKeychain("sym record size overflow".into()))?;
    let record = data
        .get(record_start..record_end)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn parser_uses_schema_offset_as_the_table_base() {
        let schema = 32usize;
        let table = schema + 16;
        let blob = table + 0x38;
        let mut data = vec![0u8; blob + 80];
        data[..4].copy_from_slice(KEYCHAIN_SIGNATURE);
        put_u32(&mut data, 12, schema as u32);
        put_u32(&mut data, schema + 4, 1);
        put_u32(&mut data, schema + 8, 16);
        put_u32(&mut data, table + 4, CSSM_DL_DB_RECORD_METADATA);
        put_u32(&mut data, blob, KEY_BLOB_MAGIC);

        let parsed = KeychainFile::parse(data).unwrap();

        assert_eq!(parsed.db_blob.base_offset, blob);
        assert_eq!(parsed.tables.by_id[&CSSM_DL_DB_RECORD_METADATA], table);
    }

    #[test]
    fn parser_rejects_table_count_beyond_the_file() {
        let mut data = vec![0u8; HEADER_SIZE + 8];
        data[..4].copy_from_slice(KEYCHAIN_SIGNATURE);
        put_u32(&mut data, 12, HEADER_SIZE as u32);
        put_u32(&mut data, HEADER_SIZE + 4, u32::MAX);

        assert!(KeychainFile::parse(data).is_err());
    }

    #[test]
    fn malformed_record_is_not_silently_discarded() {
        let table_id = CSSM_DL_DB_RECORD_PRIVATE_KEY;
        let mut data = vec![0u8; 96];
        put_u32(&mut data, 0, 96);
        put_u32(&mut data, 8, 1);
        put_u32(&mut data, TABLE_HEADER_SIZE, 64);
        let mut by_id = HashMap::new();
        by_id.insert(table_id, 0);
        let kc = KeychainFile {
            data,
            tables: TableIndex {
                by_id,
                relative: HashMap::new(),
            },
            db_blob: DbBlob {
                start_crypto: 0,
                total_length: 0,
                salt: [0; 20],
                iv: [0; 8],
                base_offset: 0,
            },
        };

        assert!(kc.private_keys().is_err());
    }

    #[test]
    fn record_offsets_must_be_unique_and_follow_the_index() {
        let table_id = CSSM_DL_DB_RECORD_PRIVATE_KEY;
        for offsets in [&[TABLE_HEADER_SIZE as u32][..], &[64, 64][..]] {
            let mut data = vec![0u8; 96];
            put_u32(&mut data, 0, 96);
            put_u32(&mut data, 8, offsets.len() as u32);
            for (index, offset) in offsets.iter().enumerate() {
                put_u32(&mut data, TABLE_HEADER_SIZE + index * ATOM_SIZE, *offset);
            }
            let mut by_id = HashMap::new();
            by_id.insert(table_id, 0);
            let kc = KeychainFile {
                data,
                tables: TableIndex {
                    by_id,
                    relative: HashMap::new(),
                },
                db_blob: DbBlob {
                    start_crypto: 0,
                    total_length: 0,
                    salt: [0; 20],
                    iv: [0; 8],
                    base_offset: 0,
                },
            };

            assert!(kc.private_keys().is_err());
        }
    }
}
