//! Known-answer tests for keydump crypto.
//!
//! The JSON files under `tests/kat/vectors/` are independently verified,
//! committed test data. This repository intentionally has no vector generator.

use std::fs;
use std::path::PathBuf;

use keydump::crypto::{
    decrypt_db_key, derive_master_key, des3_cbc_decrypt, private_key_decrypt,
    symmetric_keyblob_decrypt, DEFAULT_PBKDF2_ITERS,
};
use serde::Deserialize;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat/vectors")
}

fn load_json<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = vectors_dir().join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing static KAT file {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("invalid JSON {}: {e}", path.display()))
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap_or_else(|e| panic!("invalid hex {hex:?}: {e}"))
}

fn cms_payload(description: &[u8], raw_key: &[u8]) -> Vec<u8> {
    let mut payload = u32::try_from(description.len())
        .expect("test description length fits u32")
        .to_be_bytes()
        .to_vec();
    payload.extend_from_slice(description);
    payload.extend_from_slice(raw_key);
    payload
}

#[derive(Debug, Deserialize)]
struct Provenance {
    origin_kind: String,
    source_url: String,
    source_revision: String,
    oracle: String,
    verification: String,
}

fn assert_static_metadata(schema_version: u32, provenance: &Provenance) {
    assert_eq!(schema_version, 1);
    assert!(!provenance.origin_kind.trim().is_empty());
    assert!(provenance.source_url.starts_with("https://"));
    assert!(!provenance.source_revision.trim().is_empty());
    assert!(!provenance.oracle.trim().is_empty());
    assert!(!provenance.verification.trim().is_empty());
}

#[derive(Debug, Deserialize)]
struct Pbkdf2File {
    schema_version: u32,
    provenance: Provenance,
    cases: Vec<Pbkdf2Case>,
}

#[derive(Debug, Deserialize)]
struct Pbkdf2Case {
    name: String,
    password_hex: String,
    salt_hex: String,
    iterations: u32,
    published_dk_len: usize,
    expected_derived_key_prefix_hex: String,
}

#[test]
fn pbkdf2_matches_rfc_6070_vectors() {
    let file: Pbkdf2File = load_json("pbkdf2.json");
    assert_static_metadata(file.schema_version, &file.provenance);
    assert!(!file.cases.is_empty());
    assert_eq!(DEFAULT_PBKDF2_ITERS, 1000);

    for case in &file.cases {
        let password = decode_hex(&case.password_hex);
        let salt = decode_hex(&case.salt_hex);
        let expected = decode_hex(&case.expected_derived_key_prefix_hex);
        let master = derive_master_key(&password, &salt, case.iterations);
        assert_eq!(
            expected.len(),
            case.published_dk_len.min(master.len()),
            "published PBKDF2 length {}",
            case.name
        );
        assert!(
            expected.len() <= master.len(),
            "published PBKDF2 output is longer than keydump output for {}",
            case.name
        );
        assert_eq!(
            &master[..expected.len()],
            expected.as_slice(),
            "PBKDF2 case {}",
            case.name
        );
    }
}

#[derive(Debug, Deserialize)]
struct DbKeyFile {
    schema_version: u32,
    provenance: Provenance,
    cases: Vec<DbKeyCase>,
}

#[derive(Debug, Deserialize)]
struct DbKeyCase {
    name: String,
    password_hex: String,
    salt_hex: String,
    iterations: u32,
    master_key_hex: String,
    iv_hex: String,
    ciphertext_hex: String,
    decrypted_private_blob_hex: String,
    db_key_hex: String,
    signing_key_hex: String,
}

#[test]
fn db_key_unwrap_matches_published_keychain_vector() {
    let file: DbKeyFile = load_json("db_key.json");
    assert_static_metadata(file.schema_version, &file.provenance);
    assert!(!file.cases.is_empty());

    for case in &file.cases {
        let password = decode_hex(&case.password_hex);
        let salt = decode_hex(&case.salt_hex);
        let expected_master = decode_hex(&case.master_key_hex);
        let master = derive_master_key(&password, &salt, case.iterations);
        assert_eq!(
            master.as_slice(),
            expected_master.as_slice(),
            "master key {}",
            case.name
        );

        let iv = decode_hex(&case.iv_hex);
        let ciphertext = decode_hex(&case.ciphertext_hex);
        let expected_private_blob = decode_hex(&case.decrypted_private_blob_hex);
        let expected_db_key = decode_hex(&case.db_key_hex);
        let expected_signing_key = decode_hex(&case.signing_key_hex);
        assert_eq!(ciphertext.len(), 48, "DBBlob ciphertext {}", case.name);

        let private_blob = des3_cbc_decrypt(&master[..], &iv, &ciphertext)
            .unwrap_or_else(|e| panic!("DBBlob plaintext {}: {e}", case.name));
        assert_eq!(
            private_blob.as_slice(),
            expected_private_blob.as_slice(),
            "DBBlob plaintext {}",
            case.name
        );
        assert_eq!(&private_blob[..24], expected_db_key.as_slice());
        assert_eq!(&private_blob[24..44], expected_signing_key.as_slice());

        let db_key = decrypt_db_key(&master[..], &iv, &ciphertext)
            .unwrap_or_else(|e| panic!("db_key case {}: {e}", case.name));
        assert_eq!(
            db_key.as_slice(),
            expected_db_key.as_slice(),
            "db_key case {}",
            case.name
        );
    }
}

#[derive(Debug, Deserialize)]
struct SsgpFile {
    schema_version: u32,
    provenance: Provenance,
    magic_cms_iv_hex: String,
    cases: Vec<SsgpCase>,
}

#[derive(Debug, Deserialize)]
struct SsgpCase {
    name: String,
    db_key_hex: String,
    record_iv_hex: String,
    encrypted_hex: String,
    description_hex: String,
    symmetric_key_hex: String,
    expected_stage1_len: usize,
}

#[test]
fn ssgp_symmetric_unwrap_matches_static_apple_layout_vector() {
    let file: SsgpFile = load_json("ssgp_sym.json");
    assert_static_metadata(file.schema_version, &file.provenance);
    assert!(!file.cases.is_empty());
    let magic_iv = decode_hex(&file.magic_cms_iv_hex);

    for case in &file.cases {
        let db_key = decode_hex(&case.db_key_hex);
        let record_iv = decode_hex(&case.record_iv_hex);
        let encrypted = decode_hex(&case.encrypted_hex);
        let description = decode_hex(&case.description_hex);
        let expected_key = decode_hex(&case.symmetric_key_hex);

        let stage1 = des3_cbc_decrypt(&db_key, &magic_iv, &encrypted)
            .unwrap_or_else(|e| panic!("SSGP outer decrypt {}: {e}", case.name));
        assert_eq!(
            stage1.len(),
            case.expected_stage1_len,
            "SSGP canonical stage-1 length {}",
            case.name
        );
        let mut stage2 = stage1.to_vec();
        stage2.reverse();
        assert_eq!(
            &stage2[..8],
            record_iv.as_slice(),
            "embedded IV {}",
            case.name
        );
        let payload = des3_cbc_decrypt(&db_key, &stage2[..8], &stage2[8..])
            .unwrap_or_else(|e| panic!("SSGP inner decrypt {}: {e}", case.name));
        assert_eq!(
            payload.as_slice(),
            cms_payload(&description, &expected_key),
            "SSGP CMS payload {}",
            case.name
        );

        let key = symmetric_keyblob_decrypt(&db_key, &record_iv, &encrypted)
            .unwrap_or_else(|e| panic!("SSGP case {}: {e}", case.name));
        assert_eq!(
            key.as_slice(),
            expected_key.as_slice(),
            "SSGP key {}",
            case.name
        );
    }
}

#[derive(Debug, Deserialize)]
struct PrivateKeyFile {
    schema_version: u32,
    provenance: Provenance,
    magic_cms_iv_hex: String,
    cases: Vec<PrivateKeyCase>,
}

#[derive(Debug, Deserialize)]
struct PrivateKeyCase {
    name: String,
    db_key_hex: String,
    record_iv_hex: String,
    encrypted_hex: String,
    description_hex: String,
    description_length_be_hex: String,
    private_key_der_hex: String,
    private_key_der_sha256_hex: String,
    public_key_spki_sha256_hex: String,
    expected_stage1_len: usize,
}

#[test]
fn private_key_unwrap_matches_static_apple_layout_vector() {
    let file: PrivateKeyFile = load_json("private_key.json");
    assert_static_metadata(file.schema_version, &file.provenance);
    assert!(!file.cases.is_empty());
    let magic_iv = decode_hex(&file.magic_cms_iv_hex);

    for case in &file.cases {
        let db_key = decode_hex(&case.db_key_hex);
        let record_iv = decode_hex(&case.record_iv_hex);
        let encrypted = decode_hex(&case.encrypted_hex);
        let expected_desc = decode_hex(&case.description_hex);
        let expected_desc_len = decode_hex(&case.description_length_be_hex);
        let expected_der = decode_hex(&case.private_key_der_hex);
        assert_eq!(
            expected_desc_len,
            u32::try_from(expected_desc.len()).unwrap().to_be_bytes(),
            "description length {}",
            case.name
        );

        let stage1 = des3_cbc_decrypt(&db_key, &magic_iv, &encrypted)
            .unwrap_or_else(|e| panic!("private-key outer decrypt {}: {e}", case.name));
        assert_eq!(
            stage1.len(),
            case.expected_stage1_len,
            "private-key stage-1 length {}",
            case.name
        );
        let mut stage2 = stage1.to_vec();
        stage2.reverse();
        assert_eq!(
            &stage2[..8],
            record_iv.as_slice(),
            "embedded IV {}",
            case.name
        );
        let payload = des3_cbc_decrypt(&db_key, &stage2[..8], &stage2[8..])
            .unwrap_or_else(|e| panic!("private-key inner decrypt {}: {e}", case.name));
        assert_eq!(
            payload.as_slice(),
            cms_payload(&expected_desc, &expected_der),
            "private-key CMS payload {}",
            case.name
        );

        let (desc, der) = private_key_decrypt(&db_key, &record_iv, &encrypted)
            .unwrap_or_else(|e| panic!("private-key case {}: {e}", case.name));
        assert_eq!(desc, expected_desc, "description {}", case.name);
        assert_eq!(
            der.as_slice(),
            expected_der.as_slice(),
            "DER bytes {}",
            case.name
        );

        #[cfg(target_os = "macos")]
        {
            use openssl::hash::{hash, MessageDigest};
            use openssl::pkey::PKey;
            use openssl::rsa::Rsa;

            let expected_der_sha = decode_hex(&case.private_key_der_sha256_hex);
            let digest = hash(MessageDigest::sha256(), der.as_slice()).unwrap();
            assert_eq!(
                digest.as_ref(),
                expected_der_sha.as_slice(),
                "DER SHA-256 {}",
                case.name
            );

            let pkey = PKey::private_key_from_der(&der)
                .or_else(|_| Rsa::private_key_from_der(&der).and_then(PKey::from_rsa))
                .unwrap_or_else(|e| panic!("invalid private DER {}: {e}", case.name));
            let spki = pkey.public_key_to_der().unwrap();
            let expected_spki_sha = decode_hex(&case.public_key_spki_sha256_hex);
            let spki_digest = hash(MessageDigest::sha256(), &spki).unwrap();
            assert_eq!(
                spki_digest.as_ref(),
                expected_spki_sha.as_slice(),
                "SPKI SHA-256 {}",
                case.name
            );
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                &case.private_key_der_sha256_hex,
                &case.public_key_spki_sha256_hex,
            );
        }
    }
}
