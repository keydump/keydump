//! Write decrypted keys/certs and match identities.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use clap::ValueEnum;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use zeroize::Zeroizing;

use crate::error::{KdError, Result};
use crate::keychain::{PrivateKeyRecord, X509Record};
use crate::unlock::Unlocked;

/// Reject output paths that could mix a new export with existing data.
///
/// A missing path or an existing empty directory is accepted. Symlinks,
/// non-directories, and non-empty directories are rejected.
pub fn validate_output_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(KdError::Msg(format!(
                    "output path must not be a symlink: {}",
                    path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(KdError::Msg(format!(
                    "output path exists and is not a directory: {}",
                    path.display()
                )));
            }
            if fs::read_dir(path)?.next().transpose()?.is_some() {
                return Err(KdError::Msg(format!(
                    "output directory must be empty: {}",
                    path.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Pem,
    Der,
    #[value(alias = "pkcs12")]
    P12,
    All,
}

impl OutputFormat {
    pub fn writes_p12(self) -> bool {
        matches!(self, Self::P12 | Self::All)
    }
}

pub struct DecryptedKey {
    pub print_name: String,
    pub extractable: u32,
    pub der: Zeroizing<Vec<u8>>,
}

pub struct MatchedIdentity {
    pub key: Rc<DecryptedKey>,
    pub cert: Rc<X509Record>,
}

pub fn decrypt_all_keys(
    unlocked: &Unlocked,
    records: &[PrivateKeyRecord],
    include_exportable: bool,
) -> Result<Vec<Rc<DecryptedKey>>> {
    let mut out = Vec::new();
    for rec in records {
        // Default: only Extractable=0 (SecItem non-exportable software keys).
        if !include_exportable && rec.extractable != 0 {
            continue;
        }
        let (_descriptive_data, der) = unlocked.decrypt_private_key(rec).map_err(|e| {
            KdError::Msg(format!(
                "failed to decrypt private key {:?}: {e}",
                rec.print_name
            ))
        })?;
        if PKey::private_key_from_der(&der).is_err() && Rsa::private_key_from_der(&der).is_err() {
            return Err(KdError::Crypto(format!(
                "decrypted blob for {:?} is not a recognizable private key ({} bytes)",
                rec.print_name,
                der.len()
            )));
        }
        out.push(Rc::new(DecryptedKey {
            print_name: rec.print_name.clone(),
            extractable: rec.extractable,
            der,
        }));
    }
    Ok(out)
}

fn name_matches(name: &str, filter: &str) -> bool {
    name.to_lowercase().contains(&filter.to_lowercase())
}

pub fn filter_by_name(
    keys: &mut Vec<Rc<DecryptedKey>>,
    certs: &mut Vec<Rc<X509Record>>,
    identities: &mut Vec<MatchedIdentity>,
    filter: &str,
) {
    identities.retain(|identity| {
        name_matches(&identity.key.print_name, filter)
            || name_matches(&identity.cert.print_name, filter)
    });
    keys.retain(|key| name_matches(&key.print_name, filter));
    certs.retain(|cert| name_matches(&cert.print_name, filter));
}

fn public_key_der_from_private(der: &[u8]) -> Option<Vec<u8>> {
    let pkey = PKey::private_key_from_der(der)
        .or_else(|_| Rsa::private_key_from_der(der).and_then(PKey::from_rsa))
        .ok()?;
    pkey.public_key_to_der().ok()
}

fn public_key_der_from_certificate(der: &[u8]) -> Option<Vec<u8>> {
    let cert = X509::from_der(der).ok()?;
    let pkey = cert.public_key().ok()?;
    pkey.public_key_to_der().ok()
}

pub fn match_identities(
    keys: &[Rc<DecryptedKey>],
    certs: &[Rc<X509Record>],
) -> Vec<MatchedIdentity> {
    let cert_public_keys: Vec<_> = certs
        .iter()
        .map(|cert| public_key_der_from_certificate(&cert.der))
        .collect();
    let mut out = Vec::new();
    for key in keys {
        let Some(key_public) = public_key_der_from_private(&key.der) else {
            continue;
        };
        for (cert, cert_public) in certs.iter().zip(&cert_public_keys) {
            if cert_public.as_ref() == Some(&key_public) {
                out.push(MatchedIdentity {
                    key: Rc::clone(key),
                    cert: Rc::clone(cert),
                });
            }
        }
    }
    out
}

fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_matches('_').to_string();
    if s.is_empty() {
        "item".into()
    } else {
        s.chars().take(80).collect()
    }
}

fn ensure_dir(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(KdError::Msg(format!(
                    "output directory is not a real directory: {}",
                    p.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(p)?;
        }
        Err(e) => return Err(e.into()),
    }
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}

pub struct ExportStats {
    pub key_files_written: usize,
    pub cert_files_written: usize,
    pub identity_files_written: usize,
    pub identities_written: usize,
}

pub fn export_all(
    out_dir: &Path,
    keys: &[Rc<DecryptedKey>],
    certs: &[Rc<X509Record>],
    identities: &[MatchedIdentity],
    format: OutputFormat,
    p12_pass: &str,
) -> Result<ExportStats> {
    // Re-check at the write seam so library callers cannot bypass the CLI guard.
    validate_output_dir(out_dir)?;
    ensure_dir(out_dir)?;
    let keys_dir = out_dir.join("keys");
    let certs_dir = out_dir.join("certs");
    let id_dir = out_dir.join("identities");
    ensure_dir(&keys_dir)?;
    ensure_dir(&certs_dir)?;
    ensure_dir(&id_dir)?;

    let mut stats = ExportStats {
        key_files_written: 0,
        cert_files_written: 0,
        identity_files_written: 0,
        identities_written: 0,
    };

    let write_der = matches!(format, OutputFormat::Der | OutputFormat::All);
    let write_pem = matches!(format, OutputFormat::Pem | OutputFormat::All);
    let write_p12 = matches!(format, OutputFormat::P12 | OutputFormat::All);

    for (i, key) in keys.iter().enumerate() {
        let tag = if key.extractable == 0 {
            "nonexportable"
        } else {
            "exportable"
        };
        let base = format!("{:02}_{}_{}", i + 1, tag, sanitize(&key.print_name));
        if write_der {
            write_private(&keys_dir.join(format!("{base}.der")), &key.der)?;
            stats.key_files_written += 1;
        }
        if write_pem {
            let pem = key_der_to_pem(&key.der)?;
            write_private(&keys_dir.join(format!("{base}.pem")), &pem)?;
            stats.key_files_written += 1;
        }
    }

    for (i, cert) in certs.iter().enumerate() {
        let base = format!("{:02}_{}", i + 1, sanitize(&cert.print_name));
        if write_der {
            write_private(&certs_dir.join(format!("{base}.der")), &cert.der)?;
            stats.cert_files_written += 1;
        }
        if write_pem {
            let x = X509::from_der(&cert.der)?;
            let pem = x.to_pem()?;
            write_private(&certs_dir.join(format!("{base}.pem")), &pem)?;
            stats.cert_files_written += 1;
        }
    }

    for (i, id) in identities.iter().enumerate() {
        let base = format!("{:02}_{}", i + 1, sanitize(&id.cert.print_name));
        let folder = id_dir.join(&base);
        ensure_dir(&folder)?;

        if write_der {
            write_private(&folder.join("key.der"), &id.key.der)?;
            write_private(&folder.join("cert.der"), &id.cert.der)?;
            stats.identity_files_written += 2;
        }
        if write_pem {
            let pem = key_der_to_pem(&id.key.der)?;
            write_private(&folder.join("key.pem"), &pem)?;
            let x = X509::from_der(&id.cert.der)?;
            write_private(&folder.join("cert.pem"), &x.to_pem()?)?;
            stats.identity_files_written += 2;
        }
        if write_p12 {
            let p12_path = folder.join("identity.p12");
            write_pkcs12(&id.key.der, &id.cert.der, p12_pass, &p12_path)?;
            stats.identity_files_written += 1;
        }
        stats.identities_written += 1;
    }

    Ok(stats)
}

fn key_der_to_pem(der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(rsa) = Rsa::private_key_from_der(der) {
        return Ok(Zeroizing::new(rsa.private_key_to_pem()?));
    }
    let pkey = PKey::private_key_from_der(der)
        .map_err(|e| KdError::Crypto(format!("private key DER parse failed: {e}")))?;
    Ok(Zeroizing::new(pkey.private_key_to_pem_pkcs8()?))
}

fn write_pkcs12(key_der: &[u8], cert_der: &[u8], pass: &str, path: &Path) -> Result<()> {
    let pkey = PKey::private_key_from_der(key_der)
        .or_else(|_| Rsa::private_key_from_der(key_der).and_then(PKey::from_rsa))
        .map_err(|e| KdError::Msg(format!("p12 key parse: {e}")))?;
    let cert =
        X509::from_der(cert_der).map_err(|e| KdError::Msg(format!("p12 cert parse: {e}")))?;

    // openssl crate Pkcs12 builder
    let mut builder = openssl::pkcs12::Pkcs12::builder();
    builder.name("keydump");
    builder.pkey(&pkey);
    builder.cert(&cert);
    let p12 = builder
        .build2(pass)
        .map_err(|e| KdError::Msg(format!("p12 build: {e}")))?;
    let der = Zeroizing::new(
        p12.to_der()
            .map_err(|e| KdError::Msg(format!("p12 der: {e}")))?,
    );
    write_private(path, &der)
}

pub fn default_keychain_path() -> PathBuf {
    dirs_next_home()
        .map(|h| h.join("Library/Keychains/login.keychain-db"))
        .unwrap_or_else(|| PathBuf::from("login.keychain-db"))
}

fn dirs_next_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509NameBuilder, X509};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("kd-export-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn output_dir_accepts_missing_or_empty_directory() {
        let root = TestDir::new();
        let missing = root.0.join("missing");
        let empty = root.0.join("empty");
        fs::create_dir(&empty).unwrap();

        assert!(validate_output_dir(&missing).is_ok());
        assert!(validate_output_dir(&empty).is_ok());
    }

    #[test]
    fn output_dir_rejects_non_empty_directory_and_file() {
        let root = TestDir::new();
        let non_empty = root.0.join("non-empty");
        let file = root.0.join("file");
        fs::create_dir(&non_empty).unwrap();
        fs::write(non_empty.join("existing"), b"data").unwrap();
        fs::write(&file, b"data").unwrap();

        assert!(validate_output_dir(&non_empty).is_err());
        assert!(validate_output_dir(&file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn output_dir_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new();
        let target = root.0.join("target");
        let link = root.0.join("link");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert!(validate_output_dir(&link).is_err());
    }

    #[test]
    fn private_write_creates_file_with_restricted_permissions() {
        let root = TestDir::new();
        let file = root.0.join("secret");

        write_private(&file, b"secret").unwrap();

        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn private_write_never_overwrites_existing_file() {
        let root = TestDir::new();
        let file = root.0.join("secret");
        fs::write(&file, b"original").unwrap();

        assert!(write_private(&file, b"replacement").is_err());
        assert_eq!(fs::read(&file).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn private_write_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new();
        let target = root.0.join("target");
        let link = root.0.join("link");
        fs::write(&target, b"original").unwrap();
        symlink(&target, &link).unwrap();

        assert!(write_private(&link, b"replacement").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn ensure_dir_enforces_restricted_permissions() {
        let root = TestDir::new();
        let dir = root.0.join("output");

        ensure_dir(&dir).unwrap();

        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    fn test_key(name: &str) -> Rc<DecryptedKey> {
        Rc::new(DecryptedKey {
            print_name: name.into(),
            extractable: 0,
            der: Zeroizing::new(vec![1]),
        })
    }

    #[test]
    fn name_filter_applies_to_keys_certs_and_either_identity_side() {
        let mut keys = vec![test_key("client key"), test_key("other key")];
        let mut certs = vec![
            Rc::new(X509Record {
                print_name: "CLIENT CERT".into(),
                der: vec![2],
            }),
            Rc::new(X509Record {
                print_name: "other cert".into(),
                der: vec![3],
            }),
        ];
        let mut identities = vec![
            MatchedIdentity {
                key: test_key("unrelated key label"),
                cert: Rc::clone(&certs[0]),
            },
            MatchedIdentity {
                key: test_key("other key"),
                cert: Rc::clone(&certs[1]),
            },
        ];

        filter_by_name(&mut keys, &mut certs, &mut identities, "client");

        assert_eq!(keys.len(), 1);
        assert_eq!(certs.len(), 1);
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].cert.print_name, "CLIENT CERT");
    }

    fn certificate_for_key(key: &PKey<Private>) -> Vec<u8> {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "keydump test").unwrap();
        let name = name.build();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(key).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        builder.sign(key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    #[test]
    fn identity_matching_supports_ec_and_all_matching_certificates() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let decrypted = Rc::new(DecryptedKey {
            print_name: "EC key".into(),
            extractable: 0,
            der: Zeroizing::new(key.private_key_to_der().unwrap()),
        });
        let cert_der = certificate_for_key(&key);
        let certs = vec![
            Rc::new(X509Record {
                print_name: "first".into(),
                der: cert_der.clone(),
            }),
            Rc::new(X509Record {
                print_name: "renewed".into(),
                der: cert_der,
            }),
        ];

        let identities = match_identities(&[Rc::clone(&decrypted)], &certs);

        assert_eq!(identities.len(), 2);
        assert!(identities
            .iter()
            .all(|identity| Rc::ptr_eq(&identity.key, &decrypted)));
    }

    #[test]
    fn p12_only_stats_count_only_files_actually_written() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let decrypted = Rc::new(DecryptedKey {
            print_name: "EC key".into(),
            extractable: 0,
            der: Zeroizing::new(key.private_key_to_der().unwrap()),
        });
        let cert = Rc::new(X509Record {
            print_name: "EC cert".into(),
            der: certificate_for_key(&key),
        });
        let keys = vec![Rc::clone(&decrypted)];
        let certs = vec![Rc::clone(&cert)];
        let identities = vec![MatchedIdentity {
            key: decrypted,
            cert,
        }];
        let root = TestDir::new();

        let stats = export_all(
            &root.0,
            &keys,
            &certs,
            &identities,
            OutputFormat::P12,
            "test password",
        )
        .unwrap();

        assert_eq!(stats.key_files_written, 0);
        assert_eq!(stats.cert_files_written, 0);
        assert_eq!(stats.identity_files_written, 1);
        assert_eq!(stats.identities_written, 1);
    }
}
