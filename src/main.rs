mod cli;
mod crypto;
mod error;
mod export;
mod keychain;
mod unlock;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use clap::Parser;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{Cli, Command, CommonArgs};
use crate::error::{KdError, Result};
use crate::export::{
    decrypt_all_keys, default_keychain_path, export_all, filter_by_name, match_identities,
    validate_output_dir, OutputFormat,
};
use crate::keychain::KeychainFile;
use crate::unlock::{try_master_key_hex, try_password, unlock_from_securityd, Unlocked};

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        // hint on wrong credential + 26.x
        if matches!(e, KdError::WrongCredential) {
            eprintln!(
                "hint: password/master-key rejected. On macOS 26.x (blobVersion 0x200) \
                 offline --password often fails due to Secure Enclave pre-processing. \
                 Try: sudo kd export --from-securityd ...  (needs root; blocked by default SIP \
                 Debugging Restrictions)  or  kd export --master-key <hex> ..."
            );
        }
        if matches!(e, KdError::Securityd(_)) {
            eprintln!(
                "hint: --from-securityd requires root and readable securityd memory. \
                 Default SIP Debugging Restrictions usually block this. \
                 Alternatives: --master-key, or --password on legacy keychains."
            );
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::List(mut a) => {
            resolve_common_secret_files(&mut a.common)?;
            cmd_list(a.common)
        }
        Command::Export(mut a) => {
            resolve_common_secret_files(&mut a.common)?;
            if let Some(path) = a.p12_pass_file.take() {
                a.p12_pass = Some(read_secret_file(&path, "PKCS#12 password")?);
            }
            cmd_export(a)
        }
    }
}

fn read_secret_file(path: &Path, label: &str) -> Result<String> {
    let bytes = std::fs::read(path).map_err(|e| {
        KdError::Msg(format!(
            "failed to read {label} file {}: {e}",
            path.display()
        ))
    })?;
    let mut value = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(KdError::Msg(format!(
                "{label} file must contain UTF-8 text: {}",
                path.display()
            )));
        }
    };
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
    Ok(value)
}

fn resolve_common_secret_files(common: &mut CommonArgs) -> Result<()> {
    if let Some(path) = common.password_file.take() {
        common.password = Some(read_secret_file(&path, "Keychain password")?);
    }
    if let Some(path) = common.master_key_file.take() {
        common.master_key = Some(read_secret_file(&path, "master key")?);
    }
    Ok(())
}

fn resolve_keychain(path: &Option<PathBuf>) -> PathBuf {
    path.clone().unwrap_or_else(default_keychain_path)
}

fn unlock(common: &CommonArgs, kc: &KeychainFile) -> Result<Option<Unlocked>> {
    let modes = [
        common.password.is_some(),
        common.master_key.is_some(),
        common.from_securityd,
    ];
    let n = modes.iter().filter(|x| **x).count();
    if n == 0 {
        return Ok(None);
    }
    if n > 1 {
        return Err(KdError::Msg(
            "use only one of --password / --master-key / --from-securityd".into(),
        ));
    }

    if let Some(ref p) = common.password {
        if common.verbose {
            eprintln!(
                "unlock: password (PBKDF2 iters={}), blobVersion={:#x}",
                common.pbkdf2_iters,
                kc.blob_version()
            );
        }
        return Ok(Some(try_password(kc, p, common.pbkdf2_iters)?));
    }
    if let Some(ref k) = common.master_key {
        if common.verbose {
            eprintln!("unlock: master-key");
        }
        return Ok(Some(try_master_key_hex(kc, k)?));
    }
    if common.from_securityd {
        if common.verbose {
            eprintln!(
                "unlock: securityd scan (root + SIP Debugging Restrictions must allow task_for_pid)"
            );
        }
        return Ok(Some(unlock_from_securityd(kc)?));
    }
    Ok(None)
}

fn cmd_list(common: CommonArgs) -> Result<()> {
    let path = resolve_keychain(&common.keychain);
    if common.verbose {
        eprintln!("keychain: {}", path.display());
    }
    let kc = KeychainFile::open(&path)?;
    eprintln!(
        "opened {} bytes, blobVersion={:#x}",
        kc.file_len(),
        kc.blob_version()
    );

    let certs = kc.certificates()?;
    let pks = kc.private_keys()?;
    println!("certificates: {}", certs.len());
    for (i, c) in certs.iter().enumerate() {
        println!(
            "  cert[{}] name={:?} der_len={}",
            i + 1,
            c.print_name,
            c.der.len()
        );
    }
    println!("private_keys: {}", pks.len());
    for (i, k) in pks.iter().enumerate() {
        println!(
            "  key[{}] name={:?} bits={} extractable={} enc_len={}",
            i + 1,
            k.print_name,
            k.key_size_bits,
            k.extractable,
            k.encrypted.len()
        );
    }

    if let Some(u) = unlock(&common, &kc)? {
        eprintln!("unlocked via {} (db_key ok)", u.method());
        if common.print_secrets {
            if let Some(m) = u.master_key() {
                eprintln!("master_key={}", hex::encode(m));
            }
            eprintln!("db_key={}", hex::encode(u.database_key()));
        }
        let mut ok = 0;
        for k in &pks {
            if u.decrypt_private_key(k).is_ok() {
                ok += 1;
            }
        }
        eprintln!("private keys decryptable: {ok}/{}", pks.len());
    } else {
        eprintln!("(no credentials: metadata only; pass -p / -k / --from-securityd to decrypt)");
    }
    Ok(())
}

fn cmd_export(mut args: cli::ExportArgs) -> Result<()> {
    // Fail before opening or decrypting the keychain if results could be mixed
    // with an earlier export.
    validate_output_dir(&args.output)?;
    let path = resolve_keychain(&args.common.keychain);
    let kc = KeychainFile::open(&path)?;
    if args.common.verbose {
        eprintln!(
            "keychain: {} ({} bytes, blobVersion={:#x})",
            path.display(),
            kc.file_len(),
            kc.blob_version()
        );
    }

    let unlocked = unlock(&args.common, &kc)?.ok_or_else(|| {
        KdError::Msg("export requires unlock: --password, --master-key, or --from-securityd".into())
    })?;
    eprintln!("unlocked via {}", unlocked.method());
    if args.common.print_secrets {
        if let Some(m) = unlocked.master_key() {
            eprintln!("master_key={}", hex::encode(m));
        }
        eprintln!("db_key={}", hex::encode(unlocked.database_key()));
    }

    let pks = kc.private_keys()?;
    let mut certs: Vec<_> = kc.certificates()?.into_iter().map(Rc::new).collect();
    let mut keys = decrypt_all_keys(&unlocked, &pks, args.include_exportable)?;
    let mut identities = match_identities(&keys, &certs);
    if let Some(filter) = args.name.as_deref() {
        filter_by_name(&mut keys, &mut certs, &mut identities, filter);
    }
    let format = args.format;
    let p12_pass = resolve_p12_password(args.p12_pass.take(), format)?;

    let stats = export_all(&args.output, &keys, &certs, &identities, format, &p12_pass)?;

    println!("export complete → {}", args.output.display());
    println!(
        "  key files: {}  cert files: {}  identity files: {}  matched identities: {}",
        stats.key_files_written,
        stats.cert_files_written,
        stats.identity_files_written,
        stats.identities_written
    );
    for id in &identities {
        let tag = if id.key.extractable == 0 {
            "non-exportable"
        } else {
            "exportable"
        };
        println!(
            "  identity: cert={:?} key={:?} ({tag})",
            id.cert.print_name, id.key.print_name
        );
    }
    Ok(())
}

fn resolve_p12_password(
    explicit: Option<String>,
    format: OutputFormat,
) -> Result<Zeroizing<String>> {
    if !format.writes_p12() {
        return Ok(Zeroizing::new(explicit.unwrap_or_default()));
    }
    if let Some(password) = explicit {
        return Ok(Zeroizing::new(password));
    }

    let password = Zeroizing::new(
        rpassword::prompt_password("PKCS#12 password: ")
            .map_err(|e| KdError::Msg(format!("failed to read PKCS#12 password: {e}")))?,
    );
    if password.is_empty() {
        return Err(KdError::Msg("PKCS#12 password must not be empty".into()));
    }
    let confirmation = Zeroizing::new(
        rpassword::prompt_password("Confirm PKCS#12 password: ")
            .map_err(|e| KdError::Msg(format!("failed to confirm PKCS#12 password: {e}")))?,
    );
    if password != confirmation {
        return Err(KdError::Msg("PKCS#12 passwords do not match".into()));
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_SECRET_FILE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn secret_file_removes_trailing_line_endings() {
        let id = NEXT_SECRET_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("kd-secret-{}-{id}", std::process::id()));
        std::fs::write(&path, b"secret\r\n").unwrap();

        let result = read_secret_file(&path, "test secret");
        let _ = std::fs::remove_file(&path);

        assert_eq!(result.unwrap(), "secret");
    }

    #[test]
    fn secret_file_rejects_non_utf8_data() {
        let id = NEXT_SECRET_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("kd-secret-{}-{id}", std::process::id()));
        std::fs::write(&path, [0xff]).unwrap();

        let result = read_secret_file(&path, "test secret");
        let _ = std::fs::remove_file(&path);

        assert!(result.is_err());
    }

    #[test]
    fn explicit_p12_password_is_preserved() {
        let password = resolve_p12_password(Some("legacy".into()), OutputFormat::P12).unwrap();
        assert_eq!(password.as_str(), "legacy");
    }

    #[test]
    fn non_p12_export_does_not_require_password() {
        let password = resolve_p12_password(None, OutputFormat::Pem).unwrap();
        assert!(password.is_empty());
    }
}
