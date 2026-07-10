mod cli;
mod crypto;
mod error;
mod export;
mod keychain;
mod unlock;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, CommonArgs};
use crate::error::{KdError, Result};
use crate::export::{
    decrypt_all_keys, default_keychain_path, export_all, match_identities, OutputFormat,
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
        Command::List(a) => cmd_list(a.common),
        Command::Export(a) => cmd_export(a),
    }
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
        kc.data.len(),
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
        eprintln!("unlocked via {} (db_key ok)", u.method);
        if common.print_secrets {
            if let Some(ref m) = u.master_key {
                eprintln!("master_key={}", hex::encode(m));
            }
            eprintln!("db_key={}", hex::encode(&u.db_key));
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

fn cmd_export(args: cli::ExportArgs) -> Result<()> {
    let path = resolve_keychain(&args.common.keychain);
    let kc = KeychainFile::open(&path)?;
    if args.common.verbose {
        eprintln!(
            "keychain: {} ({} bytes, blobVersion={:#x})",
            path.display(),
            kc.data.len(),
            kc.blob_version()
        );
    }

    let unlocked = unlock(&args.common, &kc)?.ok_or_else(|| {
        KdError::Msg("export requires unlock: --password, --master-key, or --from-securityd".into())
    })?;
    eprintln!("unlocked via {}", unlocked.method);
    if args.common.print_secrets {
        if let Some(ref m) = unlocked.master_key {
            eprintln!("master_key={}", hex::encode(m));
        }
        eprintln!("db_key={}", hex::encode(&unlocked.db_key));
    }

    let pks = kc.private_keys()?;
    let certs = kc.certificates()?;
    let keys = decrypt_all_keys(
        &unlocked,
        &pks,
        args.name.as_deref(),
        args.include_exportable,
    )?;
    let identities = match_identities(&keys, &certs);
    let format = OutputFormat::parse(&args.format)?;

    let stats = export_all(
        &args.output,
        &keys,
        &certs,
        &identities,
        format,
        &args.p12_pass,
    )?;

    println!("export complete → {}", args.output.display());
    println!(
        "  keys: {}  certs: {}  matched identities: {}",
        stats.keys_written, stats.certs_written, stats.identities_written
    );
    for id in &identities {
        let tag = if id.key.extractable == 0 {
            "non-exportable"
        } else {
            "exportable"
        };
        println!(
            "  identity: cert={:?} key={:?} ({tag})",
            id.cert_name, id.key.print_name
        );
    }
    Ok(())
}
