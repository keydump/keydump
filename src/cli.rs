use std::path::PathBuf;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use crate::export::OutputFormat;

/// macOS Keychain private-key dump tool (authorized security assessment only).
///
/// Unlock paths:
///   --password       Classic PBKDF2 offline unlock (works on legacy keychains;
///                    often FAILS on macOS 26.x blobVersion=0x200 where the password
///                    is pre-processed by the Secure Enclave before PBKDF2).
///   --master-key     24-byte master key (hex), e.g. from memory forensics.
///   --from-securityd Scan securityd heap for the master key while the keychain is
///                    unlocked. Requires root. Strongly depends on SIP: default SIP
///                    Debugging Restrictions block `task_for_pid` / memory read of securityd
///                    even as root. Does NOT require disabling SIP for file parsing
///                    itself — only for this memory-scan path.
#[derive(Parser)]
#[command(
    name = "kd",
    version,
    about = "Key dump: export private keys from macOS login.keychain-db (incl. non-exportable)",
    long_about = LONG_ABOUT
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

const LONG_ABOUT: &str = "\
kd (keydump) — export private keys and certificates from macOS file-based keychains \
(login.keychain-db), including items marked non-exportable / NeverExtractable.

IMPORTANT — SIP and unlock paths:
  • File parse + crypto unwrap do not require SIP changes.
  • --password works offline on classic keychains (blobVersion 0x100). On many \
macOS 26.4+ systems the login keychain is re-wrapped (blobVersion 0x200) with SEP \
involvement; password offline unlock then fails even if `security unlock-keychain` works.
  • --from-securityd needs root and the ability to read securityd memory. Default SIP \
Debugging Restrictions usually prevent this. Use only on authorized hosts where policy \
allows it, or supply --master-key obtained by other authorized means.

For authorized red-team / security assessment only. Treat outputs as highly sensitive.
";

#[derive(Subcommand)]
pub enum Command {
    /// List private keys and certificates (metadata; decrypt if credentials given)
    List(ListArgs),
    /// Decrypt and export private keys / certs / matched PKCS#12 identities
    Export(ExportArgs),
}

#[derive(Parser)]
pub struct ListArgs {
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser)]
pub struct ExportArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Output directory (files created mode 0600 / dirs 0700)
    #[arg(short = 'o', long, default_value = "./keys-dumped")]
    pub output: PathBuf,

    /// Output format: pem | der | p12 | all
    #[arg(long, default_value = "all")]
    pub format: OutputFormat,

    /// Password for PKCS#12 export
    #[arg(long, env = "KD_P12_PASS", hide_env_values = true)]
    pub p12_pass: Option<String>,

    /// Read the PKCS#12 password from a UTF-8 file (trailing newline removed)
    #[arg(long, value_name = "PATH", conflicts_with = "p12_pass")]
    pub p12_pass_file: Option<PathBuf>,

    /// Also export keys that are already SecItem-exportable (default: non-exportable only)
    #[arg(long)]
    pub include_exportable: bool,

    /// Filter by private key / cert print name (substring, case-insensitive)
    #[arg(long)]
    pub name: Option<String>,
}

impl Drop for ExportArgs {
    fn drop(&mut self) {
        if let Some(password) = &mut self.p12_pass {
            password.zeroize();
        }
    }
}

#[derive(Parser)]
pub struct CommonArgs {
    /// Path to keychain file (default: ~/Library/Keychains/login.keychain-db)
    #[arg(short = 'f', long = "keychain")]
    pub keychain: Option<PathBuf>,

    /// Keychain password (classic PBKDF2 path; may fail on macOS 26.x SEP-wrapped keychains)
    #[arg(
        short = 'p',
        long,
        env = "KD_PASSWORD",
        hide_env_values = true,
        conflicts_with_all = ["master_key", "master_key_file", "from_securityd"]
    )]
    pub password: Option<String>,

    /// Read the Keychain password from a UTF-8 file (trailing newline removed)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["password", "master_key", "master_key_file", "from_securityd"]
    )]
    pub password_file: Option<PathBuf>,

    /// 24-byte master key as hex (48 hex chars)
    #[arg(
        short = 'k',
        long = "master-key",
        env = "KD_MASTER_KEY",
        hide_env_values = true,
        conflicts_with_all = ["password", "password_file", "from_securityd"]
    )]
    pub master_key: Option<String>,

    /// Read the master key hex from a UTF-8 file (trailing newline removed)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["password", "password_file", "master_key", "from_securityd"]
    )]
    pub master_key_file: Option<PathBuf>,

    /// Recover master key by scanning securityd memory (macOS, root, SIP-sensitive)
    #[arg(
        long = "from-securityd",
        conflicts_with_all = ["password", "password_file", "master_key", "master_key_file"]
    )]
    pub from_securityd: bool,

    /// PBKDF2 iteration count for --password (classic keychains use 1000)
    #[arg(
        long,
        default_value_t = crate::crypto::DEFAULT_PBKDF2_ITERS,
        value_parser = clap::value_parser!(u32).range(1..=10_000_000)
    )]
    pub pbkdf2_iters: u32,

    /// Verbose progress (never prints key material unless --print-secrets)
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Allow printing master/db key material to stderr (dangerous)
    #[arg(long, hide = true)]
    pub print_secrets: bool,
}

impl Drop for CommonArgs {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.zeroize();
        }
        if let Some(master_key) = &mut self.master_key {
            master_key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{Arg, Command, CommandFactory, Parser};

    use super::Cli;

    fn find_arg<'a>(command: &'a Command, id: &str) -> Option<&'a Arg> {
        command
            .get_arguments()
            .find(|arg| arg.get_id() == id)
            .or_else(|| {
                command
                    .get_subcommands()
                    .find_map(|subcommand| find_arg(subcommand, id))
            })
    }

    #[test]
    fn secret_environment_values_are_hidden_from_help() {
        let command = Cli::command();

        for id in ["password", "master_key", "p12_pass"] {
            let arg = find_arg(&command, id).expect("secret argument exists");
            assert!(arg.is_hide_env_values_set(), "{id} must hide its env value");
        }
    }

    #[test]
    fn unlock_sources_are_mutually_exclusive() {
        let parsed = Cli::try_parse_from([
            "kd",
            "list",
            "--password",
            "secret",
            "--master-key",
            "00112233445566778899aabbccddeeff0011223344556677",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn format_is_validated_by_clap() {
        assert!(Cli::try_parse_from(["kd", "export", "--format", "invalid"]).is_err());
        assert!(Cli::try_parse_from(["kd", "export", "--format", "pkcs12"]).is_ok());
    }

    #[test]
    fn pbkdf2_iterations_must_be_in_safe_range() {
        assert!(Cli::try_parse_from(["kd", "list", "--pbkdf2-iters", "0"]).is_err());
        assert!(Cli::try_parse_from(["kd", "list", "--pbkdf2-iters", "10000001"]).is_err());
    }
}
