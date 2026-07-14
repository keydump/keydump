# keydump (`kd`)

macOS **file-based** Keychain private-key dump CLI for **authorized** security assessment / red-team exercises.

Exports private keys (including SecItem **non-exportable** / `NeverExtractable` software keys) and certificates from `login.keychain-db`, and matches them into PKCS#12 identities.

> Not for iCloud / Data Protection `keychain-2.db`, and not for Secure Enclave–resident keys (no private key material on disk).

## Install

### Download (recommended)

Download the universal binary from [GitHub Releases](https://github.com/keydump/keydump/releases):

```bash
curl -L -o kd.zip https://github.com/keydump/keydump/releases/latest/download/kd-darwin-universal.zip
unzip kd.zip
chmod +x kd
sudo mv kd /usr/local/bin/
```

### Build from source

Requires Rust 1.85+.

```bash
git clone https://github.com/keydump/keydump.git
cd keydump
cargo install --path .
```

## Commands

```bash
# Metadata only
kd list -f ~/Library/Keychains/login.keychain-db

# Classic offline password (legacy keychains). A file/FD avoids argv history.
kd export -f login.keychain-db --password-file /secure/path/keychain.pass -o ./out

# Known 24-byte master key (hex), read from an already-open file descriptor
kd export -f login.keychain-db --master-key-file /dev/fd/3 -o ./out 3<master-key.hex

# Live host: recover master key from securityd (macOS, see SIP notes)
sudo kd export -f ~/Library/Keychains/login.keychain-db --from-securityd -o ./out

# Default: non-exportable keys only. Full dump + filter + P12:
kd export --master-key-file /dev/fd/3 -o ./out --include-exportable --name 'NAC' \
  --format p12 --p12-pass-file /dev/fd/4 3<master-key.hex 4<p12.pass
```

Default keychain path: `~/Library/Keychains/login.keychain-db`.

## Unlock paths & SIP

| Path | Needs | Notes |
| ------ | -------- | -------- |
| `--password` | Keychain file + password | Pure offline crypto. Works on **classic** keychains (`blobVersion` 0x100). On many **macOS 26.4+** systems the login keychain is re-wrapped (`blobVersion` **0x200**): the password is pre-processed via **Secure Enclave / keybag** before PBKDF2, so offline `-p` fails even when `security unlock-keychain -p` succeeds. |
| `--master-key` | File + 24-byte key | No SIP dependency. |
| `--from-securityd` | **root**, unlocked keychain, readable `securityd` memory | Scans heap for a master key that decrypts the DB blob **and** unwraps a symmetric keyblob. **Default SIP Debugging Restrictions usually block `task_for_pid` / memory read of `securityd` even as root.** File parsing itself does **not** require disabling SIP—only this memory-scan path does. |

**Summary:** Export logic (parse + unwrap + write PEM/DER/P12) has **no SIP dependency**. Only **live master-key recovery from `securityd`** depends on SIP debugging policy (and root).

If `--from-securityd` fails under default SIP, use `--master-key` from another authorized source, or `--password` on a legacy keychain.

## Output layout

```text
out/
  keys/          # decrypted private keys (pem/der)
  certs/         # certificates
  identities/    # public-key-matched cert+key (+ identity.p12)
```

The output path must not exist or must be an empty, non-symlink directory. `kd`
builds the export in a private sibling staging directory and renames it into
place only after every requested artifact succeeds. Files are created mode
`0600`; directories are mode `0700`; existing files are never overwritten.

When `p12` output is requested without `--p12-pass`, `KD_P12_PASS`, or
`--p12-pass-file`, `kd` securely prompts for the password twice. Automation
should prefer a protected file or already-open file descriptor; direct flags
and environment variables remain supported for compatibility but can be more
widely observable on the host.

## How it works (short)

1. Parse Apple `kych` tables (PrivateKey, X509, SymmetricKey, Metadata).
2. Derive or recover **master key** → decrypt **DB wrapping key**.
3. CMS-style 3DES unwrap of private key blobs (**does not check** `Extractable`).
4. Match complete public keys to certificates (including RSA and EC); optional PKCS#12.

`Extractable=0` only constrains Security.framework / `security export`. Offline (or memory-assisted) dump still recovers software-wrapped keys.

## Safety

- Authorized use only.
- Outputs may include corporate MDM / NAC private keys — delete after the exercise.
- Prefer `--password-file`, `--master-key-file`, and `--p12-pass-file` with
  protected files or `/dev/fd/*` over placing secrets directly in command arguments.
- Do not pass `--print-secrets` unless debugging in a controlled environment.

## Acknowledgments

Inspired by [n0fate/chainbreaker](https://github.com/n0fate/chainbreaker) and
[gremwell/chainbreaker](https://github.com/gremwell/chainbreaker), two pioneering
open-source tools that first demonstrated offline macOS keychain analysis.

## License

MIT
