# keydump (`kd`)

macOS **file-based** Keychain private-key dump CLI for **authorized** security assessment / red-team exercises.

Exports private keys (including SecItem **non-exportable** / `NeverExtractable` software keys) and certificates from `login.keychain-db`, and matches them into PKCS#12 identities.

> Not for iCloud / Data Protection `keychain-2.db`, and not for Secure Enclave–resident keys (no private key material on disk).

## Install

```bash
cd ~/Projects/keydump
cargo install --path .
# binary: kd
```

## Commands

```bash
# Metadata only
kd list -f ~/Library/Keychains/login.keychain-db

# Classic offline password (legacy keychains)
kd export -f login.keychain-db -p '...' -o ./out

# Known 24-byte master key (hex)
kd export -f login.keychain-db -k <48-hex-chars> -o ./out

# Live host: recover master key from securityd (macOS, see SIP notes)
sudo kd export -f ~/Library/Keychains/login.keychain-db --from-securityd -o ./out

# Default: non-exportable keys only. Full dump + filter + P12:
kd export -k ... -o ./out --include-exportable --name 'NAC' --format p12 --p12-pass labexport
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
  identities/    # modulus-matched cert+key (+ identity.p12)
```

Files are written mode `0600`, directories `0700`.

## How it works (short)

1. Parse Apple `kych` tables (PrivateKey, X509, SymmetricKey, Metadata).
2. Derive or recover **master key** → decrypt **DB wrapping key**.
3. CMS-style 3DES unwrap of private key blobs (**does not check** `Extractable`).
4. Match RSA moduli to certificates; optional PKCS#12.

`Extractable=0` only constrains Security.framework / `security export`. Offline (or memory-assisted) dump still recovers software-wrapped keys.

## Safety

- Authorized use only.
- Outputs may include corporate MDM / NAC private keys — delete after the exercise.
- Do not pass `--print-secrets` unless debugging in a controlled environment.

## Acknowledgments

Inspired by [n0fate/chainbreaker](https://github.com/n0fate/chainbreaker) and
[gremwell/chainbreaker](https://github.com/gremwell/chainbreaker), two pioneering
open-source tools that first demonstrated offline macOS keychain analysis.

## License

MIT
