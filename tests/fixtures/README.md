# Keychain fixtures (phase 2 — end-to-end)

## Goal

Prove `parse → unlock → decrypt → identity match` on a **classic**
(`blobVersion 0x100`) file keychain with a known password, using keys that are
safe to commit (test-only material).

## Status

No binary fixture is committed yet. Add one with the procedure below when you
are ready to extend CI beyond crypto KATs (`tests/kat/`).

## Recommended generation (on macOS)

Use a disposable keychain file — never a real user login keychain.

```bash
FIXTURE=tests/fixtures/test-login.keychain-db
PASS='keydump-test-password-not-secret'

# Create an empty file-based keychain (classic offline unlock).
security create-keychain -p "$PASS" "$FIXTURE"
security set-keychain-settings "$FIXTURE"
security unlock-keychain -p "$PASS" "$FIXTURE"

# Import a test identity (self-signed RSA or EC) as non-extractable. That is
# the main product surface exercised by keydump.
#
# Example outline (adjust to your org's tooling):
#   openssl req -x509 -newkey rsa:2048 -keyout /tmp/t.key -out /tmp/t.crt -days 1 -nodes -subj '/CN=keydump-fixture'
#   # convert to p12, then:
#   security import /tmp/t.p12 -k "$FIXTURE" -P '' -x -T /usr/bin/security

security lock-keychain "$FIXTURE"
```

Record next to the file (or in a sibling `test-login.meta.json`):

- the fixture password (plaintext is fine for this fixture only)
- expected private-key and certificate counts and print names
- SHA-256 of each key's canonical public-key SPKI, calculated from the original
  test key before import
- expected certificate CN and public-key relationship
- optionally, the decrypted private-DER SHA-256 produced by an external tool
  that correctly implements Apple's variable-length CMS description and has
  itself been verified against this fixture

Never use `kd export` to establish the expected values for a keydump test.

## Test sketch

```rust
// tests/e2e_unlock.rs (future)
let kc = KeychainFile::open("tests/fixtures/test-login.keychain-db")?;
let unlocked = try_password(&kc, PASSWORD, 1000)?;
assert_eq!(kc.blob_version(), 0x100);
let records = kc.private_keys()?;
let keys = decrypt_all_keys(&unlocked, &records, false)?; // include_exportable
assert!(!keys.is_empty());
// assert non-zero counts and fingerprints from meta.json
```

## Constraints

- Prefer **blobVersion 0x100**. macOS 26.x SEP-wrapped (`0x200`) keychains will
  fail offline `--password` and are a poor CI default.
- Do not commit corporate / personal key material.
- Establish expected values from the original test material, `security`,
  OpenSSL, or a pinned external implementation that correctly handles Apple's
  variable-length CMS description. Record the exact source and tool version;
  do not derive expectations from keydump itself.
- Assert `blobVersion == 0x100` before committing the fixture.
- Tests must assert non-zero key and identity counts so filtering cannot make
  the end-to-end path pass vacuously.
