# Crypto known-answer tests (KAT)

## Purpose

These tests compare keydump's PBKDF2, 3DES, and Apple custom-CMS unwrap
results with committed known answers established outside the Rust
implementation.

The vectors provide regression evidence for the recorded cases. They do not,
by themselves, prove full keychain-file parsing or interoperability; that
belongs in the end-to-end fixtures described under `tests/fixtures/`.

## Layout

| Path | Role |
|------|------|
| `vectors/*.json` | Independently verified, immutable inputs and expected outputs |
| `crypto_kat.rs` | Integration tests that consume the static vectors |

This repository intentionally contains no vector-generation script. CI only
reads the committed JSON.

## Provenance

Each JSON file records its source and verification method:

- `pbkdf2.json` copies published PBKDF2-HMAC-SHA1 answers from RFC 6070,
  including non-1000 iteration cases.
- `db_key.json` uses a published 48-byte Apple Keychain sample from John the
  Ripper at a pinned commit. Its 24-byte master key and 44-byte decrypted
  private blob were independently checked with OpenSSL.
- `ssgp_sym.json` and `private_key.json` are static, specification-derived
  vectors. Their byte layout follows Apple's pinned `wrapKeyCms.cpp`; 3DES
  results were calculated and checked with OpenSSL outside keydump. The SSGP
  decoder behavior is also cross-referenced to pinned chainbreaker source.

The SSGP and private-key cases use the canonical Apple layout:

```text
payload = u32be(description_len) || description || raw_key
TEMP1   = 3DES-CBC-PAD(db_key, record_iv, payload)
TEMP2   = record_iv || TEMP1
TEMP3   = reverse(TEMP2)
wrapped = 3DES-CBC-PAD(db_key, MAGIC_CMS_IV, TEMP3)
```

In particular, a zero-description 24-byte SSGP key has a 40-byte `TEMP3` and
a 48-byte wrapped ciphertext. Private-key descriptions are variable-length;
they are not a fixed 12-byte prefix.

## Run

```bash
cargo test -p keydump --test crypto_kat
```

## Changing vectors

Every new or changed case must record:

- the external source or fixture;
- the exact upstream commit, tool version, or published standard;
- the independent verification procedure;
- the fixed input and expected output.

Do not derive vectors from the Rust crate under test or add a repository-local
mirror of the wrap operation. Prefer adding a new case. Do not rewrite an
existing known answer unless its recorded source has been shown to be wrong.

## Phase 2

End-to-end `KeychainFile::parse -> unlock -> decrypt` against a disposable
classic `login.keychain-db` belongs under `tests/fixtures/` (see that README).
Crypto KATs here stay free of full keychain binaries.
