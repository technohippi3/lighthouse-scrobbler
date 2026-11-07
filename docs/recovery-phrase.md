# Recovery secret scheme `lhs-recovery-v1`

This document freezes how a profile's backup key is derived from its recovery
secret. Backups written under this scheme must stay readable by every later
version. Any change, however small, needs a new scheme name. Old secrets must
keep working.

## Derivation

1. Setup draws 16 bytes (128 bits) from the operating system's random number
   generator. It never accepts a secret as input, so a wallet phrase cannot be
   reused by mistake.
2. The 16 bytes are fed into HKDF-SHA256 (RFC 5869), producing 32 bytes. The
   HKDF parameters are:
   - salt: the ASCII bytes `lighthouse-scrobbler recovery phrase`
   - info: the ASCII bytes `lhs-recovery-v1 age-x25519-identity`
3. The 32 bytes are the age X25519 secret key. Encoded as Bech32 with HRP
   `age-secret-key-` and uppercased, they become the usual
   `AGE-SECRET-KEY-1…` identity string.

The profile stores only the public `age1…` recipient. The private key exists
only in memory when a backup has to be read.

## How the secret is protected

Normally, passkeys protect the secret; see `src/recovery.rs`. Each passkey
wraps the 16 bytes with XChaCha20-Poly1305 under a key derived by HKDF-SHA256
from that passkey's WebAuthn PRF output. The additional authenticated data
binds the wrapped copy to the backup recipient, the relying party ID and the
credential ID. The wrapped copies live in
`lighthouse-scrobbler-recovery.json` next to the backups.

As a fallback, the same 16 bytes can be written as 12 words from the English
BIP39 word list, following
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). The
last word carries a 4-bit checksum. The words encode the raw secret: this
scheme uses neither the BIP39 PBKDF2 seed nor a BIP39 passphrase. Words are
shown only when asked for, by `recovery-words` after a passkey approval or by
the words-only `init`. They are parsed case-insensitively, with any whitespace
between words. The parser rejects any input that is not 12 words or fails the
checksum.

Backup files are ordinary age files encrypted to the recipient. With the
identity string, any age implementation can decrypt one. The result is zstd
data, which decompresses to JSONL.

## Test vectors

These come from BIP39's own test vectors. An independent Python
implementation of HKDF, Bech32 and X25519 produced the same values.

| Secret | Words |
|---|---|
| `00` × 16 | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| `7f` × 16 | `legal winner thank year wave sausage worth useful legal winner thank yellow` |

| Secret | Identity | Recipient |
|---|---|---|
| `00` × 16 | `AGE-SECRET-KEY-19FQWAL842SYQXUJCLG07YJF6AH9TCDJV9GAT67MA9GYNPV8UJC9SHNJ3KA` | `age14a2r3culn8gwfx2lth372wl8vq7rghq2vqkeld7397pph5sjrfrswfptue` |
| `7f` × 16 | `AGE-SECRET-KEY-135N9HKSM7KNE7G9J5HJPHSGRTC5R2HGSEK7QCH6CF0KLVDKCG7MS65A6WZ` | `age14y5yze88k4gh02x5qv7tm9ara5647jk7d0yavk64qtpd9y0vzcwszpqd79` |

`tests/fixtures/passkey-v1/` is a backup folder written by version 0.1.0. Its
secret is `24` × 16, and it holds one passkey envelope whose PRF output is
`42` × 32. The test suite restores it on every run, once through the passkey
path and once through the words.
