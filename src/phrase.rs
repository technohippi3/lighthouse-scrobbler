//! Recovery secret scheme `lhs-recovery-v1`.
//!
//! Every profile's backup key is derived from a 128-bit recovery secret.
//! Passkeys protect that secret (see `recovery`). The same secret can also be
//! written as 12 BIP39 words, an opt-in paper backup that is never part of
//! normal setup. The derivation is frozen: changing anything here would make
//! existing backups unreadable. It is specified, with test vectors, in
//! `docs/recovery-phrase.md`; the tests below pin those vectors.
//!
//! 1. 16 bytes of OS randomness; as words, 12 English BIP39 words (the last
//!    word carries a 4-bit checksum).
//! 2. HKDF-SHA256 over those 16 bytes (not the BIP39 PBKDF2 seed, and no BIP39
//!    passphrase), with the salt and info strings below, gives 32 bytes.
//! 3. Those bytes are the age X25519 secret key, encoded as `AGE-SECRET-KEY-1…`.

use std::str::FromStr;

use age::x25519::Identity;
use anyhow::{Result, anyhow, bail};
use bech32::{Bech32, Hrp};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const SCHEME: &str = "lhs-recovery-v1";
pub const WORDS: usize = 12;
pub const SECRET_BYTES: usize = 16;
const SALT: &[u8] = b"lighthouse-scrobbler recovery phrase";
const INFO: &[u8] = b"lhs-recovery-v1 age-x25519-identity";

pub type Secret = Zeroizing<[u8; SECRET_BYTES]>;

/// A fresh recovery secret from OS randomness. Setup never accepts one typed
/// in, so a wallet phrase can't be reused by mistake.
pub fn generate() -> Result<Secret> {
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    getrandom::fill(secret.as_mut()).map_err(|e| anyhow!("no OS randomness: {e}"))?;
    Ok(secret)
}

/// The secret as 12 words.
pub fn words(secret: &Secret) -> Result<Zeroizing<Mnemonic>> {
    Ok(Zeroizing::new(Mnemonic::from_entropy(secret.as_ref())?))
}

/// Parse words as a person would type them: case and spacing don't matter.
pub fn parse(input: &str) -> Result<Secret> {
    let normalized = Zeroizing::new(
        input.split_whitespace().map(str::to_lowercase).collect::<Vec<_>>().join(" "),
    );
    let count = normalized.split(' ').filter(|w| !w.is_empty()).count();
    if count != WORDS {
        bail!("recovery words come in a set of {WORDS}; got {count}");
    }
    let m = Zeroizing::new(
        Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|e| match e {
            bip39::Error::UnknownWord(i) => {
                anyhow!("word {} is not a recovery word; check its spelling", i + 1)
            }
            bip39::Error::InvalidChecksum => anyhow!(
                "the words are valid but not in this combination; check each word and its order"
            ),
            other => anyhow!("not valid recovery words: {other}"),
        })?,
    );
    let (entropy, len) = m.to_entropy_array();
    let entropy = Zeroizing::new(entropy);
    if len != SECRET_BYTES {
        bail!("recovery words come in a set of {WORDS}");
    }
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    secret.copy_from_slice(&entropy[..SECRET_BYTES]);
    Ok(secret)
}

/// The backup identity for a recovery secret.
pub fn identity(secret: &Secret) -> Result<Identity> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SALT), secret.as_ref())
        .expand(INFO, key.as_mut())
        .map_err(|_| anyhow!("key derivation failed"))?;
    let encoded = Zeroizing::new(bech32::encode_upper::<Bech32>(
        Hrp::parse("age-secret-key-").expect("valid HRP"),
        key.as_ref(),
    )?);
    Identity::from_str(&encoded).map_err(|e| anyhow!("derived an invalid key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    // BIP39's own test vector for 0x7f repeated 16 times.
    const VECTOR_WORDS: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const VECTOR_IDENTITY: &str =
        "AGE-SECRET-KEY-135N9HKSM7KNE7G9J5HJPHSGRTC5R2HGSEK7QCH6CF0KLVDKCG7MS65A6WZ";
    const VECTOR_RECIPIENT: &str =
        "age14y5yze88k4gh02x5qv7tm9ara5647jk7d0yavk64qtpd9y0vzcwszpqd79";

    #[test]
    fn frozen_vector() {
        let s = parse(VECTOR_WORDS).unwrap();
        assert_eq!(*s, [0x7f; 16]);
        let id = identity(&s).unwrap();
        assert_eq!(id.to_string().expose_secret(), VECTOR_IDENTITY);
        assert_eq!(id.to_public().to_string(), VECTOR_RECIPIENT);
        assert_eq!(words(&s).unwrap().to_string(), VECTOR_WORDS);
    }

    #[test]
    fn zero_entropy_vector() {
        let s = parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let id = identity(&s).unwrap();
        assert_eq!(
            id.to_string().expose_secret(),
            "AGE-SECRET-KEY-19FQWAL842SYQXUJCLG07YJF6AH9TCDJV9GAT67MA9GYNPV8UJC9SHNJ3KA"
        );
        assert_eq!(
            id.to_public().to_string(),
            "age14a2r3culn8gwfx2lth372wl8vq7rghq2vqkeld7397pph5sjrfrswfptue"
        );
    }

    #[test]
    fn typing_is_forgiving_about_case_and_spacing() {
        let messy = "  Legal WINNER thank\tyear\nwave sausage worth useful legal winner thank yellow ";
        assert_eq!(*parse(messy).unwrap(), *parse(VECTOR_WORDS).unwrap());
    }

    #[test]
    fn rejects_bad_words() {
        let swapped =
            "winner legal thank year wave sausage worth useful legal winner thank yellow";
        assert!(parse(swapped).unwrap_err().to_string().contains("combination"));
        let typo = "legal winnr thank year wave sausage worth useful legal winner thank yellow";
        assert!(parse(typo).unwrap_err().to_string().contains("word 2"));
        assert!(parse("legal winner thank").unwrap_err().to_string().contains("got 3"));
        let twenty_four = format!("{VECTOR_WORDS} {VECTOR_WORDS}");
        assert!(parse(&twenty_four).is_err());
    }

    #[test]
    fn generated_secrets_round_trip_through_words() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(*a, *b);
        let w = words(&a).unwrap();
        assert_eq!(w.word_count(), WORDS);
        assert_eq!(*parse(&w.to_string()).unwrap(), *a);
    }
}
