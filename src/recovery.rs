//! Passkey recovery: the descriptor stored next to the backups.
//!
//! The archive key is an age identity derived from the profile's 128-bit
//! recovery secret (see `phrase`). Each enrolled passkey wraps that same
//! secret independently with a key derived from the passkey's WebAuthn PRF
//! output, so adding or removing a passkey never changes how backups are
//! encrypted, and the secret can always be shown as recovery words on request. The descriptor holds only wrapped material and
//! public parameters; it is readable before anything is decrypted, so a fresh
//! install can find out which passkeys to ask for.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::phrase::{self, SECRET_BYTES, Secret};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

pub const FILE_NAME: &str = "lighthouse-scrobbler-recovery.json";
pub const FORMAT: &str = "lighthouse-scrobbler-recovery";
pub const VERSION: u32 = 1;
const ENVELOPE_KIND: &str = "webauthn-prf-v1";
const WRAP_SALT: &[u8] = b"lighthouse-scrobbler passkey wrap v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Descriptor {
    pub format: String,
    pub version: u32,
    /// The age recipient every backup in this folder is encrypted to.
    pub recipient: String,
    pub envelopes: Vec<Envelope>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub kind: String,
    /// WebAuthn relying party ID (domain) the passkey belongs to.
    pub rp_id: String,
    /// base64url credential ID.
    pub credential_id: String,
    /// base64url PRF input ("first") for this credential. Not secret.
    pub prf_salt: String,
    /// base64url XChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// base64url ciphertext of the 16-byte recovery secret.
    pub ciphertext: String,
    pub created_at: String,
}

impl Descriptor {
    pub fn new(recipient: String) -> Self {
        Descriptor { format: FORMAT.into(), version: VERSION, recipient, envelopes: vec![] }
    }

    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(FILE_NAME)
    }

    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let path = Self::path_in(dir);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let d: Descriptor =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if d.format != FORMAT {
            bail!("{} is not a lighthouse-scrobbler recovery descriptor", path.display());
        }
        if d.version != VERSION {
            bail!("recovery descriptor version {} is not supported", d.version);
        }
        Ok(Some(d))
    }

    /// Write atomically: a crash leaves either the old descriptor or the new one.
    pub fn save(&self, dir: &Path) -> Result<()> {
        crate::paths::private_dir(dir)?;
        let path = Self::path_in(dir);
        let tmp = dir.join(format!(".{FILE_NAME}.partial"));
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        serde_json::to_writer_pretty(&mut f, self)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        fs::rename(&tmp, &path)?;
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn find(&self, credential_id: &str) -> Option<&Envelope> {
        self.envelopes.iter().find(|e| e.credential_id == credential_id)
    }
}

/// A random PRF input for a new credential.
pub fn new_salt() -> Result<String> {
    random_b64(32)
}

pub fn random_b64(len: usize) -> Result<String> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no OS randomness: {e}"))?;
    Ok(B64.encode(bytes))
}

fn wrapping_key(prf_output: &[u8], rp_id: &str, credential_id: &str) -> Result<Zeroizing<[u8; 32]>> {
    if prf_output.len() != 32 {
        bail!("PRF output must be 32 bytes, got {}", prf_output.len());
    }
    let mut info = Vec::new();
    info.extend_from_slice(ENVELOPE_KIND.as_bytes());
    info.push(0);
    info.extend_from_slice(rp_id.as_bytes());
    info.push(0);
    info.extend_from_slice(credential_id.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(WRAP_SALT), prf_output)
        .expand(&info, key.as_mut())
        .map_err(|_| anyhow!("key derivation failed"))?;
    Ok(key)
}

fn aad(recipient: &str, rp_id: &str, credential_id: &str) -> Vec<u8> {
    [ENVELOPE_KIND, recipient, rp_id, credential_id].join("\0").into_bytes()
}

/// Wrap the recovery secret for one passkey.
pub fn wrap(
    secret: &Secret,
    rp_id: &str,
    credential_id: &str,
    prf_salt: &str,
    prf_output: &[u8],
) -> Result<Envelope> {
    let recipient = phrase::identity(secret)?.to_public().to_string();
    let key = wrapping_key(prf_output, rp_id, credential_id)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("no OS randomness: {e}"))?;
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: secret.as_ref(), aad: &aad(&recipient, rp_id, credential_id) },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Envelope {
        kind: ENVELOPE_KIND.into(),
        rp_id: rp_id.into(),
        credential_id: credential_id.into(),
        prf_salt: prf_salt.into(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
    })
}

/// Unwrap the recovery secret with one passkey's PRF output and check that it
/// derives the descriptor's key.
pub fn unwrap(descriptor: &Descriptor, envelope: &Envelope, prf_output: &[u8]) -> Result<Secret> {
    if envelope.kind != ENVELOPE_KIND {
        bail!("unsupported recovery method {:?}", envelope.kind);
    }
    let key = wrapping_key(prf_output, &envelope.rp_id, &envelope.credential_id)?;
    let nonce = B64.decode(&envelope.nonce).context("bad nonce")?;
    if nonce.len() != 24 {
        bail!("bad nonce length");
    }
    let ciphertext = B64.decode(&envelope.ciphertext).context("bad ciphertext")?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(&descriptor.recipient, &envelope.rp_id, &envelope.credential_id),
                },
            )
            .map_err(|_| anyhow!("this passkey could not unlock the backups"))?,
    );
    if plain.len() != SECRET_BYTES {
        bail!("corrupt recovery secret");
    }
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    secret.copy_from_slice(&plain);
    if phrase::identity(&secret)?.to_public().to_string() != descriptor.recipient {
        bail!("unlocked key does not match the descriptor");
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_profile() -> (Secret, Descriptor) {
        let s = phrase::generate().unwrap();
        let d = Descriptor::new(phrase::identity(&s).unwrap().to_public().to_string());
        (s, d)
    }

    #[test]
    fn wrap_unwrap_round_trip_and_tamper_detection() {
        let (id, mut d) = new_profile();
        let prf = [7u8; 32];
        let salt = new_salt().unwrap();
        let env = wrap(&id, "localhost", "cred-1", &salt, &prf).unwrap();
        d.envelopes.push(env.clone());
        let back = unwrap(&d, &env, &prf).unwrap();
        assert_eq!(*back, *id);

        assert!(unwrap(&d, &env, &[8u8; 32]).is_err(), "wrong PRF output");
        let mut other_rp = env.clone();
        other_rp.rp_id = "example.com".into();
        assert!(unwrap(&d, &other_rp, &prf).is_err(), "bound to the RP ID");
        let mut other_cred = env.clone();
        other_cred.credential_id = "cred-2".into();
        assert!(unwrap(&d, &other_cred, &prf).is_err(), "bound to the credential");
        let mut swapped = d.clone();
        swapped.recipient = new_profile().1.recipient;
        assert!(unwrap(&swapped, &env, &prf).is_err(), "bound to the recipient");
        assert!(wrap(&id, "localhost", "c", &salt, &[0u8; 16]).is_err());
    }

    #[test]
    fn independent_passkeys_unlock_the_same_identity() {
        let (id, mut d) = new_profile();
        d.envelopes.push(wrap(&id, "localhost", "a", &new_salt().unwrap(), &[1u8; 32]).unwrap());
        d.envelopes.push(wrap(&id, "localhost", "b", &new_salt().unwrap(), &[2u8; 32]).unwrap());
        let a = unwrap(&d, d.find("a").unwrap(), &[1u8; 32]).unwrap();
        let b = unwrap(&d, d.find("b").unwrap(), &[2u8; 32]).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn descriptor_save_load() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(Descriptor::load(tmp.path()).unwrap().is_none());
        let (id, mut d) = new_profile();
        d.envelopes.push(wrap(&id, "localhost", "a", &new_salt().unwrap(), &[1u8; 32]).unwrap());
        d.save(tmp.path()).unwrap();
        let text = fs::read_to_string(Descriptor::path_in(tmp.path())).unwrap();
        assert!(!text.contains("AGE-SECRET-KEY"));
        assert_eq!(Descriptor::load(tmp.path()).unwrap().unwrap(), d);
    }
}
