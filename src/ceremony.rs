//! Running a passkey ceremony in the user's browser.
//!
//! The app opens the ceremony page with the session parameters in the URL
//! fragment, which browsers never send to the server hosting the page. The
//! page runs WebAuthn and hands the result back to this process. The result is encrypted to a per-session X25519 key that
//! only this process holds: X25519, then HKDF-SHA256 with the session token as
//! salt, then AES-256-GCM with the token and page origin as associated data.
//! `seal` below is the reference for what the page does in JavaScript.
//!
//! Two hosts are supported. For a real relying party, such as the staging
//! Worker, the page is `https://<rp_id>/`; it drops the sealed result in a
//! one-shot mailbox at `https://<rp_id>/mailbox/<id>`, which this process
//! long-polls. For `localhost`, used in tests and the first prototype, this
//! process serves the page itself and receives the result directly.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tiny_http::{Header, Method, Response, Server};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::recovery::{Envelope, random_b64};

/// Where new passkeys are enrolled unless `LIGHTHOUSE_SCROBBLER_RP_ID` says otherwise.
pub const DEFAULT_RP_ID: &str = "lhs-passkey-staging.piratesocialclub.workers.dev";
pub const LOCAL_RP_ID: &str = "localhost";
const HANDOFF: &str = "lhs-handoff-v1";
const PAGE: &str = include_str!("ceremony.html");
const TIMEOUT: Duration = Duration::from_secs(300);
const MAX_BODY: u64 = 16 * 1024;

/// The relying party new passkeys are created for.
pub fn rp_id() -> String {
    std::env::var("LIGHTHOUSE_SCROBBLER_RP_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_RP_ID.to_string())
}

#[derive(Serialize)]
struct PageConfig<'a> {
    v: u32,
    mode: &'a str,
    token: String,
    #[serde(rename = "appKey")]
    app_key: String,
    #[serde(rename = "resultUrl", skip_serializing_if = "Option::is_none")]
    result_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mailbox: Option<String>,
    challenge: String,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exclude: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<CredentialRef<'a>>>,
}

#[derive(Serialize)]
struct CredentialRef<'a> {
    id: &'a str,
    salt: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct Sealed {
    pub epk: String,
    pub iv: String,
    pub ct: String,
}

#[derive(Deserialize)]
struct PageResult {
    #[serde(rename = "credentialId")]
    credential_id: Option<String>,
    prf: Option<String>,
    error: Option<String>,
}

pub struct CeremonyOutput {
    pub rp_id: String,
    pub credential_id: String,
    pub prf_output: Zeroizing<Vec<u8>>,
}

/// Create a new passkey for the current relying party and return its PRF output.
pub fn enroll(salt: &str, existing: &[Envelope]) -> Result<CeremonyOutput> {
    let rp = rp_id();
    let exclude =
        existing.iter().filter(|e| e.rp_id == rp).map(|e| e.credential_id.as_str()).collect();
    let user_id = random_b64(16)?;
    run(&rp, "enroll", "Set up a passkey for your backups", move |c| {
        c.user_id = Some(user_id);
        c.salt = Some(salt);
        c.exclude = Some(exclude);
    })
}

/// Ask for any enrolled passkey and return the PRF output of the one used.
/// Passkeys belong to one relying party each; the current one is preferred.
pub fn unlock(envelopes: &[Envelope]) -> Result<CeremonyOutput> {
    let preferred = rp_id();
    let rp = if envelopes.iter().any(|e| e.rp_id == preferred) {
        preferred
    } else {
        envelopes
            .first()
            .map(|e| e.rp_id.clone())
            .context("no passkey is enrolled for these backups")?
    };
    let credentials: Vec<_> = envelopes
        .iter()
        .filter(|e| e.rp_id == rp)
        .map(|e| CredentialRef { id: &e.credential_id, salt: &e.prf_salt })
        .collect();
    run(&rp, "unlock", "Unlock your backups with your passkey", move |c| {
        c.credentials = Some(credentials);
    })
}

fn run<'a>(
    rp: &str,
    mode: &'a str,
    purpose: &str,
    fill: impl FnOnce(&mut PageConfig<'a>),
) -> Result<CeremonyOutput> {
    let token = random_b64(24)?;
    let secret_bytes = {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(b.as_mut()).map_err(|e| anyhow!("no OS randomness: {e}"))?;
        b
    };
    let app_secret = StaticSecret::from(*secret_bytes);
    let mut config = PageConfig {
        v: 1,
        mode,
        token: token.clone(),
        app_key: B64.encode(PublicKey::from(&app_secret).as_bytes()),
        result_url: None,
        mailbox: None,
        challenge: random_b64(32)?,
        user_id: None,
        salt: None,
        exclude: None,
        credentials: None,
    };
    fill(&mut config);
    let session = Session { rp, purpose, token: &token, app_secret: &app_secret };
    if rp == LOCAL_RP_ID { run_local(session, config) } else { run_hosted(session, config) }
}

struct Session<'s> {
    rp: &'s str,
    purpose: &'s str,
    token: &'s str,
    app_secret: &'s StaticSecret,
}

fn open_browser(purpose: &str, url: &str) {
    eprintln!("{purpose}: opening {url}");
    eprintln!("If no browser window appears, open that address yourself.");
    // Tests set this to drive the handoff without a real browser.
    if std::env::var_os("LIGHTHOUSE_SCROBBLER_NO_BROWSER").is_none() {
        let _ = Command::new("xdg-open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

/// Hosted page: it drops the sealed result in a one-shot mailbox on its own
/// site, and this process collects it. Nothing has to reach this computer
/// from the browser, so local-network protections and content blockers that
/// stop websites from calling 127.0.0.1 don't get in the way.
fn run_hosted(s: Session<'_>, mut config: PageConfig<'_>) -> Result<CeremonyOutput> {
    let mailbox = random_b64(24)?;
    config.mailbox = Some(mailbox.clone());
    let origin = format!("https://{}", s.rp);
    let url = format!("{origin}/#{}", B64.encode(serde_json::to_vec(&config)?));
    open_browser(s.purpose, &url);

    let relay = std::env::var("LIGHTHOUSE_SCROBBLER_RELAY").unwrap_or_else(|_| origin.clone());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(40)))
        .http_status_as_error(false)
        .build()
        .into();
    let mailbox_url = format!("{relay}/mailbox/{mailbox}");
    let deadline = Instant::now() + TIMEOUT;
    let mut warned = false;
    while Instant::now() < deadline {
        match agent.get(&mailbox_url).call() {
            Ok(mut resp) if resp.status().as_u16() == 200 => {
                let body = resp.body_mut().with_config().limit(MAX_BODY).read_to_string()?;
                let sealed: Sealed = serde_json::from_str(&body).context("bad result from the page")?;
                let plain = open(s.app_secret, s.token, &origin, &sealed)
                    .context("the result did not decrypt; it was not produced for this session")?;
                return finish_result(s.rp, &plain);
            }
            Ok(resp) if resp.status().as_u16() == 204 => {} // long poll ended; ask again
            Ok(resp) => {
                if !warned {
                    eprintln!("waiting: the page host answered {}", resp.status());
                    warned = true;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(e) => {
                if !warned {
                    eprintln!("waiting: cannot reach {relay} yet ({e})");
                    warned = true;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    bail!("timed out waiting for the browser")
}

/// Local page: this process serves it on localhost and receives the result directly.
fn run_local(s: Session<'_>, mut config: PageConfig<'_>) -> Result<CeremonyOutput> {
    let server = Server::http("127.0.0.1:0").map_err(|e| anyhow!("starting local server: {e}"))?;
    let port = server.server_addr().to_ip().context("no local port")?.port();
    let page_origin = format!("http://localhost:{port}");
    let host = format!("localhost:{port}");
    let page_path = format!("/{}/", s.token);
    let result_path = format!("/{}/result", s.token);
    config.result_url = Some(format!("{page_origin}{result_path}"));
    let url = format!("{page_origin}{page_path}#{}", B64.encode(serde_json::to_vec(&config)?));
    open_browser(s.purpose, &url);

    let deadline = Instant::now() + TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            bail!("timed out waiting for the browser");
        }
        let Some(mut req) = server.recv_timeout(left)? else { continue };
        // Refuse anything not addressed to this server by name (DNS rebinding).
        if header(&req, "Host").as_deref() != Some(host.as_str()) {
            let _ = req.respond(Response::from_string("wrong host").with_status_code(421));
            continue;
        }
        let path = req.url().split('?').next().unwrap_or("").to_string();
        match (req.method(), path.as_str()) {
            (Method::Get, p) if p == page_path => {
                let _ = req.respond(local_page());
            }
            (Method::Post, p) if p == result_path => {
                if header(&req, "Origin").as_deref() != Some(page_origin.as_str()) {
                    let _ = req.respond(Response::from_string("wrong origin").with_status_code(403));
                    continue;
                }
                let mut body = String::new();
                req.as_reader().take(MAX_BODY).read_to_string(&mut body)?;
                let opened = serde_json::from_str::<Sealed>(&body)
                    .ok()
                    .and_then(|sealed| open(s.app_secret, s.token, &page_origin, &sealed).ok());
                let Some(plain) = opened else {
                    let _ = req.respond(Response::from_string("bad request").with_status_code(400));
                    continue;
                };
                let _ = req.respond(Response::from_string("ok"));
                return finish_result(s.rp, &plain);
            }
            _ => {
                let _ = req.respond(Response::from_string("not found").with_status_code(404));
            }
        }
    }
}

fn finish_result(rp: &str, plain: &[u8]) -> Result<CeremonyOutput> {
    let result: PageResult = serde_json::from_slice(plain).context("bad result")?;
    if let Some(err) = result.error {
        bail!("{err}");
    }
    let credential_id = result.credential_id.context("browser sent no credential")?;
    let prf = Zeroizing::new(result.prf.context("browser sent no PRF output")?);
    let prf_output = Zeroizing::new(B64.decode(prf.as_bytes()).context("bad PRF output")?);
    if prf_output.len() != 32 {
        bail!("PRF output had {} bytes, expected 32", prf_output.len());
    }
    Ok(CeremonyOutput { rp_id: rp.to_string(), credential_id, prf_output })
}

fn handoff_key(shared: &[u8], token: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(token.as_bytes()), shared)
        .expand(HANDOFF.as_bytes(), key.as_mut())
        .map_err(|_| anyhow!("key derivation failed"))?;
    Ok(key)
}

fn handoff_aad(token: &str, origin: &str) -> Vec<u8> {
    format!("{HANDOFF}\0{token}\0{origin}").into_bytes()
}

/// Decrypt a result sealed by the page to this session's key.
fn open(
    app_secret: &StaticSecret,
    token: &str,
    origin: &str,
    s: &Sealed,
) -> Result<Zeroizing<Vec<u8>>> {
    let epk: [u8; 32] = B64.decode(&s.epk)?.try_into().map_err(|_| anyhow!("bad key"))?;
    let shared = app_secret.diffie_hellman(&PublicKey::from(epk));
    if !shared.was_contributory() {
        bail!("bad key");
    }
    let key = handoff_key(shared.as_bytes(), token)?;
    let iv = B64.decode(&s.iv)?;
    if iv.len() != 12 {
        bail!("bad nonce");
    }
    let ct = B64.decode(&s.ct)?;
    let plain = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()))
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: &handoff_aad(token, origin) })
        .map_err(|_| anyhow!("result did not decrypt"))?;
    Ok(Zeroizing::new(plain))
}

/// What the page does: seal `plaintext` to the app's key. Kept here as the
/// reference implementation and for tests that play the browser's part.
pub fn seal(app_key: &[u8; 32], token: &str, origin: &str, plaintext: &[u8]) -> Result<Sealed> {
    let mut eph = Zeroizing::new([0u8; 32]);
    getrandom::fill(eph.as_mut()).map_err(|e| anyhow!("no OS randomness: {e}"))?;
    let eph = StaticSecret::from(*eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*app_key));
    let key = handoff_key(shared.as_bytes(), token)?;
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).map_err(|e| anyhow!("no OS randomness: {e}"))?;
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()))
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad: &handoff_aad(token, origin) })
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Sealed {
        epk: B64.encode(PublicKey::from(&eph).as_bytes()),
        iv: B64.encode(iv),
        ct: B64.encode(ct),
    })
}

fn local_page() -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(PAGE.as_bytes().to_vec())
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Cache-Control", "no-store"))
        .with_header(h("Referrer-Policy", "no-referrer"))
        .with_header(h(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
        ))
}

fn header(req: &tiny_http::Request, name: &'static str) -> Option<String> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str().to_string())
}

fn h(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_and_binding() {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        let app = StaticSecret::from(b);
        let app_pub = *PublicKey::from(&app).as_bytes();
        let s = seal(&app_pub, "tok", "https://rp.example", b"hello").unwrap();
        assert_eq!(&open(&app, "tok", "https://rp.example", &s).unwrap()[..], b"hello");
        assert!(open(&app, "other", "https://rp.example", &s).is_err(), "bound to the session");
        assert!(open(&app, "tok", "https://evil.example", &s).is_err(), "bound to the origin");
        let mut other = [0u8; 32];
        getrandom::fill(&mut other).unwrap();
        assert!(open(&StaticSecret::from(other), "tok", "https://rp.example", &s).is_err());
    }
}
