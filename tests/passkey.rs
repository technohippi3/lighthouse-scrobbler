//! Drives the passkey handoff end to end with a simulated browser: the test
//! plays the page's part by posting a credential ID and PRF output back to the
//! app's loopback server. What it cannot prove is that a real browser and
//! passkey provider return PRF output; that needs a person and a device.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_lighthouse-scrobbler");

thread_local! {
    /// The fake mailbox relay a hosted-mode test points the app at.
    static RELAY: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// A stand-in for the Worker's mailbox: PUT stores, GET collects once.
fn start_relay() -> String {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = format!("http://127.0.0.1:{}", server.server_addr().to_ip().unwrap().port());
    let boxes: Arc<Mutex<HashMap<String, String>>> = Arc::default();
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let id = req.url().trim_start_matches("/mailbox/").to_string();
            match req.method() {
                tiny_http::Method::Put => {
                    let mut body = String::new();
                    req.as_reader().read_to_string(&mut body).unwrap();
                    boxes.lock().unwrap().insert(id, body);
                    let _ = req.respond(tiny_http::Response::empty(204));
                }
                _ => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    match boxes.lock().unwrap().remove(&id) {
                        Some(body) => { let _ = req.respond(tiny_http::Response::from_string(body)); }
                        None => { let _ = req.respond(tiny_http::Response::empty(204)); }
                    }
                }
            }
        }
    });
    addr
}

fn spawn(home: &Path, args: &[&str], stdin: Option<&str>, rp: &str) -> Child {
    let mut cmd = Command::new(BIN);
    if let Some(relay) = RELAY.with(|r| r.borrow().clone()) {
        cmd.env("LIGHTHOUSE_SCROBBLER_RELAY", relay);
    }
    let mut child = cmd
        .args(args)
        .env("LIGHTHOUSE_SCROBBLER_HOME", home)
        .env("LIGHTHOUSE_SCROBBLER_NO_BROWSER", "1")
        .env("LIGHTHOUSE_SCROBBLER_RP_ID", rp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    drop(child.stdin.take());
    child
}

struct Run {
    child: Child,
    err: BufReader<std::process::ChildStderr>,
}

fn start(home: &Path, args: &[&str], stdin: Option<&str>) -> Run {
    start_rp(home, args, stdin, "localhost")
}

fn start_rp(home: &Path, args: &[&str], stdin: Option<&str>, rp: &str) -> Run {
    let mut child = spawn(home, args, stdin, rp);
    let err = BufReader::new(child.stderr.take().unwrap());
    Run { child, err }
}

/// Read stderr until the next ceremony URL appears.
fn ceremony_url(run: &mut Run) -> String {
    let err = &mut run.err;
    let mut line = String::new();
    loop {
        line.clear();
        assert!(err.read_line(&mut line).unwrap() > 0, "no ceremony URL printed");
        if let Some(i) = line.find("http://localhost:").or_else(|| line.find("https://")) {
            return line[i..].trim().to_string();
        }
    }
}

fn http(url: &str, method: &str, origin: Option<&str>, body: &str) -> (u16, String) {
    let rest = url.strip_prefix("http://").unwrap();
    let (host, path) = rest.split_at(rest.find('/').unwrap());
    let port: u16 = host.split(':').nth(1).unwrap().parse().unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let origin = origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{origin}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status = resp.split(' ').nth(1).unwrap().parse().unwrap();
    (status, resp)
}

struct Page {
    base: String,
    origin: String,
    result_url: Option<String>,
    mailbox: Option<String>,
    token: String,
    app_key: [u8; 32],
}

/// Read what the page reads: the session parameters in the URL fragment.
fn page(url: &str) -> Page {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (base, frag) = url.split_once('#').expect("parameters in the fragment");
    let cfg: serde_json::Value = serde_json::from_slice(&b64.decode(frag).unwrap()).unwrap();
    let key = b64.decode(cfg["appKey"].as_str().unwrap()).unwrap();
    Page {
        base: base.to_string(),
        origin: base.split('/').take(3).collect::<Vec<_>>().join("/"),
        result_url: cfg["resultUrl"].as_str().map(str::to_string),
        mailbox: cfg["mailbox"].as_str().map(str::to_string),
        token: cfg["token"].as_str().unwrap().to_string(),
        app_key: key.try_into().unwrap(),
    }
}

/// Post a plaintext result the way the page does: sealed to the app's key.
fn post_result(url: &str, json: &str) -> u16 {
    let p = page(url);
    let sealed = lighthouse_scrobbler::ceremony::seal(&p.app_key, &p.token, &p.origin, json.as_bytes()).unwrap();
    let body = serde_json::to_string(&sealed).unwrap();
    match (&p.result_url, &p.mailbox) {
        (Some(result), _) => http(result, "POST", Some(&p.origin), &body).0,
        (None, Some(id)) => {
            let relay = RELAY.with(|r| r.borrow().clone()).expect("hosted test needs a relay");
            http(&format!("{relay}/mailbox/{id}"), "PUT", Some(&p.origin), &body).0
        }
        _ => panic!("page has nowhere to send the result"),
    }
}

/// Play the browser: load the page, check forgeries are refused, post the result.
fn complete(url: &str, credential: &str, prf: &[u8; 32]) {
    let p = page(url);
    if let Some(result) = &p.result_url {
        let (status, body) = http(&p.base, "GET", None, "");
        assert_eq!(status, 200);
        assert!(body.contains("navigator.credentials"));
        // Another origin cannot post, and an unsealed or forged body is rejected.
        assert_eq!(http(result, "POST", Some("https://evil.example"), "{}").0, 403);
        assert_eq!(http(result, "POST", Some(&p.origin), r#"{"credentialId":"x","prf":"y"}"#).0, 400);
    } else {
        assert!(p.base.starts_with("https://") && p.mailbox.is_some(), "{url}");
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let body = format!(r#"{{"credentialId":"{credential}","prf":"{}"}}"#, b64.encode(prf));
    let status = post_result(url, &body);
    assert!(status == 200 || status == 204, "{status}");
}

fn finish(mut run: Run) -> String {
    let mut rest = String::new();
    let _ = run.err.read_to_string(&mut rest);
    let out = run.child.wait_with_output().unwrap();
    assert!(out.status.success(), "stderr: {rest}");
    String::from_utf8(out.stdout).unwrap()
}

fn fails(mut run: Run) -> bool {
    let mut rest = String::new();
    let _ = run.err.read_to_string(&mut rest);
    !run.child.wait().unwrap().success()
}

#[test]
fn new_profile_enrolls_and_restores_with_passkeys_only() {
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    let other = tmp.path().join("other-device");
    let backups = tmp.path().join("synced-folder");
    let b = backups.to_str().unwrap();

    // Enroll on a brand-new profile: no words are ever shown.
    let mut c = start(&laptop, &["enroll-passkey", "--backups", b], None);
    let url = ceremony_url(&mut c);
    complete(&url, "cred-phone", &[11u8; 32]);
    let out = finish(c);
    assert!(out.contains("1 passkey(s)"), "{out}");
    assert!(!out.to_lowercase().contains("phrase"));
    let descriptor = std::fs::read_to_string(backups.join("lighthouse-scrobbler-recovery.json")).unwrap();
    assert!(!descriptor.contains("AGE-SECRET-KEY"));
    assert!(std::fs::read_dir(&backups).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".age")));

    // Add an independent second passkey: unlock with the first, then create.
    let mut c = start(&laptop, &["enroll-passkey", "--backups", b], None);
    complete(&ceremony_url(&mut c), "cred-phone", &[11u8; 32]);
    // The same process then starts the enrollment ceremony on a new server.
    let url = ceremony_url(&mut c);
    complete(&url, "cred-password-manager", &[22u8; 32]);
    assert!(finish(c).contains("2 passkey(s)"));

    // Lose the laptop. A different device restores with either passkey.
    std::fs::remove_dir_all(&laptop).unwrap();
    for (cred, prf, home) in [("cred-phone", [11u8; 32], other.clone()), ("cred-password-manager", [22u8; 32], tmp.path().join("third"))] {
        let mut c = start(&home, &["restore", "--from", b], None);
        complete(&ceremony_url(&mut c), cred, &prf);
        let out = finish(c);
        assert!(out.contains("restored"), "{out}");
        assert!(home.join("config/backup-recipient.txt").exists());
    }

    // A passkey that isn't enrolled, or the wrong PRF output, restores nothing.
    let mut c = start(&tmp.path().join("fourth"), &["restore", "--from", b], None);
    complete(&ceremony_url(&mut c), "cred-phone", &[99u8; 32]);
    assert!(fails(c));
    assert!(!tmp.path().join("fourth/config/backup-recipient.txt").exists());
}

#[test]
fn page_reported_failure_sets_nothing_up() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("p");
    let backups = tmp.path().join("b");
    let mut c = start(&home, &["enroll-passkey", "--backups", backups.to_str().unwrap()], None);
    let url = ceremony_url(&mut c);
    assert_eq!(post_result(&url, r#"{"error":"This passkey provider can't protect backups"}"#), 200);
    assert!(fails(c));
    assert!(!backups.join("lighthouse-scrobbler-recovery.json").exists());
    assert!(!home.join("config/backup-recipient.txt").exists());
}

#[test]
fn old_key_is_replaced_only_with_new_key_and_history_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("p");
    let backups = tmp.path().join("b");
    let b = backups.to_str().unwrap();

    // A profile from an older version: a key with no passkey, plus some plays.
    let paths = lighthouse_scrobbler::paths::Paths { data: home.join("data"), config: home.join("config") };
    paths.ensure().unwrap();
    let old = age::x25519::Identity::generate().to_public();
    lighthouse_scrobbler::keys::replace_recipient(&paths, &old).unwrap();
    let conn = lighthouse_scrobbler::db::open(&paths.db()).unwrap();
    lighthouse_scrobbler::db::insert(&conn, &sample(1)).unwrap();
    drop(conn);
    let first = Command::new(BIN).args(["export", "--to", b]).env("LIGHTHOUSE_SCROBBLER_HOME", &home).output().unwrap();
    assert!(first.status.success());

    // Without --new-key it refuses, and opens no browser.
    let out = Command::new(BIN).args(["enroll-passkey", "--backups", b])
        .env("LIGHTHOUSE_SCROBBLER_HOME", &home).env("LIGHTHOUSE_SCROBBLER_NO_BROWSER", "1").env("LIGHTHOUSE_SCROBBLER_RP_ID", "localhost").output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--new-key"));

    // A failed ceremony with --new-key leaves the old key in place.
    let mut c = start(&home, &["enroll-passkey", "--backups", b, "--new-key"], None);
    let url = ceremony_url(&mut c);
    post_result(&url, r#"{"error":"cancelled"}"#);
    assert!(fails(c));
    assert_eq!(lighthouse_scrobbler::keys::load_recipient(&paths).unwrap().to_string(), old.to_string());

    let mut c = start(&home, &["enroll-passkey", "--backups", b, "--new-key"], None);
    complete(&ceremony_url(&mut c), "yubikey", &[7u8; 32]);
    let out = finish(c);
    assert!(out.contains("1 older backup(s)"), "{out}");
    assert!(out.contains("only way to restore"), "{out}");
    assert_ne!(lighthouse_scrobbler::keys::load_recipient(&paths).unwrap().to_string(), old.to_string());

    // The plays recorded under the old key come back with the passkey.
    let fresh = tmp.path().join("fresh");
    let mut c = start(&fresh, &["restore", "--from", b], None);
    complete(&ceremony_url(&mut c), "yubikey", &[7u8; 32]);
    assert!(finish(c).contains("1 added"));

    // --new-key on already-protected backups is refused.
    let out = Command::new(BIN).args(["enroll-passkey", "--backups", b, "--new-key"])
        .env("LIGHTHOUSE_SCROBBLER_HOME", &home).env("LIGHTHOUSE_SCROBBLER_NO_BROWSER", "1").env("LIGHTHOUSE_SCROBBLER_RP_ID", "localhost").output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn restore_refuses_while_run_holds_the_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("p");
    let paths = lighthouse_scrobbler::paths::Paths { data: home.join("data"), config: home.join("config") };
    paths.ensure().unwrap();
    let _held = lighthouse_scrobbler::lock::exclusive(&paths).unwrap();
    let out = Command::new(BIN).args(["restore", "--from", "nowhere"])
        .env("LIGHTHOUSE_SCROBBLER_HOME", &home).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("stop `run` first"));
}

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/passkey-v1");
const FIXTURE_CREDENTIAL: &str = "fixture-credential";
const FIXTURE_PRF: [u8; 32] = [0x42; 32];
/// The fixture's recovery secret is fixed, so its words are fixed too.
const FIXTURE_SECRET: [u8; 16] = [0x24; 16];

/// A folder written by version 0.1.0 (descriptor plus backup) must stay
/// restorable by every later version, given the same passkey response.
#[test]
fn v1_fixture_restores() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("p");
    let mut c = start(&home, &["restore", "--from", FIXTURE], None);
    complete(&ceremony_url(&mut c), FIXTURE_CREDENTIAL, &FIXTURE_PRF);
    assert!(finish(c).contains("3 added"));
    let conn = lighthouse_scrobbler::db::open(&home.join("data/history.sqlite")).unwrap();
    for n in 0..3 {
        assert_eq!(lighthouse_scrobbler::db::get(&conn, &sample(n).id).unwrap().unwrap(), sample(n));
    }
}

/// The same fixture also restores with its recovery words, without the passkey.
#[test]
fn v1_fixture_restores_with_recovery_words() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("p");
    let words = lighthouse_scrobbler::phrase::words(&zeroize::Zeroizing::new(FIXTURE_SECRET)).unwrap().to_string();
    let out = finish(start(&home, &["restore", "--from", FIXTURE, "--recovery-words"], Some(&format!("{words}\n"))));
    assert!(out.contains("3 added"), "{out}");
}

#[test]
fn passkey_profile_can_show_words_and_restore_with_them() {
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    let backups = tmp.path().join("b");
    let b = backups.to_str().unwrap();
    let mut c = start(&laptop, &["enroll-passkey", "--backups", b], None);
    complete(&ceremony_url(&mut c), "key-1", &[3u8; 32]);
    finish(c);

    // Words are shown only after the passkey is approved.
    let mut c = start(&laptop, &["recovery-words", "--backups", b, "--batch"], None);
    complete(&ceremony_url(&mut c), "key-1", &[3u8; 32]);
    let words = finish(c).trim().to_string();
    assert_eq!(words.split(' ').count(), 12);
    let mut c = start(&laptop, &["recovery-words", "--backups", b, "--batch"], None);
    complete(&ceremony_url(&mut c), "key-1", &[4u8; 32]);
    assert!(fails(c), "wrong passkey response shows nothing");

    std::fs::remove_dir_all(&laptop).unwrap();
    let fresh = tmp.path().join("fresh");
    let out = finish(start(&fresh, &["restore", "--from", b, "--recovery-words"], Some(&format!("{words}\n"))));
    assert!(out.contains("restored"), "{out}");
    let wrong = lighthouse_scrobbler::phrase::words(&lighthouse_scrobbler::phrase::generate().unwrap()).unwrap().to_string();
    assert!(fails(start(&tmp.path().join("x"), &["restore", "--from", b, "--recovery-words"], Some(&format!("{wrong}\n")))));
}

#[test]
fn word_profile_adds_a_passkey_keeping_its_key() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("p");
    let backups = tmp.path().join("b");
    let b = backups.to_str().unwrap();
    let words = Command::new(BIN).args(["init", "--batch"]).env("LIGHTHOUSE_SCROBBLER_HOME", &home).output().unwrap();
    let words = String::from_utf8(words.stdout).unwrap();
    assert!(Command::new(BIN).args(["export", "--to", b]).env("LIGHTHOUSE_SCROBBLER_HOME", &home).status().unwrap().success());
    let before = std::fs::read_to_string(home.join("config/backup-recipient.txt")).unwrap();

    // The mainline command never prompts for words; it explains the choices.
    let out = Command::new(BIN).args(["enroll-passkey", "--backups", b])
        .env("LIGHTHOUSE_SCROBBLER_HOME", &home).env("LIGHTHOUSE_SCROBBLER_NO_BROWSER", "1").env("LIGHTHOUSE_SCROBBLER_RP_ID", "localhost")
        .stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && err.contains("--recovery-words") && err.contains("--new-key"), "{err}");

    let mut c = start(&home, &["enroll-passkey", "--backups", b, "--recovery-words"], Some(&words));
    complete(&ceremony_url(&mut c), "key-1", &[5u8; 32]);
    finish(c);
    assert_eq!(std::fs::read_to_string(home.join("config/backup-recipient.txt")).unwrap(), before, "same key");

    let fresh = tmp.path().join("fresh");
    let mut c = start(&fresh, &["restore", "--from", b], None);
    complete(&ceremony_url(&mut c), "key-1", &[5u8; 32]);
    assert!(finish(c).contains("restored"));
    // The words still work as the fallback, and check-recovery-words agrees.
    assert!(Command::new(BIN).args(["check-recovery-words"]).env("LIGHTHOUSE_SCROBBLER_HOME", &fresh)
        .stdin(Stdio::piped()).spawn().map(|mut ch| { ch.stdin.take().unwrap().write_all(words.as_bytes()).unwrap(); ch.wait().unwrap().success() }).unwrap());
}

/// Regenerate with `cargo test --test passkey -- --ignored`. Only do this when
/// deliberately replacing the fixture; the point is that it never changes.
#[test]
#[ignore]
fn regenerate_v1_fixture() {
    use lighthouse_scrobbler::recovery;
    let dir = Path::new(FIXTURE);
    let _ = std::fs::remove_dir_all(dir);
    let secret = zeroize::Zeroizing::new(FIXTURE_SECRET);
    let id = lighthouse_scrobbler::phrase::identity(&secret).unwrap();
    let mut d = recovery::Descriptor::new(id.to_public().to_string());
    let salt = recovery::new_salt().unwrap();
    d.envelopes.push(recovery::wrap(&secret, "localhost", FIXTURE_CREDENTIAL, &salt, &FIXTURE_PRF).unwrap());
    d.save(dir).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut conn = lighthouse_scrobbler::db::open(&tmp.path().join("h.sqlite")).unwrap();
    for n in 0..3 {
        lighthouse_scrobbler::db::insert(&conn, &sample(n)).unwrap();
    }
    lighthouse_scrobbler::folder::write_archive_file(&mut conn, &id.to_public(), dir).unwrap();
}

fn sample(n: u32) -> lighthouse_scrobbler::db::Listen {
    lighthouse_scrobbler::db::Listen {
        id: format!("00000000-0000-4000-8000-{n:012}"),
        started_at: format!("2026-11-07T1{n}:00:00Z"),
        title: format!("Song {n}"),
        artist: Some("Artist".into()),
        album: Some("Album".into()),
        album_artist: None,
        track_number: Some(i64::from(n)),
        disc_number: None,
        duration_ms: Some(200_000),
        qualified_after_ms: 100_000,
        qualification_rule: "half_duration".into(),
        observed_listened_ms: Some(200_000),
        mb_track_id: None,
        mb_album_id: None,
        mb_artist_id: None,
        url: None,
        player: "rhythmbox".into(),
        player_track_id: Some(format!("/org/mpris/MediaPlayer2/Track/{n}")),
        recorded_at: "2026-11-07T20:00:00Z".into(),
    }
}

#[test]
fn words_only_profile_restores_without_a_recovery_file() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("p");
    let b = tmp.path().join("b");
    let words = Command::new(BIN).args(["init", "--batch"]).env("LIGHTHOUSE_SCROBBLER_HOME", &home).output().unwrap();
    let words = String::from_utf8(words.stdout).unwrap();
    let paths = lighthouse_scrobbler::paths::Paths { data: home.join("data"), config: home.join("config") };
    lighthouse_scrobbler::db::insert(&lighthouse_scrobbler::db::open(&paths.db()).unwrap(), &sample(1)).unwrap();
    assert!(Command::new(BIN).args(["export", "--to", b.to_str().unwrap()]).env("LIGHTHOUSE_SCROBBLER_HOME", &home).status().unwrap().success());
    std::fs::remove_dir_all(&home).unwrap();
    let fresh = tmp.path().join("fresh");
    // Without --recovery-words, a folder with no recovery file says what to do.
    let out = Command::new(BIN).args(["restore", "--from", b.to_str().unwrap()]).env("LIGHTHOUSE_SCROBBLER_HOME", &fresh).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("--recovery-words"));
    let out = finish(start(&fresh, &["restore", "--from", b.to_str().unwrap(), "--recovery-words"], Some(&words)));
    assert!(out.contains("1 added"), "{out}");
}

#[test]
fn hosted_page_handoff_enrolls_and_restores() {
    // Same flow through the hosted transport: the page lives on another origin
    // and drops sealed results in a mailbox that the app polls.
    let relay = start_relay();
    RELAY.with(|r| *r.borrow_mut() = Some(relay.clone()));
    let tmp = tempfile::tempdir().unwrap();
    let b = tmp.path().join("b");
    let b = b.to_str().unwrap();
    let rp = "passkeys.example.test";
    let mut c = start_rp(&tmp.path().join("a"), &["enroll-passkey", "--backups", b], None, rp);
    let url = ceremony_url(&mut c);
    assert!(url.starts_with("https://passkeys.example.test/#"), "{url}");
    complete(&url, "hosted-key", &[9u8; 32]);
    finish(c);
    let d = std::fs::read_to_string(Path::new(b).join("lighthouse-scrobbler-recovery.json")).unwrap();
    assert!(d.contains(rp));

    let mut c = start_rp(&tmp.path().join("fresh"), &["restore", "--from", b], None, rp);
    complete(&ceremony_url(&mut c), "hosted-key", &[9u8; 32]);
    assert!(finish(c).contains("restored"));

    // A result sealed for a different session is refused, not accepted.
    let mut c = start_rp(&tmp.path().join("forged"), &["restore", "--from", b], None, rp);
    let url = ceremony_url(&mut c);
    let p = page(&url);
    let mut other_key = [0u8; 32];
    other_key[0] = 9;
    let forged = lighthouse_scrobbler::ceremony::seal(&other_key, &p.token, &p.origin, b"{}").unwrap();
    http(&format!("{relay}/mailbox/{}", p.mailbox.unwrap()), "PUT", None, &serde_json::to_string(&forged).unwrap());
    assert!(fails(c));

    // A passkey enrolled under localhost is still used when no hosted one exists.
    let mut c = start(&tmp.path().join("fresh2"), &["restore", "--from", b], None);
    let url = ceremony_url(&mut c);
    assert!(url.starts_with("https://passkeys.example.test/"), "falls back to the envelope's RP: {url}");
    complete(&url, "hosted-key", &[9u8; 32]);
    finish(c);
}

#[test]
fn backup_set_copied_to_another_folder_restores_on_its_own() {
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    let enrolled = tmp.path().join("enrolled");
    let usb = tmp.path().join("usb-drive");
    let copy = tmp.path().join("copied-elsewhere");

    let mut c = start(&laptop, &["enroll-passkey", "--backups", enrolled.to_str().unwrap()], None);
    complete(&ceremony_url(&mut c), "key-1", &[6u8; 32]);
    finish(c);
    let paths = lighthouse_scrobbler::paths::Paths { data: laptop.join("data"), config: laptop.join("config") };
    let conn = lighthouse_scrobbler::db::open(&paths.db()).unwrap();
    for n in 0..3 {
        lighthouse_scrobbler::db::insert(&conn, &sample(n)).unwrap();
    }
    drop(conn);

    // Exporting to a brand-new folder writes a complete set: archive + recovery file.
    let out = Command::new(BIN).args(["export", "--to", usb.to_str().unwrap()])
        .env("LIGHTHOUSE_SCROBBLER_HOME", &laptop).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(usb.join("lighthouse-scrobbler-recovery.json").exists());
    assert_eq!(lighthouse_scrobbler::folder::archives(&usb).unwrap().len(), 1);

    // Copy the set somewhere else and lose the laptop.
    std::fs::create_dir_all(&copy).unwrap();
    for e in std::fs::read_dir(&usb).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), copy.join(e.file_name())).unwrap();
    }
    std::fs::remove_dir_all(&laptop).unwrap();

    let fresh = tmp.path().join("fresh");
    let mut c = start(&fresh, &["restore", "--from", copy.to_str().unwrap()], None);
    complete(&ceremony_url(&mut c), "key-1", &[6u8; 32]);
    assert!(finish(c).contains("3 added"));
    let conn = lighthouse_scrobbler::db::open(&fresh.join("data/history.sqlite")).unwrap();
    for n in 0..3 {
        assert_eq!(lighthouse_scrobbler::db::get(&conn, &sample(n).id).unwrap().unwrap(), sample(n), "same record, same UUID");
    }
    drop(conn);
    let mut c = start(&fresh, &["restore", "--from", copy.to_str().unwrap()], None);
    complete(&ceremony_url(&mut c), "key-1", &[6u8; 32]);
    let again = finish(c);
    assert!(again.contains("0 added") && again.contains("3 already present"), "{again}");

    // The restored profile keeps its own copy of the recovery file, so its
    // next export to yet another folder is a complete set too.
    let next = tmp.path().join("next");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let out = Command::new(BIN).args(["export", "--to", next.to_str().unwrap()])
        .env("LIGHTHOUSE_SCROBBLER_HOME", &fresh).output().unwrap();
    assert!(out.status.success());
    assert!(next.join("lighthouse-scrobbler-recovery.json").exists());

    // A folder holding another profile's recovery file is refused.
    let other = tmp.path().join("other-profile");
    let mut c = start(&other, &["enroll-passkey", "--backups", tmp.path().join("theirs").to_str().unwrap()], None);
    complete(&ceremony_url(&mut c), "key-2", &[8u8; 32]);
    finish(c);
    let out = Command::new(BIN).args(["export", "--to", tmp.path().join("theirs").to_str().unwrap()])
        .env("LIGHTHOUSE_SCROBBLER_HOME", &fresh).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("another profile"));
}
