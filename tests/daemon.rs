//! End to end: the real daemon against a fake Rhythmbox on a private session
//! bus. The fake player mimics what Rhythmbox was seen doing on a real
//! session: track changes arrive as one PropertiesChanged carrying Metadata
//! and PlaybackStatus, metadata is sometimes repeated for the same track ID,
//! and Volume rides along with everything. Timing is real, so this test takes
//! about 30 seconds.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::zvariant::{OwnedValue, Value};

const BIN: &str = env!("CARGO_BIN_EXE_lighthouse-scrobbler");
const NAME: &str = "org.mpris.MediaPlayer2.rhythmbox";
const PATH: &str = "/org/mpris/MediaPlayer2";
const IFACE: &str = "org.mpris.MediaPlayer2.Player";

/// A private dbus-daemon, killed when dropped.
struct Bus {
    child: Child,
    address: String,
}

impl Bus {
    fn start() -> Option<Bus> {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut line = String::new();
        BufReader::new(child.stdout.take()?).read_line(&mut line).ok()?;
        Some(Bus { child, address: line.trim().to_string() })
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Default)]
struct State {
    status: String,
    metadata: HashMap<String, OwnedValue>,
    position_us: i64,
}

struct Player {
    state: Arc<Mutex<State>>,
}

#[zbus::interface(name = "org.mpris.MediaPlayer2.Player")]
impl Player {
    #[zbus(property)]
    fn playback_status(&self) -> String {
        self.state.lock().unwrap().status.clone()
    }

    #[zbus(property)]
    fn metadata(&self) -> HashMap<String, OwnedValue> {
        let s = self.state.lock().unwrap();
        s.metadata.iter().map(|(k, v)| (k.clone(), v.try_clone().unwrap())).collect()
    }

    #[zbus(property)]
    fn position(&self) -> i64 {
        self.state.lock().unwrap().position_us
    }

    #[zbus(property)]
    fn volume(&self) -> f64 {
        1.0
    }
}

struct FakeRhythmbox {
    conn: Connection,
    state: Arc<Mutex<State>>,
}

fn metadata(id: u32, title: &str, seconds: i64) -> HashMap<String, OwnedValue> {
    let mut m = HashMap::new();
    let s = |v: &str| OwnedValue::try_from(Value::from(v.to_string())).unwrap();
    m.insert("mpris:trackid".into(), s(&format!("/org/mpris/MediaPlayer2/Track/{id}")));
    m.insert("xesam:title".into(), s(title));
    m.insert("xesam:artist".into(), OwnedValue::try_from(Value::from(vec!["Fake Artist".to_string()])).unwrap());
    m.insert("xesam:album".into(), s("Fake Album"));
    m.insert("mpris:length".into(), OwnedValue::from(seconds * 1_000_000));
    m
}

impl FakeRhythmbox {
    fn start(address: &str) -> FakeRhythmbox {
        let state = Arc::new(Mutex::new(State { status: "Stopped".into(), ..Default::default() }));
        let conn = zbus::blocking::connection::Builder::address(address)
            .unwrap()
            .name(NAME)
            .unwrap()
            .serve_at(PATH, Player { state: state.clone() })
            .unwrap()
            .build()
            .unwrap();
        FakeRhythmbox { conn, state }
    }

    /// Change state and announce it the way Rhythmbox does: one signal,
    /// with a Volume entry riding along.
    fn change(&self, status: Option<&str>, meta: Option<HashMap<String, OwnedValue>>) {
        let mut changed: HashMap<&str, Value> = HashMap::new();
        {
            let mut s = self.state.lock().unwrap();
            if let Some(m) = meta {
                let dict: HashMap<String, Value> =
                    m.iter().map(|(k, v)| (k.clone(), Value::from(v.try_clone().unwrap()))).collect();
                changed.insert("Metadata", Value::from(dict));
                s.metadata = m;
            }
            if let Some(st) = status {
                changed.insert("PlaybackStatus", Value::from(st.to_string()));
                s.status = st.to_string();
            }
        }
        changed.insert("Volume", Value::from(1.0f64));
        self.conn
            .emit_signal(
                None::<zbus::names::BusName>,
                PATH,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                &(IFACE, changed, Vec::<&str>::new()),
            )
            .unwrap();
    }
}

fn plays(home: &Path) -> Vec<lighthouse_scrobbler::db::Listen> {
    let conn = lighthouse_scrobbler::db::open(&home.join("data/history.sqlite")).unwrap();
    let mut v = lighthouse_scrobbler::db::recent(&conn, 100).unwrap();
    v.reverse();
    v
}

#[test]
fn daemon_records_plays_from_a_fake_rhythmbox() {
    let Some(bus) = Bus::start() else {
        eprintln!("skipping: dbus-daemon is not available");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("profile");

    let player = FakeRhythmbox::start(&bus.address);
    let mut daemon = Command::new(BIN)
        .arg("run")
        .env("LIGHTHOUSE_SCROBBLER_HOME", &home)
        .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let log = log.clone();
        let err = daemon.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                log.lock().unwrap().push(line);
            }
        });
    }
    sleep(Duration::from_millis(1500));

    // Track A, 31 s long, so it qualifies after 15.5 s of listening.
    player.change(Some("Playing"), Some(metadata(1, "Track A", 31)));
    sleep(Duration::from_secs(5));
    player.change(Some("Paused"), None);
    sleep(Duration::from_secs(3)); // paused time must not count
    player.change(Some("Playing"), None);
    sleep(Duration::from_secs(4));
    player.change(None, Some(metadata(1, "Track A", 31))); // duplicate metadata
    sleep(Duration::from_secs(5));
    // 14 s heard so far: the pause and the duplicate metadata changed nothing.
    assert!(plays(&home).is_empty(), "recorded too early: {:?}", log.lock().unwrap());
    sleep(Duration::from_secs(3));
    let rows = plays(&home);
    assert_eq!(rows.len(), 1, "log: {:?}", log.lock().unwrap());
    assert_eq!(rows[0].title, "Track A");
    assert_eq!(rows[0].artist.as_deref(), Some("Fake Artist"));
    assert_eq!(rows[0].qualification_rule, "half_duration");
    assert!((15_500..16_700).contains(&rows[0].qualified_after_ms), "{}", rows[0].qualified_after_ms);
    assert_eq!(rows[0].observed_listened_ms, None, "still playing");
    let stream = std::fs::read_to_string(home.join("config/stream-id.txt")).unwrap();
    assert_eq!(rows[0].stream_id.as_deref(), Some(stream.trim()), "stamped with this install's stream ID");

    // Switching tracks ends A; quitting the player ends B before it qualifies.
    player.change(Some("Playing"), Some(metadata(2, "Track B", 31)));
    sleep(Duration::from_secs(2));
    drop(player);
    sleep(Duration::from_millis(1500));
    let rows = plays(&home);
    assert_eq!(rows.len(), 1, "B must not be recorded");
    let heard = rows[0].observed_listened_ms.expect("A's end was observed");
    assert!((16_000..19_000).contains(&heard), "A heard for {heard} ms");
    assert!(log.lock().unwrap().iter().any(|l| l.contains("rhythmbox went away")));

    // Rhythmbox coming back is noticed, and nothing is recorded twice.
    let player = FakeRhythmbox::start(&bus.address);
    sleep(Duration::from_millis(1500));
    assert!(log.lock().unwrap().iter().any(|l| l.contains("rhythmbox appeared")));
    drop(player);

    // A clean stop on SIGTERM.
    unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
    let status = daemon.wait().unwrap();
    assert!(status.success(), "daemon exit: {status:?}; log: {:?}", log.lock().unwrap());
    assert_eq!(plays(&home).len(), 1);
}

#[test]
fn daemon_started_mid_track_skips_it_and_records_the_next() {
    let Some(bus) = Bus::start() else {
        eprintln!("skipping: dbus-daemon is not available");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("profile");

    // Already 20 s into track R when the daemon starts (a restart, say).
    let player = FakeRhythmbox::start(&bus.address);
    player.change(Some("Playing"), Some(metadata(7, "Track R", 31)));
    player.state.lock().unwrap().position_us = 20_000_000;
    let mut daemon = Command::new(BIN)
        .arg("run")
        .env("LIGHTHOUSE_SCROBBLER_HOME", &home)
        .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    sleep(Duration::from_secs(17));
    assert!(plays(&home).is_empty(), "a track already under way must not be recorded");

    player.state.lock().unwrap().position_us = 0;
    player.change(Some("Playing"), Some(metadata(8, "Track S", 31)));
    sleep(Duration::from_secs(17));
    let rows = plays(&home);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "Track S");

    unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
    assert!(daemon.wait().unwrap().success());
}
