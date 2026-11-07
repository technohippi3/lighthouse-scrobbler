//! Watching Rhythmbox over MPRIS on the session bus.
//!
//! Only `PlaybackStatus` and `Metadata` drive accounting. Rhythmbox also emits
//! `Volume` with almost every change and occasionally duplicates `Metadata` for
//! the same track; both are harmless because the tracker keys plays on
//! `mpris:trackid`.

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::thread;

use anyhow::{Context, Result};
use zbus::blocking::Connection;
use zbus::blocking::fdo::{DBusProxy, PropertiesProxy};
use zbus::names::InterfaceName;
use zbus::zvariant::{OwnedValue, Value};

use crate::tracker::{Status, Track};

pub const BUS_NAME: &str = "org.mpris.MediaPlayer2.rhythmbox";
pub const PLAYER: &str = "rhythmbox";
const OBJECT_PATH: &str = "/org/mpris/MediaPlayer2";
const PLAYER_IFACE: &str = "org.mpris.MediaPlayer2.Player";

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    Changed { status: Option<Status>, track: Option<Track> },
    Appeared,
    Vanished,
    Failed(String),
}

pub struct Snapshot {
    pub status: Status,
    pub track: Option<Track>,
    pub position_ms: Option<u64>,
}

pub struct Watcher {
    props: PropertiesProxy<'static>,
}

impl Watcher {
    /// Subscribe to Rhythmbox's signals. Events arrive on `tx` from background
    /// threads; the proxy keeps following the well-known name across restarts.
    pub fn start(conn: &Connection, tx: Sender<Event>) -> Result<Self> {
        let props = PropertiesProxy::builder(conn)
            .destination(BUS_NAME)?
            .path(OBJECT_PATH)?
            .build()
            .context("creating the MPRIS properties proxy")?;

        let changes = props.receive_properties_changed()?;
        let tx_changes = tx.clone();
        thread::Builder::new().name("mpris-props".into()).spawn(move || {
            for signal in changes {
                let Ok(args) = signal.args() else { continue };
                if args.interface_name.as_str() != PLAYER_IFACE {
                    continue;
                }
                let changed = &args.changed_properties;
                let status = changed.get("PlaybackStatus").and_then(value_status);
                let track = changed.get("Metadata").and_then(value_track);
                if (status.is_some() || track.is_some())
                    && tx_changes.send(Event::Changed { status, track }).is_err()
                {
                    return;
                }
            }
            let _ = tx_changes.send(Event::Failed("properties signal stream ended".into()));
        })?;

        let owners = DBusProxy::new(conn)?.receive_name_owner_changed_with_args(&[(0, BUS_NAME)])?;
        thread::Builder::new().name("mpris-owner".into()).spawn(move || {
            for signal in owners {
                let Ok(args) = signal.args() else { continue };
                let event =
                    if args.new_owner().is_some() { Event::Appeared } else { Event::Vanished };
                if tx.send(event).is_err() {
                    return;
                }
            }
            let _ = tx.send(Event::Failed("name owner signal stream ended".into()));
        })?;

        Ok(Watcher { props })
    }

    /// Read the player's full state, or `None` if Rhythmbox is not running.
    pub fn snapshot(&self) -> Option<Snapshot> {
        let iface = InterfaceName::from_static_str_unchecked(PLAYER_IFACE);
        let status = self.props.get(iface.clone(), "PlaybackStatus").ok()?;
        let status = value_status(&status)?;
        let track = self.props.get(iface.clone(), "Metadata").ok().and_then(|v| value_track(&v));
        let position_ms = self
            .props
            .get(iface, "Position")
            .ok()
            .and_then(|v| value_i64(&v))
            .map(|us| (us.max(0) / 1000) as u64);
        Some(Snapshot { status, track, position_ms })
    }
}

fn unwrap_variant<'a>(v: &'a Value<'a>) -> &'a Value<'a> {
    match v {
        Value::Value(inner) => unwrap_variant(inner),
        other => other,
    }
}

fn value_str(v: &Value<'_>) -> Option<String> {
    match unwrap_variant(v) {
        Value::Str(s) => Some(s.as_str().to_string()),
        Value::ObjectPath(p) => Some(p.as_str().to_string()),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}

fn value_strs(v: &Value<'_>) -> Option<String> {
    match unwrap_variant(v) {
        Value::Array(a) => {
            let parts: Vec<String> = a.iter().filter_map(value_str).collect();
            (!parts.is_empty()).then(|| parts.join("; "))
        }
        other => value_str(other),
    }
}

fn value_first_str(v: &Value<'_>) -> Option<String> {
    match unwrap_variant(v) {
        Value::Array(a) => a.iter().find_map(value_str),
        other => value_str(other),
    }
}

fn value_i64(v: &Value<'_>) -> Option<i64> {
    match unwrap_variant(v) {
        Value::I64(n) => Some(*n),
        Value::U64(n) => i64::try_from(*n).ok(),
        Value::I32(n) => Some(i64::from(*n)),
        Value::U32(n) => Some(i64::from(*n)),
        Value::I16(n) => Some(i64::from(*n)),
        Value::U16(n) => Some(i64::from(*n)),
        Value::F64(n) if n.is_finite() => Some(*n as i64),
        _ => None,
    }
}

fn value_status(v: &Value<'_>) -> Option<Status> {
    match value_str(v)?.as_str() {
        "Playing" => Some(Status::Playing),
        "Paused" => Some(Status::Paused),
        "Stopped" => Some(Status::Stopped),
        _ => None,
    }
}

fn value_track(v: &Value<'_>) -> Option<Track> {
    let owned = OwnedValue::try_from(unwrap_variant(v)).ok()?;
    let map = HashMap::<String, OwnedValue>::try_from(owned).ok()?;
    track_from_metadata(&map)
}

pub fn track_from_metadata(m: &HashMap<String, OwnedValue>) -> Option<Track> {
    let s = |k: &str| m.get(k).and_then(|v| value_str(v));
    let list = |k: &str| m.get(k).and_then(|v| value_strs(v));
    let first = |k: &str| m.get(k).and_then(|v| value_first_str(v));
    let int = |k: &str| m.get(k).and_then(|v| value_i64(v));
    Some(Track {
        track_id: s("mpris:trackid")?,
        title: s("xesam:title"),
        artist: list("xesam:artist"),
        album: s("xesam:album"),
        album_artist: list("xesam:albumArtist"),
        track_number: int("xesam:trackNumber"),
        disc_number: int("xesam:discNumber"),
        duration_ms: int("mpris:length").filter(|&us| us > 0).map(|us| (us / 1000) as u64),
        url: s("xesam:url"),
        mb_track_id: first("xesam:musicBrainzTrackID"),
        mb_album_id: first("xesam:musicBrainzAlbumID"),
        mb_artist_id: first("xesam:musicBrainzArtistID"),
    })
}
