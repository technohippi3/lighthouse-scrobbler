//! `run`: record Rhythmbox plays until stopped.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use time::OffsetDateTime;

use crate::db::{self, Listen};
use crate::lock;
use crate::mpris::{self, Event, Watcher};
use crate::paths::Paths;
use crate::tracker::{Action, Tracker};

/// Upper bound on how long the loop sleeps, so a stop signal is noticed promptly.
const MAX_WAIT: Duration = Duration::from_secs(1);

pub fn run(paths: &Paths) -> Result<()> {
    paths.ensure()?;
    let _lock = lock::exclusive(paths)
        .context("another `run` is already recording, or an import is in progress")?;
    let conn = db::open(&paths.db())?;

    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone())?;

    let bus = zbus::blocking::Connection::session().context("connecting to the session bus")?;
    let (tx, rx) = mpsc::channel();
    let watcher = Watcher::start(&bus, tx)?;

    // Instant is CLOCK_MONOTONIC on Linux, which does not advance during suspend.
    let epoch = Instant::now();
    let now = || epoch.elapsed().as_millis() as u64;
    let mut tracker = Tracker::new();

    eprintln!("watching {}", mpris::BUS_NAME);
    attach(&watcher, &mut tracker, now(), &conn)?;

    loop {
        if stop.load(Ordering::SeqCst) {
            apply(&conn, tracker.shutdown(now()))?;
            eprintln!("stopped");
            return Ok(());
        }
        let t = now();
        let wait = tracker
            .next_deadline(t)
            .map(|d| Duration::from_millis(d.saturating_sub(t) + 1))
            .unwrap_or(MAX_WAIT)
            .min(MAX_WAIT);
        let wall = OffsetDateTime::now_utc();
        match rx.recv_timeout(wait) {
            Ok(Event::Changed { status, track }) => {
                if let Some(track) = track {
                    apply(&conn, tracker.metadata(now(), wall, track))?;
                }
                if let Some(status) = status {
                    apply(&conn, tracker.status(now(), wall, status))?;
                }
            }
            Ok(Event::Appeared) => {
                eprintln!("rhythmbox appeared");
                attach(&watcher, &mut tracker, now(), &conn)?;
            }
            Ok(Event::Vanished) => {
                eprintln!("rhythmbox went away");
                apply(&conn, tracker.gone(now()))?;
            }
            Ok(Event::Failed(why)) => {
                apply(&conn, tracker.shutdown(now()))?;
                bail!("lost the D-Bus connection: {why}");
            }
            Err(RecvTimeoutError::Timeout) => apply(&conn, tracker.tick(now()))?,
            Err(RecvTimeoutError::Disconnected) => {
                apply(&conn, tracker.shutdown(now()))?;
                bail!("D-Bus listener threads exited");
            }
        }
    }
}

fn attach(watcher: &Watcher, tracker: &mut Tracker, now: u64, conn: &Connection) -> Result<()> {
    if let Some(s) = watcher.snapshot() {
        let wall = OffsetDateTime::now_utc();
        apply(conn, tracker.attach(now, wall, s.status, s.track, s.position_ms))?;
    }
    Ok(())
}

fn apply(conn: &Connection, actions: Vec<Action>) -> Result<()> {
    for action in actions {
        match action {
            Action::Record(q) => {
                let listen = Listen::from_qualified(&q, mpris::PLAYER, OffsetDateTime::now_utc())?;
                db::insert(conn, &listen)?;
                eprintln!(
                    "recorded: {} - {} ({}, after {}s)",
                    listen.artist.as_deref().unwrap_or("?"),
                    listen.title,
                    listen.qualification_rule,
                    listen.qualified_after_ms / 1000
                );
            }
            Action::Finish { id, observed_ms } => {
                db::set_observed(conn, &id.to_string(), observed_ms as i64)?;
            }
        }
    }
    Ok(())
}
