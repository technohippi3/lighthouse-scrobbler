//! The local listening history.

use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::tracker::Qualified;

const SCHEMA_VERSION: i64 = 1;

/// One recorded play. The same shape is used in the database and in backups.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Listen {
    pub id: String,
    /// When the play started, RFC 3339 UTC.
    pub started_at: String,
    pub title: String,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub album_artist: Option<String>,
    pub track_number: Option<i64>,
    pub disc_number: Option<i64>,
    pub duration_ms: Option<i64>,
    /// Listening time at the moment the play qualified.
    pub qualified_after_ms: i64,
    pub qualification_rule: String,
    /// Listening time when the play ended. A lower bound if the daemon stopped
    /// mid-play; absent if it never saw the end.
    pub observed_listened_ms: Option<i64>,
    pub mb_track_id: Option<String>,
    pub mb_album_id: Option<String>,
    pub mb_artist_id: Option<String>,
    pub url: Option<String>,
    pub player: String,
    pub player_track_id: Option<String>,
    pub recorded_at: String,
}

impl Listen {
    pub fn from_qualified(q: &Qualified, player: &str, now: OffsetDateTime) -> Result<Self> {
        let t = &q.track;
        Ok(Listen {
            id: q.id.to_string(),
            started_at: q.started_at.format(&Rfc3339)?,
            title: t.title.clone().unwrap_or_default(),
            artist: t.artist.clone(),
            album: t.album.clone(),
            album_artist: t.album_artist.clone(),
            track_number: t.track_number,
            disc_number: t.disc_number,
            duration_ms: t.duration_ms.map(|d| d as i64),
            qualified_after_ms: q.qualified_after_ms as i64,
            qualification_rule: q.rule.as_str().to_string(),
            observed_listened_ms: None,
            mb_track_id: t.mb_track_id.clone(),
            mb_album_id: t.mb_album_id.clone(),
            mb_artist_id: t.mb_artist_id.clone(),
            url: t.url.clone(),
            player: player.to_string(),
            player_track_id: Some(t.track_id.clone()),
            recorded_at: now.format(&Rfc3339)?,
        })
    }

    /// Reject records that could not have come from this program.
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.id).with_context(|| format!("bad id {:?}", self.id))?;
        for (name, ts) in [("started_at", &self.started_at), ("recorded_at", &self.recorded_at)] {
            OffsetDateTime::parse(ts, &Rfc3339)
                .with_context(|| format!("bad {name} {ts:?} in {}", self.id))?;
        }
        if self.title.trim().is_empty() {
            bail!("empty title in {}", self.id);
        }
        if self.qualified_after_ms < 0 || self.observed_listened_ms.is_some_and(|m| m < 0) {
            bail!("negative duration in {}", self.id);
        }
        Ok(())
    }

    /// Equal apart from `observed_listened_ms`, which may legitimately be filled
    /// in after a backup was taken.
    pub fn same_play(&self, other: &Listen) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.observed_listened_ms = None;
        b.observed_listened_ms = None;
        a == b
    }
}

const COLUMNS: &str = "id, started_at, title, artist, album, album_artist, track_number, \
     disc_number, duration_ms, qualified_after_ms, qualification_rule, observed_listened_ms, \
     mb_track_id, mb_album_id, mb_artist_id, url, player, player_track_id, recorded_at";

fn row_to_listen(r: &rusqlite::Row<'_>) -> rusqlite::Result<Listen> {
    Ok(Listen {
        id: r.get(0)?,
        started_at: r.get(1)?,
        title: r.get(2)?,
        artist: r.get(3)?,
        album: r.get(4)?,
        album_artist: r.get(5)?,
        track_number: r.get(6)?,
        disc_number: r.get(7)?,
        duration_ms: r.get(8)?,
        qualified_after_ms: r.get(9)?,
        qualification_rule: r.get(10)?,
        observed_listened_ms: r.get(11)?,
        mb_track_id: r.get(12)?,
        mb_album_id: r.get(13)?,
        mb_artist_id: r.get(14)?,
        url: r.get(15)?,
        player: r.get(16)?,
        player_track_id: r.get(17)?,
        recorded_at: r.get(18)?,
    })
}

pub fn insert(conn: &Connection, l: &Listen) -> Result<()> {
    conn.execute(
        &format!(
            "INSERT INTO listens ({COLUMNS}) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)"
        ),
        params![
            l.id,
            l.started_at,
            l.title,
            l.artist,
            l.album,
            l.album_artist,
            l.track_number,
            l.disc_number,
            l.duration_ms,
            l.qualified_after_ms,
            l.qualification_rule,
            l.observed_listened_ms,
            l.mb_track_id,
            l.mb_album_id,
            l.mb_artist_id,
            l.url,
            l.player,
            l.player_track_id,
            l.recorded_at,
        ],
    )?;
    Ok(())
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<Listen>> {
    Ok(conn
        .query_row(&format!("SELECT {COLUMNS} FROM listens WHERE id = ?1"), [id], row_to_listen)
        .optional()?)
}

pub fn set_observed(conn: &Connection, id: &str, ms: i64) -> Result<()> {
    conn.execute(
        "UPDATE listens SET observed_listened_ms = MAX(COALESCE(observed_listened_ms, 0), ?2) \
         WHERE id = ?1",
        params![id, ms],
    )?;
    Ok(())
}

pub fn recent(conn: &Connection, limit: usize) -> Result<Vec<Listen>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM listens ORDER BY started_at DESC, recorded_at DESC LIMIT ?1"
    ))?;
    let rows = stmt.query_map([limit as i64], row_to_listen)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn count(tx: &Transaction<'_>) -> Result<u64> {
    let n: i64 = tx.query_row("SELECT COUNT(*) FROM listens", [], |r| r.get(0))?;
    Ok(n as u64)
}

/// Visit every listen, oldest first, one row at a time, inside the caller's
/// transaction. Memory use does not depend on the size of the history.
pub fn for_each(tx: &Transaction<'_>, mut visit: impl FnMut(Listen) -> Result<()>) -> Result<()> {
    let mut stmt =
        tx.prepare(&format!("SELECT {COLUMNS} FROM listens ORDER BY started_at, id"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        visit(row_to_listen(row)?)?;
    }
    Ok(())
}

/// Every listen, oldest first, read inside the caller's transaction.
pub fn all(tx: &Transaction<'_>) -> Result<Vec<Listen>> {
    let mut stmt =
        tx.prepare(&format!("SELECT {COLUMNS} FROM listens ORDER BY started_at, id"))?;
    let rows = stmt.query_map([], row_to_listen)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub struct Stats {
    pub listens: i64,
    pub distinct_tracks: i64,
    pub first: Option<String>,
    pub last: Option<String>,
    pub observed_ms: i64,
    pub observed_listens: i64,
    pub top_artists: Vec<(String, i64)>,
    pub top_tracks: Vec<(String, String, i64)>,
}

pub fn stats(conn: &Connection) -> Result<Stats> {
    let (listens, distinct_tracks, first, last, observed_ms, observed_listens) = conn.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT COALESCE(artist, '') || char(31) || title), \
                MIN(started_at), MAX(started_at), \
                COALESCE(SUM(observed_listened_ms), 0), COUNT(observed_listened_ms) \
         FROM listens",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    let mut stmt = conn.prepare(
        "SELECT COALESCE(artist, '(unknown)'), COUNT(*) AS n FROM listens \
         GROUP BY 1 ORDER BY n DESC, 1 LIMIT 10",
    )?;
    let top_artists =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
    let mut stmt = conn.prepare(
        "SELECT COALESCE(artist, '(unknown)'), title, COUNT(*) AS n FROM listens \
         GROUP BY 1, 2 ORDER BY n DESC, 1, 2 LIMIT 10",
    )?;
    let top_tracks = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Stats {
        listens,
        distinct_tracks,
        first,
        last,
        observed_ms,
        observed_listens,
        top_artists,
        top_tracks,
    })
}

/// Open (creating if needed) the history database.
pub fn open(path: &Path) -> Result<Connection> {
    let conn =
        Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // One insert per song: full durability costs nothing noticeable.
    conn.pragma_update(None, "synchronous", "FULL")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    match version {
        0 => {
            conn.execute_batch(
                "BEGIN;
                 CREATE TABLE listens (
                     id                   TEXT PRIMARY KEY NOT NULL,
                     started_at           TEXT NOT NULL,
                     title                TEXT NOT NULL,
                     artist               TEXT,
                     album                TEXT,
                     album_artist         TEXT,
                     track_number         INTEGER,
                     disc_number          INTEGER,
                     duration_ms          INTEGER,
                     qualified_after_ms   INTEGER NOT NULL,
                     qualification_rule   TEXT NOT NULL,
                     observed_listened_ms INTEGER,
                     mb_track_id          TEXT,
                     mb_album_id          TEXT,
                     mb_artist_id         TEXT,
                     url                  TEXT,
                     player               TEXT NOT NULL,
                     player_track_id      TEXT,
                     recorded_at          TEXT NOT NULL
                 );
                 CREATE INDEX listens_started_at ON listens (started_at);
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
            Ok(())
        }
        SCHEMA_VERSION => Ok(()),
        v => bail!("database schema version {v} is newer than this program supports"),
    }
}
