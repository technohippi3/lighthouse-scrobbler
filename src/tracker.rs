//! Playback accounting for a single player.
//!
//! The tracker is a pure state machine: callers feed it player observations
//! together with a monotonic timestamp in milliseconds, and it returns the
//! actions to persist. It never reads a clock itself, which keeps it testable.

use time::OffsetDateTime;
use uuid::Uuid;

/// Tracks this short or shorter never qualify (Last.fm and ListenBrainz convention).
pub const MIN_TRACK_MS: u64 = 30_000;
/// Listening this long always qualifies, whatever the track length.
pub const CAP_MS: u64 = 240_000;
/// When attaching to a player that is already playing, a position at or below
/// this is treated as the start of the track rather than the middle of it.
pub const ATTACH_FRESH_MS: u64 = 2_000;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Track {
    pub track_id: String,
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub album_artist: Option<String>,
    pub track_number: Option<i64>,
    pub disc_number: Option<i64>,
    pub duration_ms: Option<u64>,
    pub url: Option<String>,
    pub mb_track_id: Option<String>,
    pub mb_album_id: Option<String>,
    pub mb_artist_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Playing,
    Paused,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    HalfDuration,
    FourMinutes,
    FourMinutesUnknownDuration,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::HalfDuration => "half_duration",
            Rule::FourMinutes => "four_minutes",
            Rule::FourMinutesUnknownDuration => "four_minutes_unknown_duration",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Qualified {
    pub id: Uuid,
    pub track: Track,
    pub started_at: OffsetDateTime,
    pub qualified_after_ms: u64,
    pub rule: Rule,
}

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Action {
    /// A play crossed its threshold: insert it now.
    Record(Qualified),
    /// A recorded play ended: store how long it was actually heard.
    Finish { id: Uuid, observed_ms: u64 },
}

/// The listening threshold for a track, or `None` if it can never qualify.
pub fn threshold(track: &Track) -> Option<(u64, Rule)> {
    let has_title = track.title.as_deref().is_some_and(|t| !t.trim().is_empty());
    if !has_title {
        return None;
    }
    match track.duration_ms {
        Some(d) if d > 0 => {
            if d <= MIN_TRACK_MS {
                None
            } else if d / 2 <= CAP_MS {
                Some((d / 2, Rule::HalfDuration))
            } else {
                Some((CAP_MS, Rule::FourMinutes))
            }
        }
        _ => {
            let has_artist = track.artist.as_deref().is_some_and(|a| !a.trim().is_empty());
            has_artist.then_some((CAP_MS, Rule::FourMinutesUnknownDuration))
        }
    }
}

#[derive(Debug)]
struct Occurrence {
    id: Uuid,
    track: Track,
    started_at: OffsetDateTime,
    listened_ms: u64,
    playing_since: Option<u64>,
    qualified: bool,
    /// Attached mid-track: we cannot know what was heard before, so never record it.
    ignored: bool,
}

impl Occurrence {
    fn new(track: Track, wall: OffsetDateTime, now: u64, playing: bool, ignored: bool) -> Self {
        Occurrence {
            id: Uuid::new_v4(),
            track,
            started_at: wall,
            listened_ms: 0,
            playing_since: playing.then_some(now),
            qualified: false,
            ignored,
        }
    }

    fn listened(&self, now: u64) -> u64 {
        self.listened_ms + self.playing_since.map_or(0, |s| now.saturating_sub(s))
    }

    fn pause(&mut self, now: u64) {
        if let Some(since) = self.playing_since.take() {
            self.listened_ms += now.saturating_sub(since);
        }
    }
}

#[derive(Debug)]
pub struct Tracker {
    status: Status,
    last_track: Option<Track>,
    current: Option<Occurrence>,
}

impl Default for Tracker {
    fn default() -> Self {
        Tracker { status: Status::Stopped, last_track: None, current: None }
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start (or resume) watching a player from a full snapshot of its state.
    pub fn attach(
        &mut self,
        now: u64,
        wall: OffsetDateTime,
        status: Status,
        track: Option<Track>,
        position_ms: Option<u64>,
    ) -> Vec<Action> {
        // Re-attaching to the play we are already following changes nothing.
        if let (Some(cur), Some(t)) = (&self.current, &track)
            && cur.track.track_id == t.track_id {
                let mut out = self.metadata(now, wall, t.clone());
                out.extend(self.status(now, wall, status));
                return out;
            }
        let mut out = self.finish_current(now);
        self.status = status;
        self.last_track = track.clone();
        if let Some(t) = track
            && status != Status::Stopped {
                let fresh = position_ms.is_some_and(|p| p <= ATTACH_FRESH_MS);
                self.current =
                    Some(Occurrence::new(t, wall, now, status == Status::Playing, !fresh));
            }
        out.extend(self.check(now));
        out
    }

    /// The player published metadata. Only a new track ID starts a new play;
    /// anything else (artwork, tags, duration) updates the current one in place.
    pub fn metadata(&mut self, now: u64, wall: OffsetDateTime, track: Track) -> Vec<Action> {
        if let Some(cur) = self.current.as_mut()
            && cur.track.track_id == track.track_id {
                cur.track = track.clone();
                self.last_track = Some(track);
                return self.check(now);
            }
        let mut out = self.finish_current(now);
        self.last_track = Some(track.clone());
        if self.status != Status::Stopped {
            let playing = self.status == Status::Playing;
            self.current = Some(Occurrence::new(track, wall, now, playing, false));
        }
        out.extend(self.check(now));
        out
    }

    pub fn status(&mut self, now: u64, wall: OffsetDateTime, status: Status) -> Vec<Action> {
        let mut out = self.check(now);
        match status {
            Status::Playing => match self.current.as_mut() {
                Some(cur) => {
                    if cur.playing_since.is_none() {
                        cur.playing_since = Some(now);
                    }
                }
                None => {
                    // Playing after Stopped restarts the track without new metadata.
                    if let Some(t) = self.last_track.clone() {
                        self.current = Some(Occurrence::new(t, wall, now, true, false));
                    }
                }
            },
            Status::Paused => {
                if let Some(cur) = self.current.as_mut() {
                    cur.pause(now);
                }
            }
            Status::Stopped => out.extend(self.finish_current(now)),
        }
        self.status = status;
        out
    }

    /// The player left the bus or the connection to it failed.
    pub fn gone(&mut self, now: u64) -> Vec<Action> {
        let out = self.finish_current(now);
        self.status = Status::Stopped;
        self.last_track = None;
        out
    }

    /// Called when the deadline from `next_deadline` passes.
    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        self.check(now)
    }

    /// The daemon is exiting.
    pub fn shutdown(&mut self, now: u64) -> Vec<Action> {
        self.finish_current(now)
    }

    /// When the current play will qualify if playback continues uninterrupted.
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        let cur = self.current.as_ref()?;
        if cur.qualified || cur.ignored || cur.playing_since.is_none() {
            return None;
        }
        let (need, _) = threshold(&cur.track)?;
        Some(now + need.saturating_sub(cur.listened(now)))
    }

    fn check(&mut self, now: u64) -> Vec<Action> {
        let Some(cur) = self.current.as_mut() else { return vec![] };
        if cur.qualified || cur.ignored {
            return vec![];
        }
        let Some((need, rule)) = threshold(&cur.track) else { return vec![] };
        let listened = cur.listened(now);
        if listened < need {
            return vec![];
        }
        cur.qualified = true;
        vec![Action::Record(Qualified {
            id: cur.id,
            track: cur.track.clone(),
            started_at: cur.started_at,
            qualified_after_ms: listened,
            rule,
        })]
    }

    fn finish_current(&mut self, now: u64) -> Vec<Action> {
        // A threshold crossed since the last tick still counts.
        let mut out = self.check(now);
        if let Some(mut cur) = self.current.take() {
            cur.pause(now);
            if cur.qualified {
                out.push(Action::Finish { id: cur.id, observed_ms: cur.listened_ms });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000;

    fn wall() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn track(id: &str, secs: Option<u64>) -> Track {
        Track {
            track_id: id.into(),
            title: Some(format!("Title {id}")),
            artist: Some("Artist".into()),
            duration_ms: secs.map(|s| s * S),
            ..Default::default()
        }
    }

    fn records(actions: &[Action]) -> usize {
        actions.iter().filter(|a| matches!(a, Action::Record(_))).count()
    }

    /// A tracker that has just started a fresh play of `t`.
    fn playing(t: Track) -> Tracker {
        let mut tr = Tracker::new();
        tr.attach(0, wall(), Status::Playing, Some(t), Some(0));
        tr
    }

    #[test]
    fn thresholds() {
        assert_eq!(threshold(&track("a", Some(30))), None);
        assert_eq!(threshold(&track("a", Some(31))), Some((15_500, Rule::HalfDuration)));
        assert_eq!(threshold(&track("a", Some(391))), Some((195_500, Rule::HalfDuration)));
        assert_eq!(threshold(&track("a", Some(600))), Some((CAP_MS, Rule::FourMinutes)));
        assert_eq!(
            threshold(&track("a", None)),
            Some((CAP_MS, Rule::FourMinutesUnknownDuration))
        );
        let mut no_artist = track("a", None);
        no_artist.artist = None;
        assert_eq!(threshold(&no_artist), None);
        let mut no_title = track("a", Some(200));
        no_title.title = None;
        assert_eq!(threshold(&no_title), None);
    }

    #[test]
    fn qualifies_at_deadline() {
        let mut tr = playing(track("1", Some(200)));
        assert_eq!(tr.next_deadline(0), Some(100 * S));
        assert!(tr.tick(99 * S).is_empty());
        let out = tr.tick(100 * S);
        assert_eq!(records(&out), 1);
        assert!(tr.tick(150 * S).is_empty(), "records only once");
        assert_eq!(tr.next_deadline(150 * S), None);
    }

    #[test]
    fn pause_stops_the_clock() {
        let mut tr = playing(track("1", Some(200)));
        tr.status(60 * S, wall(), Status::Paused);
        assert_eq!(tr.next_deadline(500 * S), None);
        assert!(tr.tick(500 * S).is_empty());
        tr.status(500 * S, wall(), Status::Playing);
        assert_eq!(tr.next_deadline(500 * S), Some(540 * S));
        assert_eq!(records(&tr.tick(540 * S)), 1);
    }

    #[test]
    fn duplicate_metadata_does_not_reset() {
        let mut tr = playing(track("1", Some(200)));
        let mut updated = track("1", Some(200));
        updated.album = Some("Late artwork or tags".into());
        assert!(tr.metadata(90 * S, wall(), updated).is_empty());
        assert_eq!(records(&tr.tick(100 * S)), 1);
    }

    #[test]
    fn duration_change_recomputes_deadline() {
        let mut tr = playing(track("1", None));
        assert_eq!(tr.next_deadline(0), Some(CAP_MS));
        tr.metadata(10 * S, wall(), track("1", Some(100)));
        assert_eq!(tr.next_deadline(10 * S), Some(50 * S));
    }

    #[test]
    fn short_skips_record_nothing() {
        let mut tr = playing(track("1", Some(200)));
        let mut all = vec![];
        for (i, id) in ["2", "3", "4", "5", "6", "7"].iter().enumerate() {
            all.extend(tr.metadata((i as u64 + 1) * S, wall(), track(id, Some(200))));
        }
        assert!(all.is_empty());
    }

    #[test]
    fn track_change_after_threshold_records_before_switching() {
        // The deadline tick was missed, but the change still records the play.
        let mut tr = playing(track("1", Some(200)));
        let out = tr.metadata(150 * S, wall(), track("2", Some(200)));
        assert_eq!(records(&out), 1);
        assert!(matches!(out[1], Action::Finish { observed_ms, .. } if observed_ms == 150 * S));
    }

    #[test]
    fn finish_reports_observed_time() {
        let mut tr = playing(track("1", Some(200)));
        tr.tick(100 * S);
        tr.status(120 * S, wall(), Status::Paused);
        let out = tr.metadata(300 * S, wall(), track("2", Some(200)));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Action::Finish { observed_ms, .. } if observed_ms == 120 * S));
    }

    #[test]
    fn attaching_mid_track_skips_it_but_not_the_next() {
        let mut tr = Tracker::new();
        tr.attach(0, wall(), Status::Playing, Some(track("1", Some(200))), Some(90 * S));
        assert_eq!(tr.next_deadline(0), None);
        assert!(tr.tick(500 * S).is_empty());
        tr.metadata(500 * S, wall(), track("2", Some(200)));
        assert_eq!(records(&tr.tick(600 * S)), 1);
    }

    #[test]
    fn reattach_to_same_track_keeps_progress() {
        let mut tr = playing(track("1", Some(200)));
        tr.attach(50 * S, wall(), Status::Playing, Some(track("1", Some(200))), Some(50 * S));
        assert_eq!(records(&tr.tick(100 * S)), 1);
    }

    #[test]
    fn stop_then_play_is_a_new_play() {
        let mut tr = playing(track("1", Some(200)));
        tr.tick(100 * S);
        let out = tr.status(110 * S, wall(), Status::Stopped);
        assert!(matches!(out[0], Action::Finish { .. }));
        tr.status(200 * S, wall(), Status::Playing);
        assert_eq!(records(&tr.tick(300 * S)), 1);
    }

    #[test]
    fn metadata_while_stopped_waits_for_play() {
        let mut tr = Tracker::new();
        tr.attach(0, wall(), Status::Stopped, None, None);
        tr.metadata(0, wall(), track("1", Some(200)));
        assert!(tr.tick(500 * S).is_empty());
        tr.status(500 * S, wall(), Status::Playing);
        assert_eq!(records(&tr.tick(600 * S)), 1);
    }

    #[test]
    fn player_vanishing_ends_the_play() {
        let mut tr = playing(track("1", Some(200)));
        assert!(tr.gone(50 * S).is_empty());
        assert!(tr.tick(500 * S).is_empty());
        assert_eq!(tr.next_deadline(500 * S), None);
    }
}
