use std::fs;
use std::path::{Path, PathBuf};

use age::x25519::Identity;
use lighthouse_scrobbler::folder;
use lighthouse_scrobbler::db::{self, Listen};

fn listen(n: u32) -> Listen {
    Listen {
        id: uuid::Uuid::new_v4().to_string(),
        started_at: format!("2026-11-07T11:{:02}:00Z", n % 60),
        title: format!("Song {n}"),
        artist: Some("Artist".into()),
        album: Some("Album".into()),
        album_artist: None,
        track_number: Some(i64::from(n)),
        disc_number: None,
        duration_ms: Some(200_000),
        qualified_after_ms: 100_000,
        qualification_rule: "half_duration".into(),
        observed_listened_ms: None,
        mb_track_id: None,
        mb_album_id: None,
        mb_artist_id: None,
        url: None,
        player: "rhythmbox".into(),
        player_track_id: Some(format!("/org/mpris/MediaPlayer2/Track/{n}")),
        recorded_at: "2026-11-07T12:00:00Z".into(),
    }
}

fn fresh_db(dir: &Path, name: &str) -> rusqlite::Connection {
    db::open(&dir.join(name)).unwrap()
}

fn export_one(conn: &mut rusqlite::Connection, id: &Identity, out: &Path) -> PathBuf {
    folder::write_archive_file(conn, &id.to_public(), out).unwrap()
}

fn rows(conn: &mut rusqlite::Connection) -> Vec<Listen> {
    let tx = conn.transaction().unwrap();
    db::all(&tx).unwrap()
}

#[test]
fn round_trip_into_empty_db_and_reimport_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let mut src = fresh_db(tmp.path(), "src.sqlite");
    for n in 0..50 {
        db::insert(&src, &listen(n)).unwrap();
    }
    let file = export_one(&mut src, &id, &tmp.path().join("out"));
    let raw = fs::read(&file).unwrap();
    assert!(raw.starts_with(b"age-encryption.org/v1"));
    assert!(!String::from_utf8_lossy(&raw).contains("Song"), "no plaintext in the backup");

    let mut dst = fresh_db(tmp.path(), "dst.sqlite");
    let r = folder::import_file(&mut dst, &id, &file).unwrap();
    assert_eq!((r.added, r.updated, r.unchanged), (50, 0, 0));
    assert_eq!(rows(&mut src), rows(&mut dst));

    let r = folder::import_file(&mut dst, &id, &file).unwrap();
    assert_eq!((r.added, r.updated, r.unchanged), (0, 0, 50));
}

#[test]
fn later_observed_time_is_merged_not_a_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let mut src = fresh_db(tmp.path(), "src.sqlite");
    let l = listen(1);
    db::insert(&src, &l).unwrap();
    let before = export_one(&mut src, &id, &tmp.path().join("a"));
    db::set_observed(&src, &l.id, 180_000).unwrap();
    let after = export_one(&mut src, &id, &tmp.path().join("b"));

    let mut dst = fresh_db(tmp.path(), "dst.sqlite");
    folder::import_file(&mut dst, &id, &before).unwrap();
    let r = folder::import_file(&mut dst, &id, &after).unwrap();
    assert_eq!(r.updated, 1);
    // Importing the older snapshot again must not lower it.
    folder::import_file(&mut dst, &id, &before).unwrap();
    assert_eq!(db::get(&dst, &l.id).unwrap().unwrap().observed_listened_ms, Some(180_000));
}

#[test]
fn conflicting_record_imports_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let mut src = fresh_db(tmp.path(), "src.sqlite");
    let a = listen(1);
    let b = listen(2);
    db::insert(&src, &a).unwrap();
    db::insert(&src, &b).unwrap();
    let file = export_one(&mut src, &id, &tmp.path().join("out"));

    let mut dst = fresh_db(tmp.path(), "dst.sqlite");
    let mut changed = b.clone();
    changed.title = "Edited elsewhere".into();
    db::insert(&dst, &changed).unwrap();
    let err = format!("{:#}", folder::import_file(&mut dst, &id, &file).unwrap_err());
    assert!(err.contains("nothing was imported"), "{err}");
    assert!(db::get(&dst, &a.id).unwrap().is_none(), "no partial import");
}

#[test]
fn truncated_or_corrupted_or_wrong_key_imports_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let mut src = fresh_db(tmp.path(), "src.sqlite");
    for n in 0..2000 {
        db::insert(&src, &listen(n)).unwrap();
    }
    let file = export_one(&mut src, &id, &tmp.path().join("out"));
    let good = fs::read(&file).unwrap();
    let mut dst = fresh_db(tmp.path(), "dst.sqlite");

    let truncated = tmp.path().join("truncated.age");
    fs::write(&truncated, &good[..good.len() - 100]).unwrap();
    assert!(folder::import_file(&mut dst, &id, &truncated).is_err());

    let flipped = tmp.path().join("flipped.age");
    let mut bad = good.clone();
    let i = bad.len() / 2;
    bad[i] ^= 0x01;
    fs::write(&flipped, &bad).unwrap();
    assert!(folder::import_file(&mut dst, &id, &flipped).is_err());

    assert!(folder::import_file(&mut dst, &Identity::generate(), &file).is_err());
    assert!(rows(&mut dst).is_empty());
}

#[test]
fn export_leaves_no_partial_files() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let mut src = fresh_db(tmp.path(), "src.sqlite");
    db::insert(&src, &listen(1)).unwrap();
    let out = tmp.path().join("out");
    export_one(&mut src, &id, &out);
    let names: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(names[0].ends_with(".jsonl.zst.age"));
}
