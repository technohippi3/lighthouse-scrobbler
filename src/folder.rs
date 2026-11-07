//! The folder destination: a directory on an external drive, a synced folder
//! or anything else the user picks. It is the only destination in v1.
//!
//! A backup set is the encrypted archives together with the current passkey
//! recovery file. Every export writes both, so any copy of a folder can be
//! restored on its own, with this program alone and no storage provider in
//! between. Provider-specific details (object keys, CIDs, upload state) will
//! belong to future destinations, not to the archive format or the database.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use time::OffsetDateTime;
use time::macros::format_description;

use crate::backup::{self, ImportReport};
use crate::keys;
use crate::paths::{self, Paths};
use crate::recovery::Descriptor;

const PREFIX: &str = "scrobbles-";
const SUFFIX: &str = ".jsonl.zst.age";

pub struct ExportReport {
    pub archive: PathBuf,
    /// Set when this export wrote or refreshed the folder's recovery file.
    pub recovery_file_written: bool,
    /// False for a profile with no passkey (recovery words only).
    pub has_recovery_file: bool,
}

/// Write a complete backup set into `dir`: a new archive, plus the profile's
/// current recovery file if it isn't there already.
pub fn export_set(conn: &mut Connection, paths: &Paths, dir: &Path) -> Result<ExportReport> {
    let recipient = keys::load_recipient(paths)?;
    let here = Descriptor::load(dir)?;
    if let Some(h) = &here
        && h.recipient != recipient.to_string()
    {
        bail!("{} holds another profile's backups; use a different folder", dir.display());
    }
    let descriptor = profile_descriptor(paths, here.as_ref())?;
    let archive = write_archive_file(conn, &recipient, dir)?;
    let mut written = false;
    if let Some(d) = &descriptor
        && here.as_ref() != Some(d)
    {
        d.save(dir)?;
        written = true;
    }
    Ok(ExportReport {
        archive,
        recovery_file_written: written,
        has_recovery_file: descriptor.is_some(),
    })
}

/// The profile's own copy of its recovery file. A profile from before copies
/// were kept adopts the matching one from its backup folder.
pub fn profile_descriptor(paths: &Paths, folder: Option<&Descriptor>) -> Result<Option<Descriptor>> {
    let recipient = keys::load_recipient(paths)?.to_string();
    if let Some(d) = Descriptor::load(&paths.config)?
        && d.recipient == recipient
    {
        return Ok(Some(d));
    }
    if let Some(f) = folder
        && f.recipient == recipient
    {
        remember_descriptor(paths, f)?;
        return Ok(Some(f.clone()));
    }
    Ok(None)
}

/// Keep the profile's copy of the recovery file current.
pub fn remember_descriptor(paths: &Paths, descriptor: &Descriptor) -> Result<()> {
    descriptor.save(&paths.config)
}

/// Write one archive into `dir` and return its path. The ciphertext goes to a
/// temporary file that is synced and then renamed into place, so a failed
/// export leaves earlier archives untouched and no partial file behind.
pub fn write_archive_file(conn: &mut Connection, recipient: &Recipient, dir: &Path) -> Result<PathBuf> {
    paths::private_dir(dir)?;
    let now = OffsetDateTime::now_utc();
    let stamp = now.format(format_description!("[year][month][day]T[hour][minute][second]Z"))?;
    let name = format!("{PREFIX}{stamp}{SUFFIX}");
    let target = dir.join(&name);
    if target.exists() {
        bail!("{} already exists", target.display());
    }
    let tmp = dir.join(format!(".{name}.partial"));

    let result = (|| -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        let written = backup::write_archive(conn, recipient, BufWriter::new(file), now, 0)?;
        let file = written.out.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, &target).with_context(|| format!("renaming into {}", target.display()))?;
    File::open(dir)?.sync_all()?;
    Ok(target)
}

/// Merge one archive file into the history.
pub fn import_file(conn: &mut Connection, identity: &Identity, archive: &Path) -> Result<ImportReport> {
    let file = File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    backup::import_archive(conn, identity, BufReader::new(file))
        .with_context(|| format!("restoring {}", archive.display()))
}

/// Archive file names in `dir`, oldest first.
pub fn archives(dir: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
        .collect();
    names.sort();
    Ok(names)
}

/// The newest archive in `dir`, by its UTC timestamp name.
pub fn latest(dir: &Path) -> Result<Option<PathBuf>> {
    Ok(archives(dir)?.pop().map(|n| dir.join(n)))
}
