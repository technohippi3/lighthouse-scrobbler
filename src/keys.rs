//! The profile's backup key.
//!
//! Only the public recipient is stored. The private identity exists only in
//! memory, unwrapped by a passkey when a backup has to be read (see
//! `recovery`). Routine exports never touch secret material.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::str::FromStr;

use age::x25519::Recipient;
use anyhow::{Context, Result, anyhow};

use crate::paths::Paths;

pub fn load_recipient(paths: &Paths) -> Result<Recipient> {
    let path = paths.recipient();
    let text = fs::read_to_string(&path).with_context(|| {
        format!("reading {} (set up backups first: lighthouse-scrobbler enroll-passkey --backups <folder>)", path.display())
    })?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("age1"))
        .ok_or_else(|| anyhow!("no age recipient in {}", path.display()))?;
    Recipient::from_str(line).map_err(|e| anyhow!("bad recipient in {}: {e}", path.display()))
}

/// Write (or atomically replace) the profile's backup recipient.
pub fn replace_recipient(paths: &Paths, recipient: &Recipient) -> Result<()> {
    let path = paths.recipient();
    let tmp = path.with_extension("txt.partial");
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    writeln!(f, "# Public key that lighthouse-scrobbler encrypts backups to.")?;
    writeln!(f, "# The private key is unlocked only by an enrolled passkey.")?;
    writeln!(f, "{recipient}")?;
    f.sync_all()?;
    fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    if let Some(dir) = path.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}
