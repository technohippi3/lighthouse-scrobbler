//! This installation's stream ID: a random identifier recorded on every
//! listen this install captures, so histories merged from several machines
//! still say which writer produced each listen. It is never derived from
//! hardware. A restored profile keeps the stream IDs on its old listens and
//! gets a new one of its own for everything recorded from then on.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};

use crate::paths::Paths;

pub fn stream_id(paths: &Paths) -> Result<String> {
    let path = paths.config.join("stream-id.txt");
    if let Ok(text) = fs::read_to_string(&path)
        && let Some(id) = text.lines().map(str::trim).find(|l| uuid::Uuid::parse_str(l).is_ok())
    {
        return Ok(id.to_string());
    }
    paths.ensure()?;
    let id = uuid::Uuid::new_v4().to_string();
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    writeln!(f, "{id}")?;
    f.sync_all()?;
    Ok(id)
}
