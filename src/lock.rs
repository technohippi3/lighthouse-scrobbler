//! `run` and `import` must not overlap. Both take an exclusive lock on the same
//! file; `list`, `stats` and `export` never lock and are safe while recording.

use std::fs::{File, OpenOptions, TryLockError};

use anyhow::{Result, bail};

use crate::paths::Paths;

/// Hold the returned file for as long as the lock is needed.
pub fn exclusive(paths: &Paths) -> Result<File> {
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(paths.run_lock())?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => bail!("{} is held", paths.run_lock().display()),
        Err(TryLockError::Error(e)) => Err(e.into()),
    }
}
