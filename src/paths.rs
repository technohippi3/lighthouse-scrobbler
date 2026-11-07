//! Where the profile lives on disk.
//!
//! Defaults follow XDG: data in `$XDG_DATA_HOME/lighthouse-scrobbler`, config in
//! `$XDG_CONFIG_HOME/lighthouse-scrobbler`. Setting `LIGHTHOUSE_SCROBBLER_HOME`
//! puts both under one directory, which is how the recovery test builds an
//! empty profile.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const APP: &str = "lighthouse-scrobbler";

#[derive(Clone, Debug)]
pub struct Paths {
    pub data: PathBuf,
    pub config: PathBuf,
}

impl Paths {
    pub fn from_env() -> Result<Self> {
        if let Some(home) = std::env::var_os("LIGHTHOUSE_SCROBBLER_HOME") {
            let home = PathBuf::from(home);
            return Ok(Paths { data: home.join("data"), config: home.join("config") });
        }
        let user_home = std::env::var_os("HOME").map(PathBuf::from);
        let xdg = |var: &str, fallback: &str| -> Result<PathBuf> {
            match std::env::var_os(var) {
                Some(v) if !v.is_empty() => Ok(PathBuf::from(v)),
                _ => match &user_home {
                    Some(h) => Ok(h.join(fallback)),
                    None => bail!("neither {var} nor HOME is set"),
                },
            }
        };
        Ok(Paths {
            data: xdg("XDG_DATA_HOME", ".local/share")?.join(APP),
            config: xdg("XDG_CONFIG_HOME", ".config")?.join(APP),
        })
    }

    pub fn db(&self) -> PathBuf {
        self.data.join("history.sqlite")
    }

    pub fn run_lock(&self) -> PathBuf {
        self.data.join("run.lock")
    }

    pub fn recipient(&self) -> PathBuf {
        self.config.join("backup-recipient.txt")
    }

    /// Create the data and config directories, owner-only.
    pub fn ensure(&self) -> Result<()> {
        private_dir(&self.data)?;
        private_dir(&self.config)
    }
}

/// Create a directory (and parents) and make sure only the owner can enter it.
pub fn private_dir(path: &Path) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .with_context(|| format!("creating {}", path.display()))?;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    Ok(())
}
