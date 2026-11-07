use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use lighthouse_scrobbler::phrase::{self, Secret};
use lighthouse_scrobbler::recovery::{self, Descriptor};
use lighthouse_scrobbler::{ceremony, daemon, db, folder, keys, lock, paths::Paths};

/// Record Rhythmbox plays to a local history, with encrypted backups that a
/// passkey unlocks. Recording and backups make no network connections.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Watch Rhythmbox and record plays until stopped.
    Run,
    /// Show recent plays.
    List {
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// Summarize the history.
    Stats,
    /// Write an encrypted snapshot of the whole history into a directory.
    Export {
        #[arg(long)]
        to: PathBuf,
    },
    /// Set up backups with a passkey (opens your browser). The first run is the
    /// whole setup; running it again adds another passkey.
    EnrollPasskey {
        /// The backup folder. The recovery file is written there, next to the backups.
        #[arg(long)]
        backups: PathBuf,
        /// Profiles set up with recovery words only: enter them once to keep
        /// the current backup key.
        #[arg(long, conflicts_with = "new_key")]
        recovery_words: bool,
        /// Replace this profile's backup key with a new one. Recorded plays are
        /// kept; older backups stay readable only with the old key.
        #[arg(long)]
        new_key: bool,
    },
    /// Restore the newest backup in a folder by approving a passkey in your
    /// browser. `run` must be stopped.
    Restore {
        #[arg(long)]
        from: PathBuf,
        /// Fallback: unlock with recovery words instead of a passkey.
        #[arg(long)]
        recovery_words: bool,
    },
    /// Optional paper backup: after approving your passkey, show the 12
    /// recovery words for these backups.
    RecoveryWords {
        #[arg(long)]
        backups: PathBuf,
        /// For scripts and tests: print the words to stdout without a terminal.
        #[arg(long, hide = true)]
        batch: bool,
    },
    /// Check that a set of recovery words belongs to this profile, without restoring.
    CheckRecoveryWords,
    /// Advanced: set up backups with recovery words only, for systems where no
    /// passkey works. Prefer `enroll-passkey`.
    Init {
        /// For scripts and tests: print the words to stdout and skip the
        /// confirmation. Make sure stdout goes somewhere safe.
        #[arg(long)]
        batch: bool,
    },
}

fn main() {
    // Everything this program creates is for the owner only.
    unsafe { libc::umask(0o077) };
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::from_env()?;
    match cli.command {
        Command::Run => daemon::run(&paths),
        Command::List { limit } => list(&paths, limit),
        Command::Stats => stats(&paths),
        Command::Export { to } => {
            paths.ensure()?;
            let mut conn = db::open(&paths.db())?;
            let report = folder::export_set(&mut conn, &paths, &to)?;
            println!("{}", report.archive.display());
            if report.recovery_file_written {
                eprintln!("wrote the passkey recovery file into {}", to.display());
            }
            if !report.has_recovery_file {
                eprintln!("note: no passkey protects this profile; restore with --recovery-words");
            }
            Ok(())
        }
        Command::EnrollPasskey { backups, recovery_words, new_key } => {
            enroll_passkey(&paths, &backups, recovery_words, new_key)
        }
        Command::Restore { from, recovery_words } => restore(&paths, &from, recovery_words),
        Command::RecoveryWords { backups, batch } => show_recovery_words(&backups, batch),
        Command::CheckRecoveryWords => {
            let stored = keys::load_recipient(&paths)?;
            let derived = phrase::identity(&read_words()?)?.to_public();
            if derived.to_string() != stored.to_string() {
                bail!("those words do not belong to this profile");
            }
            println!("Those words match this profile. Your backups can be restored with them.");
            Ok(())
        }
        Command::Init { batch } => init(&paths, batch),
    }
}

fn profile_recipient(paths: &Paths) -> Result<Option<String>> {
    Ok(if paths.recipient().exists() { Some(keys::load_recipient(paths)?.to_string()) } else { None })
}

fn enroll_passkey(paths: &Paths, backups: &Path, recovery_words: bool, new_key: bool) -> Result<()> {
    paths.ensure()?;
    let profile = profile_recipient(paths)?;
    // A folder without a recovery file of its own (a new export folder, say)
    // still belongs to this profile's passkeys, through the profile's copy.
    let in_folder = Descriptor::load(backups)?;
    let existing = match in_folder {
        Some(d) => Some(d),
        None if !new_key && profile.is_some() => folder::profile_descriptor(paths, None)?,
        None => None,
    };
    let protected = existing.as_ref().is_some_and(|d| !d.envelopes.is_empty());
    if let (Some(d), Some(r)) = (&existing, &profile)
        && &d.recipient != r
        && !new_key
    {
        bail!("the backups in {} belong to a different profile", backups.display());
    }

    // Get hold of the recovery secret to wrap, without ever writing it down.
    let (secret, mut descriptor, key_is_new): (Secret, Descriptor, bool) = if new_key {
        if existing.is_some() {
            bail!(
                "{} already holds a recovery file; use an empty folder for the new key",
                backups.display()
            );
        }
        let s = phrase::generate()?;
        let d = Descriptor::new(phrase::identity(&s)?.to_public().to_string());
        (s, d, true)
    } else if recovery_words {
        let Some(r) = &profile else { bail!("this profile has no backup key yet") };
        let s = read_words()?;
        if &phrase::identity(&s)?.to_public().to_string() != r {
            bail!("those words do not belong to this profile");
        }
        (s, existing.unwrap_or_else(|| Descriptor::new(r.clone())), false)
    } else {
        match existing {
            Some(d) if protected => {
                eprintln!("First, approve one of the passkeys already protecting these backups.");
                let out = ceremony::unlock(&d.envelopes)?;
                let env = d.find(&out.credential_id).context("that passkey is not enrolled here")?;
                let s = recovery::unwrap(&d, env, &out.prf_output)?;
                (s, d, profile.is_none())
            }
            Some(_) => bail!("{} has a recovery file with no passkeys", backups.display()),
            None if profile.is_some() => bail!(
                "this profile's backup key is not protected by a passkey yet. Either keep it by \
                 entering its recovery words once (--recovery-words), or start a new key \
                 (--new-key); recorded plays are kept either way"
            ),
            None => {
                let s = phrase::generate()?;
                let d = Descriptor::new(phrase::identity(&s)?.to_public().to_string());
                (s, d, true)
            }
        }
    };

    let salt = recovery::new_salt()?;
    let out = ceremony::enroll(&salt, &descriptor.envelopes)?;
    let envelope =
        recovery::wrap(&secret, &out.rp_id, &out.credential_id, &salt, &out.prf_output)?;
    descriptor.envelopes.push(envelope);
    let check = descriptor.envelopes.last().expect("just pushed");
    recovery::unwrap(&descriptor, check, &out.prf_output)?;

    // Only now that a passkey can unlock the key does anything get saved.
    let older = folder::archives(backups)?.len();
    descriptor.save(backups)?;
    let recipient = phrase::identity(&secret)?.to_public();
    if key_is_new {
        keys::replace_recipient(paths, &recipient)?;
    }
    folder::remember_descriptor(paths, &descriptor)?;
    let mut conn = db::open(&paths.db())?;
    if key_is_new || folder::latest(backups)?.is_none() {
        // File names have one-second precision; make sure this one sorts last.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let file = folder::write_archive_file(&mut conn, &recipient, backups)?;
        println!("wrote backup {}", file.display());
    }
    println!(
        "Passkey added: {} passkey(s) can now unlock the backups in {}.",
        descriptor.envelopes.len(),
        backups.display()
    );
    if new_key && older > 0 {
        println!("{older} older backup(s) in that folder use the previous key; the passkey cannot open them.");
    }
    if descriptor.envelopes.len() == 1 {
        println!("This passkey is the only way to restore. Add a second one when you can:");
        println!("  lighthouse-scrobbler enroll-passkey --backups {}", backups.display());
    }
    Ok(())
}

fn restore(paths: &Paths, from: &Path, recovery_words: bool) -> Result<()> {
    paths.ensure()?;
    let _lock = lock::exclusive(paths)
        .context("stop `run` first (systemctl --user stop lighthouse-scrobbler)")?;
    let descriptor = Descriptor::load(from)?;
    let latest = folder::latest(from)?
        .with_context(|| format!("no backups in {}", from.display()))?;

    let secret = if recovery_words {
        let s = read_words()?;
        if let Some(d) = &descriptor
            && phrase::identity(&s)?.to_public().to_string() != d.recipient
        {
            bail!("those words do not belong to the backups in {}", from.display());
        }
        s
    } else {
        let d = descriptor.as_ref().with_context(|| {
            format!(
                "no {} in {}; to restore with recovery words instead, add --recovery-words",
                recovery::FILE_NAME,
                from.display()
            )
        })?;
        let out = ceremony::unlock(&d.envelopes)?;
        let envelope =
            d.find(&out.credential_id).context("that passkey is not enrolled for these backups")?;
        recovery::unwrap(d, envelope, &out.prf_output)?
    };
    let identity = phrase::identity(&secret)?;
    let recipient = identity.to_public();
    if let Some(r) = profile_recipient(paths)?
        && r != recipient.to_string()
    {
        bail!("this profile already uses a different backup key");
    }
    let mut conn = db::open(&paths.db())?;
    let report = folder::import_file(&mut conn, &identity, &latest)?;
    println!(
        "restored {}: {} added, {} updated, {} already present",
        latest.display(),
        report.added,
        report.updated,
        report.unchanged
    );
    if !paths.recipient().exists() {
        keys::replace_recipient(paths, &recipient)?;
    }
    if let Some(d) = &descriptor {
        folder::remember_descriptor(paths, d)?;
    }
    Ok(())
}

fn show_recovery_words(backups: &Path, batch: bool) -> Result<()> {
    if !batch && !io::stdout().is_terminal() {
        bail!("recovery words are only shown on a terminal");
    }
    let d = Descriptor::load(backups)?
        .with_context(|| format!("no {} in {}", recovery::FILE_NAME, backups.display()))?;
    let out = ceremony::unlock(&d.envelopes)?;
    let env = d.find(&out.credential_id).context("that passkey is not enrolled here")?;
    let secret = recovery::unwrap(&d, env, &out.prf_output)?;
    let words = phrase::words(&secret)?;
    if batch {
        println!("{}", *Zeroizing::new(words.to_string()));
        return Ok(());
    }
    print_words(&words)?;
    println!("\nThese words restore your backups if every passkey is lost:");
    println!("  lighthouse-scrobbler restore --from <backup folder> --recovery-words");
    println!("Keep them somewhere safe and private. You can see them again with your passkey.");
    Ok(())
}

/// Advanced, words-only setup for systems where no passkey works.
fn init(paths: &Paths, batch: bool) -> Result<()> {
    paths.ensure()?;
    if paths.recipient().exists() {
        bail!("already set up: {} exists", paths.recipient().display());
    }
    let secret = phrase::generate()?;
    let words = phrase::words(&secret)?;
    let recipient = phrase::identity(&secret)?.to_public();
    if batch {
        println!("{}", *Zeroizing::new(words.to_string()));
    } else {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("init shows recovery words and needs a terminal (use --batch in scripts)");
        }
        print_words(&words)?;
        print!("\nPress Enter once you have saved them. The screen will be cleared.");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        // Clear the screen and, where the terminal supports it, its scrollback.
        print!("\x1b[2J\x1b[3J\x1b[H");
        io::stdout().flush()?;
        confirm_words(&secret)?;
    }
    // Nothing is saved until the words have been shown (and confirmed).
    keys::replace_recipient(paths, &recipient)?;
    db::open(&paths.db())?;
    if !batch {
        println!("Done. Recording and backups never ask for the words.");
        println!("You can add a passkey later with --recovery-words.");
    }
    Ok(())
}

fn print_words(words: &bip39::Mnemonic) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "\nRecovery words. Anyone with these and your backups can read your listening history.\n")?;
    let list: Vec<&str> = words.words().collect();
    for (r, chunk) in list.chunks(4).enumerate() {
        let cells: Vec<String> =
            chunk.iter().enumerate().map(|(i, w)| format!("{:>2}. {w:<10}", r * 4 + i + 1)).collect();
        writeln!(out, "    {}", cells.join(" "))?;
    }
    Ok(())
}

fn confirm_words(secret: &Secret) -> Result<()> {
    for attempt in 1..=3 {
        match read_words() {
            Ok(s) if *s == **secret => return Ok(()),
            Ok(_) => eprintln!("Those are valid recovery words, but not these ones."),
            Err(e) => eprintln!("{e}"),
        }
        if attempt < 3 {
            eprintln!("Try again ({} attempts left).", 3 - attempt);
        }
    }
    bail!("the words were not confirmed, so nothing was saved; run init again for new words")
}

/// Prompt for recovery words without echo, or read one line from piped stdin.
fn read_words() -> Result<Secret> {
    let typed = Zeroizing::new(if io::stdin().is_terminal() {
        rpassword::prompt_password("Recovery words: ")?
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line
    });
    phrase::parse(&typed)
}

fn list(paths: &Paths, limit: usize) -> Result<()> {
    let conn = db::open(&paths.db())?;
    for l in db::recent(&conn, limit)?.iter().rev() {
        let when = l.started_at.get(..16).unwrap_or(&l.started_at).replace('T', " ");
        let album = l.album.as_deref().map(|a| format!("  [{a}]")).unwrap_or_default();
        println!("{when}Z  {} - {}{album}", l.artist.as_deref().unwrap_or("?"), l.title);
    }
    Ok(())
}

fn stats(paths: &Paths) -> Result<()> {
    let conn = db::open(&paths.db())?;
    let s = db::stats(&conn)?;
    if s.listens == 0 {
        println!("No plays recorded yet.");
        return Ok(());
    }
    println!("{} plays of {} distinct tracks", s.listens, s.distinct_tracks);
    println!("from {} to {}", s.first.unwrap_or_default(), s.last.unwrap_or_default());
    println!(
        "at least {:.1} hours heard across the {} plays whose end was observed",
        s.observed_ms as f64 / 3_600_000.0,
        s.observed_listens
    );
    println!("\ntop artists");
    for (artist, n) in &s.top_artists {
        println!("{n:>6}  {artist}");
    }
    println!("\ntop tracks");
    for (artist, title, n) in &s.top_tracks {
        println!("{n:>6}  {artist} - {title}");
    }
    Ok(())
}
