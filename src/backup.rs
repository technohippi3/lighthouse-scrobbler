//! The backup archive format, independent of where archives are stored.
//!
//! Format: a JSON header line followed by one listen per line (JSONL),
//! compressed with zstd (with checksum), encrypted with age to the profile's
//! recipient. Both directions stream: rows go from one SQLite read
//! transaction through the encoders into any writer, and records come from
//! any reader through the decoders into one write transaction. Memory use
//! does not grow with the size of the history. Storage concerns such as
//! temporary files, permissions, renames and provider addresses belong to the
//! destination (see `folder`).

use std::io::{BufRead, BufReader, Read, Write};
use std::iter;

use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::db::{self, Listen};

pub const FORMAT: &str = "lighthouse-scrobbler-export";
pub const VERSION: u32 = 1;
const ZSTD_LEVEL: i32 = 9;

#[derive(Serialize, Deserialize)]
struct Header {
    format: String,
    version: u32,
    created_at: String,
    count: u64,
}

pub struct Written<W> {
    pub out: W,
    pub records: u64,
    /// The newest change marker included, or `since` if nothing was.
    pub max_change_seq: u64,
}

/// Stream listens added or changed after `since` (0 for the whole history),
/// encrypted to `recipient`, into `out`, and hand `out` back once every layer
/// is finished. Plaintext exists only in memory buffers. A full snapshot and
/// an incremental batch are the same format; importing merges by UUID.
pub fn write_archive<W: Write>(
    conn: &mut Connection,
    recipient: &Recipient,
    out: W,
    created_at: OffsetDateTime,
    since: u64,
) -> Result<Written<W>> {
    // The count and the rows come from the same consistent snapshot, even
    // while the recorder keeps writing.
    let tx = conn.transaction()?;
    let count = db::count_since(&tx, since)?;

    let encryptor = age::Encryptor::with_recipients(iter::once(recipient as &dyn age::Recipient))?;
    let encrypted = encryptor.wrap_output(out)?;
    let mut zstd = zstd::Encoder::new(encrypted, ZSTD_LEVEL)?;
    zstd.include_checksum(true)?;

    let header = Header {
        format: FORMAT.into(),
        version: VERSION,
        created_at: created_at.format(&Rfc3339)?,
        count,
    };
    serde_json::to_writer(&mut zstd, &header)?;
    zstd.write_all(b"\n")?;
    let mut written = 0u64;
    let mut max_change_seq = since;
    db::for_each_since(&tx, since, |listen, seq| {
        serde_json::to_writer(&mut zstd, &listen)?;
        zstd.write_all(b"\n")?;
        written += 1;
        max_change_seq = max_change_seq.max(seq);
        Ok(())
    })?;
    tx.finish()?;
    if written != count {
        bail!("history changed while exporting ({count} counted, {written} written)");
    }

    let encrypted = zstd.finish()?;
    Ok(Written { out: encrypted.finish()?, records: written, max_change_seq })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub added: usize,
    pub updated: usize,
    pub unchanged: usize,
}

/// Decrypt, validate and merge an archive inside one write transaction.
/// Records are merged as they stream in; the transaction commits only after
/// the whole archive has been read, its record count checked and age has
/// authenticated the final chunk. Any error (wrong key, truncation,
/// corruption, conflicting records) rolls everything back.
pub fn import_archive<R: Read>(
    conn: &mut Connection,
    identity: &Identity,
    input: R,
) -> Result<ImportReport> {
    let decryptor = age::Decryptor::new(BufReader::new(input)).context("not an age-encrypted backup")?;
    let decrypted = decryptor
        .decrypt(iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow!("cannot decrypt this backup with this key: {e}"))?;
    let mut lines = BufReader::new(zstd::Decoder::new(decrypted)?);

    let mut line = String::new();
    lines.read_line(&mut line).context("reading backup header")?;
    let header: Header = serde_json::from_str(&line).context("bad backup header")?;
    if header.format != FORMAT {
        bail!("not a lighthouse-scrobbler backup");
    }
    if header.version != VERSION {
        bail!("backup format version {} is not supported", header.version);
    }

    let tx = conn.transaction()?;
    let mut report = ImportReport::default();
    let mut conflicts = Vec::new();
    let mut seen = 0u64;
    loop {
        line.clear();
        if lines.read_line(&mut line).context("reading backup")? == 0 {
            break;
        }
        seen += 1;
        let listen: Listen = serde_json::from_str(&line)
            .with_context(|| format!("bad record on line {}", seen + 1))?;
        listen.validate()?;
        match db::get(&tx, &listen.id)? {
            None => {
                db::insert(&tx, &listen)?;
                report.added += 1;
            }
            Some(existing) if existing.same_play(&listen) => {
                let newer = listen
                    .observed_listened_ms
                    .filter(|&ms| existing.observed_listened_ms.is_none_or(|have| ms > have));
                match newer {
                    Some(ms) => {
                        db::set_observed(&tx, &listen.id, ms)?;
                        report.updated += 1;
                    }
                    None => report.unchanged += 1,
                }
            }
            Some(_) => {
                if conflicts.len() < 5 {
                    conflicts.push(listen.id.clone());
                }
            }
        }
    }
    if seen != header.count {
        bail!("backup is incomplete: header says {} records, found {seen}", header.count);
    }
    // Drain to the very end so age authenticates the final chunk.
    let mut rest = Vec::new();
    lines.into_inner().finish().read_to_end(&mut rest).context("verifying backup")?;
    if !rest.is_empty() {
        bail!("unexpected data after the end of the backup");
    }
    if !conflicts.is_empty() {
        bail!(
            "records in the backup differ from local records with the same id \
             (for example {}); nothing was imported",
            conflicts.join(", ")
        );
    }
    tx.commit()?;
    Ok(report)
}
