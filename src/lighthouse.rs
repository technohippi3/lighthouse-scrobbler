//! The Lighthouse destination.
//!
//! A sync uploads, in this order:
//! 1. an incremental batch: the listens added or changed since the last batch
//!    this destination accepted, in the ordinary archive format;
//! 2. the passkey recovery file, if it changed;
//! 3. a manifest listing every batch and the current recovery file by CID.
//!
//! The manifest goes up only after everything it references is up. A fresh
//! machine lists the account's files, takes the newest manifest, and rebuilds
//! the history from what it lists. Every download is verified against its
//! CID (see `ipfs`), so the files may come from any gateway. The manifest is
//! plain JSON. It reveals file sizes, counts and times, which Lighthouse
//! already knows, and nothing about listens.
//!
//! What has been uploaded is recorded in the `remote_files` table, apart
//! from listen records. A failed upload records nothing, so the next sync
//! retries it.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;

use crate::backup;
use crate::folder;
use crate::ipfs::{self, Cid};
use crate::keys;
use crate::paths::Paths;
use crate::recovery::Descriptor;

pub const DESTINATION: &str = "lighthouse";
pub const MANIFEST_FORMAT: &str = "lighthouse-scrobbler-manifest";
pub const MANIFEST_VERSION: u32 = 1;
/// Every file this app uploads starts with this; nothing else is ever read
/// or touched in the account.
pub const NAME_PREFIX: &str = "lhs-";
const MAX_FILE: usize = 256 * 1024 * 1024;

pub fn key_path(paths: &Paths) -> PathBuf {
    paths.config.join("lighthouse-api-key")
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileRef {
    pub cid: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BatchRef {
    #[serde(flatten)]
    pub file: FileRef,
    pub records: u64,
}

/// A complete inventory of what is needed to rebuild the history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub version: u32,
    pub created_at: String,
    /// The age recipient every batch is encrypted to.
    pub recipient: String,
    pub stream_id: String,
    /// Oldest first. Importing them in order rebuilds the history.
    pub batches: Vec<BatchRef>,
    pub recovery: Option<FileRef>,
}

pub struct Client {
    key: String,
    api: String,
    upload: String,
    agent: ureq::Agent,
}

#[derive(Debug, Deserialize)]
pub struct Uploaded {
    pub id: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
    pub cid: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

impl Client {
    /// The API key comes from the profile's key file. The endpoints can be
    /// pointed elsewhere for tests.
    pub fn from_paths(paths: &Paths) -> Result<Client> {
        let path = key_path(paths);
        let key = fs::read_to_string(&path)
            .with_context(|| {
                format!("no Lighthouse API key; run `lighthouse-scrobbler lighthouse-key` ({} missing)", path.display())
            })?
            .trim()
            .to_string();
        if key.is_empty() {
            bail!("{} is empty", path.display());
        }
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Ok(Client {
            key,
            api: env("LIGHTHOUSE_SCROBBLER_LIGHTHOUSE_API", "https://api.lighthouse.storage"),
            upload: env("LIGHTHOUSE_SCROBBLER_LIGHTHOUSE_UPLOAD", "https://upload.lighthouse.storage"),
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(300)))
                .http_status_as_error(false)
                .build()
                .into(),
        })
    }

    /// Upload one file and return its CID.
    pub fn upload(&self, name: &str, bytes: &[u8]) -> Result<String> {
        let boundary = format!("lhs-{}", crate::recovery::random_b64(18)?);
        let mut body = Vec::with_capacity(bytes.len() + 512);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut resp = self
            .agent
            .post(&format!("{}/api/v0/add", self.upload))
            .header("Authorization", &format!("Bearer {}", self.key))
            .header("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
            .send(&body[..])
            .map_err(|e| anyhow!("uploading {name} to Lighthouse: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        if status != 200 {
            bail!("Lighthouse refused {name}: HTTP {status}: {}", text.chars().take(200).collect::<String>());
        }
        #[derive(Deserialize)]
        struct Added {
            #[serde(rename = "Hash")]
            hash: String,
        }
        let added: Added = serde_json::from_str(&text).context("unexpected Lighthouse upload response")?;
        Ok(added.hash)
    }

    /// Every file in the account whose name this app owns.
    pub fn list_ours(&self) -> Result<Vec<Uploaded>> {
        #[derive(Deserialize)]
        struct Page {
            #[serde(rename = "fileList", default)]
            files: Vec<Uploaded>,
        }
        let mut out: Vec<Uploaded> = Vec::new();
        let mut last = String::from("null");
        for _ in 0..1000 {
            let url = format!("{}/api/user/files_uploaded?lastKey={last}", self.api);
            let mut resp = self
                .agent
                .get(&url)
                .header("Authorization", &format!("Bearer {}", self.key))
                .call()
                .map_err(|e| anyhow!("listing Lighthouse files: {e}"))?;
            if resp.status().as_u16() != 200 {
                bail!("Lighthouse refused the file listing: HTTP {}", resp.status());
            }
            let page: Page = serde_json::from_str(&resp.body_mut().read_to_string()?)
                .context("unexpected Lighthouse listing")?;
            let before = out.len();
            let next = page.files.last().map(|f| f.id.clone());
            for f in page.files {
                if !out.iter().any(|o| o.id == f.id) {
                    out.push(f);
                }
            }
            match next {
                Some(id) if out.len() > before && id != last => last = id,
                _ => break,
            }
        }
        out.retain(|f| f.file_name.starts_with(NAME_PREFIX));
        Ok(out)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn stamp(now: OffsetDateTime) -> Result<String> {
    Ok(now.format(format_description!("[year][month][day]T[hour][minute][second]Z"))?)
}

/// A file uploaded to a destination, as recorded locally.
struct Remote {
    name: String,
    kind: String,
    file: FileRef,
    records: Option<u64>,
    max_change_seq: Option<u64>,
}

fn remotes(conn: &Connection) -> Result<Vec<Remote>> {
    let mut stmt = conn.prepare(
        "SELECT name, kind, cid, sha256, size, records, max_change_seq FROM remote_files
         WHERE destination = ?1 ORDER BY uploaded_at, name",
    )?;
    let rows = stmt.query_map([DESTINATION], |r| {
        Ok(Remote {
            name: r.get(0)?,
            kind: r.get(1)?,
            file: FileRef { cid: r.get(2)?, sha256: r.get(3)?, size: r.get::<_, i64>(4)? as u64 },
            records: r.get::<_, Option<i64>>(5)?.map(|n| n as u64),
            max_change_seq: r.get::<_, Option<i64>>(6)?.map(|n| n as u64),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn record(conn: &Connection, r: &Remote) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO remote_files
         (destination, name, kind, cid, sha256, size, records, max_change_seq, uploaded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            DESTINATION,
            r.name,
            r.kind,
            r.file.cid,
            r.file.sha256,
            r.file.size as i64,
            r.records.map(|n| n as i64),
            r.max_change_seq.map(|n| n as i64),
            OffsetDateTime::now_utc().format(&Rfc3339)?,
        ],
    )?;
    Ok(())
}

pub struct SyncReport {
    pub batch: Option<(String, u64)>,
    pub recovery_uploaded: bool,
    pub manifest: Option<String>,
}

/// Upload whatever Lighthouse doesn't have yet.
pub fn sync(conn: &mut Connection, paths: &Paths) -> Result<SyncReport> {
    let client = Client::from_paths(paths)?;
    let recipient = keys::load_recipient(paths)?;
    let stream = crate::install::stream_id(paths)?;
    let short = stream.chars().take(8).collect::<String>();
    let now = OffsetDateTime::now_utc();
    let have = remotes(conn)?;
    let since = have.iter().filter_map(|r| r.max_change_seq).max().unwrap_or(0);
    let mut report = SyncReport { batch: None, recovery_uploaded: false, manifest: None };
    let mut changed = false;

    // 1. Batch of new and changed listens.
    let written = backup::write_archive(conn, &recipient, Cursor::new(Vec::new()), now, since)?;
    if written.records > 0 {
        let bytes = written.out.into_inner();
        // Names must be unique even for syncs within the same second.
        let name = format!(
            "{NAME_PREFIX}batch-{short}-{:010}-{}.age",
            written.max_change_seq,
            stamp(now)?
        );
        let cid = upload_checked(&client, &name, &bytes)?;
        record(
            conn,
            &Remote {
                name,
                kind: "batch".into(),
                file: FileRef { cid: cid.clone(), sha256: sha256_hex(&bytes), size: bytes.len() as u64 },
                records: Some(written.records),
                max_change_seq: Some(written.max_change_seq),
            },
        )?;
        report.batch = Some((cid, written.records));
        changed = true;
    }

    // 2. The recovery file, when it differs from the last one uploaded.
    let descriptor = folder::profile_descriptor(paths, None)?;
    if let Some(d) = &descriptor {
        let bytes = serde_json::to_vec_pretty(d)?;
        let sha = sha256_hex(&bytes);
        let current = have.iter().rev().find(|r| r.kind == "recovery");
        if current.is_none_or(|r| r.file.sha256 != sha) {
            let name = format!("{NAME_PREFIX}recovery-{short}-{}-{}.json", &sha[..12], stamp(now)?);
            let cid = upload_checked(&client, &name, &bytes)?;
            record(
                conn,
                &Remote {
                    name,
                    kind: "recovery".into(),
                    file: FileRef { cid, sha256: sha, size: bytes.len() as u64 },
                    records: None,
                    max_change_seq: None,
                },
            )?;
            report.recovery_uploaded = true;
            changed = true;
        }
    }

    // 3. A complete manifest, only after everything it lists is up.
    let have = remotes(conn)?;
    if changed || !have.iter().any(|r| r.kind == "manifest") {
        let batches: Vec<BatchRef> = have
            .iter()
            .filter(|r| r.kind == "batch")
            .map(|r| BatchRef { file: r.file.clone(), records: r.records.unwrap_or(0) })
            .collect();
        if batches.is_empty() && descriptor.is_none() {
            return Ok(report); // nothing to describe yet
        }
        let manifest = Manifest {
            format: MANIFEST_FORMAT.into(),
            version: MANIFEST_VERSION,
            created_at: now.format(&Rfc3339)?,
            recipient: recipient.to_string(),
            stream_id: stream,
            batches,
            recovery: have.iter().rev().find(|r| r.kind == "recovery").map(|r| r.file.clone()),
        };
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        let number = have.iter().filter(|r| r.kind == "manifest").count() + 1;
        let name = format!("{NAME_PREFIX}manifest-{short}-{number:08}-{}.json", stamp(now)?);
        let cid = upload_checked(&client, &name, &bytes)?;
        record(
            conn,
            &Remote {
                name,
                kind: "manifest".into(),
                file: FileRef { cid: cid.clone(), sha256: sha256_hex(&bytes), size: bytes.len() as u64 },
                records: None,
                max_change_seq: None,
            },
        )?;
        report.manifest = Some(cid);
    }
    Ok(report)
}

/// Upload and, where the layout is known (one block), check that Lighthouse
/// named the content we sent.
fn upload_checked(client: &Client, name: &str, bytes: &[u8]) -> Result<String> {
    let cid = client.upload(name, bytes)?;
    let parsed = Cid::parse(&cid).with_context(|| format!("Lighthouse returned an unusable CID for {name}"))?;
    if bytes.len() <= 512 * 1024 {
        let (expected, _) = ipfs::encode_file_with(bytes, 1024 * 1024);
        if parsed != expected {
            bail!("Lighthouse's CID for {name} doesn't match its content");
        }
    }
    Ok(cid)
}

/// What a fresh machine needs: the newest manifest and the recovery file it
/// names, both downloaded and verified.
pub struct Found {
    pub manifest: Manifest,
    pub descriptor: Option<Descriptor>,
}

pub fn find_latest(paths: &Paths, gateways: &mut ipfs::Gateways) -> Result<Found> {
    let client = Client::from_paths(paths)?;
    let mut manifests: Vec<Uploaded> = client
        .list_ours()?
        .into_iter()
        .filter(|f| f.file_name.starts_with(&format!("{NAME_PREFIX}manifest-")))
        .collect();
    manifests.sort_by_key(|f| (f.created_at, f.file_name.clone()));
    let newest = manifests.pop().context("no lighthouse-scrobbler backups in this Lighthouse account")?;
    eprintln!("using manifest {} ({})", newest.file_name, newest.cid);
    let bytes = gateways.fetch_file(&Cid::parse(&newest.cid)?, MAX_FILE)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).context("bad manifest")?;
    if manifest.format != MANIFEST_FORMAT || manifest.version != MANIFEST_VERSION {
        bail!("unsupported manifest {} v{}", manifest.format, manifest.version);
    }
    let descriptor = match &manifest.recovery {
        Some(r) => {
            let bytes = fetch_ref(gateways, r)?;
            let d: Descriptor = serde_json::from_slice(&bytes).context("bad recovery file")?;
            if d.recipient != manifest.recipient {
                bail!("the recovery file belongs to a different key than the manifest");
            }
            Some(d)
        }
        None => None,
    };
    Ok(Found { manifest, descriptor })
}

/// Download a file the manifest lists and check it against the manifest too.
pub fn fetch_ref(gateways: &mut ipfs::Gateways, r: &FileRef) -> Result<Vec<u8>> {
    let bytes = gateways.fetch_file(&Cid::parse(&r.cid)?, MAX_FILE)?;
    if sha256_hex(&bytes) != r.sha256 || bytes.len() as u64 != r.size {
        bail!("{} doesn't match the manifest", r.cid);
    }
    Ok(bytes)
}

/// After restoring from a manifest, remember that Lighthouse already holds
/// all of it, so the next sync sends only plays recorded from now on.
pub fn adopt(conn: &Connection, manifest: &Manifest) -> Result<()> {
    let watermark = crate::db::max_change_seq(conn)?;
    for (i, b) in manifest.batches.iter().enumerate() {
        record(
            conn,
            &Remote {
                name: format!("{NAME_PREFIX}restored-batch-{i:05}-{}", b.file.cid),
                kind: "batch".into(),
                file: b.file.clone(),
                records: Some(b.records),
                max_change_seq: Some(if i + 1 == manifest.batches.len() { watermark } else { 0 }),
            },
        )?;
    }
    if let Some(r) = &manifest.recovery {
        record(
            conn,
            &Remote {
                name: format!("{NAME_PREFIX}restored-recovery-{}", r.cid),
                kind: "recovery".into(),
                file: r.clone(),
                records: None,
                max_change_seq: None,
            },
        )?;
    }
    Ok(())
}
