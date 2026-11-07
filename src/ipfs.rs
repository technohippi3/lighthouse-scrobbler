//! Verified retrieval of files stored on IPFS.
//!
//! Gateways are treated as untrusted. Every block is fetched in raw form
//! (`?format=raw`, the trustless-gateway protocol) and its SHA-256 is checked
//! against the CID that names it before it is used. Files are rebuilt from
//! their UnixFS DAG, so a gateway that is slow, rate-limited or dishonest can
//! stall a restore but can't change what it returns.
//!
//! Supports CIDv0 (`Qm…`) and CIDv1 in base32 (`b…`), the dag-pb and raw
//! codecs, and SHA-256 multihashes, which is what Lighthouse produces.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

pub const DAG_PB: u64 = 0x70;
pub const RAW: u64 = 0x55;
const SHA2_256: u64 = 0x12;
/// Kubo's default chunk size. Lighthouse uses larger chunks; the decoder
/// doesn't care, it follows whatever links a file has.
pub const CHUNK: usize = 256 * 1024;
/// The largest block IPFS peers exchange.
const MAX_BLOCK: u64 = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cid {
    pub version: u8,
    pub codec: u64,
    pub digest: [u8; 32],
}

impl Cid {
    pub fn v0(digest: [u8; 32]) -> Cid {
        Cid { version: 0, codec: DAG_PB, digest }
    }

    pub fn parse(s: &str) -> Result<Cid> {
        let s = s.trim();
        if s.starts_with("Qm") {
            let bytes = bs58::decode(s).into_vec().map_err(|e| anyhow!("bad CID {s}: {e}"))?;
            return Cid::from_bytes(&bytes);
        }
        if let Some(rest) = s.strip_prefix('b') {
            return Cid::from_bytes(&base32_decode(rest).with_context(|| format!("bad CID {s}"))?);
        }
        bail!("unsupported CID encoding: {s}")
    }

    /// From the binary form used inside dag-pb links.
    pub fn from_bytes(b: &[u8]) -> Result<Cid> {
        if b.len() == 34 && b[0] == SHA2_256 as u8 && b[1] == 32 {
            return Ok(Cid::v0(b[2..].try_into().unwrap()));
        }
        let mut pos = 0;
        let version = read_varint(b, &mut pos)?;
        if version != 1 {
            bail!("unsupported CID version {version}");
        }
        let codec = read_varint(b, &mut pos)?;
        let hash = read_varint(b, &mut pos)?;
        let len = read_varint(b, &mut pos)? as usize;
        if hash != SHA2_256 || len != 32 || b.len() != pos + 32 {
            bail!("unsupported multihash in CID");
        }
        Ok(Cid { version: 1, codec, digest: b[pos..].try_into().unwrap() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut mh = vec![SHA2_256 as u8, 32];
        mh.extend_from_slice(&self.digest);
        if self.version == 0 {
            return mh;
        }
        let mut out = Vec::new();
        write_varint(&mut out, 1);
        write_varint(&mut out, self.codec);
        out.extend_from_slice(&mh);
        out
    }

    pub fn verifies(&self, block: &[u8]) -> bool {
        Sha256::digest(block).as_slice() == self.digest
    }
}

impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.version == 0 {
            write!(f, "{}", bs58::encode(self.to_bytes()).into_string())
        } else {
            write!(f, "b{}", base32_encode(&self.to_bytes()))
        }
    }
}

/// Rebuild a file from its root CID. `get` returns a block's bytes; each one
/// is verified here against its CID before it is decoded.
pub fn assemble(
    root: &Cid,
    max_bytes: usize,
    get: &mut dyn FnMut(&Cid) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    walk(root, 0, max_bytes, get, &mut out)?;
    Ok(out)
}

fn walk(
    cid: &Cid,
    depth: usize,
    max_bytes: usize,
    get: &mut dyn FnMut(&Cid) -> Result<Vec<u8>>,
    out: &mut Vec<u8>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("file DAG is too deep");
    }
    let block = get(cid)?;
    if !cid.verifies(&block) {
        bail!("block {cid} does not match its CID");
    }
    match cid.codec {
        RAW => out.extend_from_slice(&block),
        DAG_PB => {
            let node = decode_node(&block)?;
            if let Some(data) = node.data {
                let fs = decode_unixfs(data)?;
                if fs.kind != 0 && fs.kind != 2 {
                    bail!("block {cid} is not a file");
                }
                out.extend_from_slice(fs.data);
            }
            for link in node.links {
                walk(&Cid::from_bytes(link)?, depth + 1, max_bytes, get, out)?;
            }
        }
        other => bail!("unsupported codec 0x{other:x}"),
    }
    if out.len() > max_bytes {
        bail!("file is larger than {max_bytes} bytes");
    }
    Ok(())
}

struct Node<'a> {
    links: Vec<&'a [u8]>,
    data: Option<&'a [u8]>,
}

struct UnixFs<'a> {
    kind: u64,
    data: &'a [u8],
}

fn decode_node(block: &[u8]) -> Result<Node<'_>> {
    let mut node = Node { links: vec![], data: None };
    for (field, value) in fields(block)? {
        match (field, value) {
            (1, Field::Bytes(b)) => node.data = Some(b),
            (2, Field::Bytes(link)) => {
                let hash = fields(link)?
                    .into_iter()
                    .find_map(|(f, v)| match (f, v) {
                        (1, Field::Bytes(h)) => Some(h),
                        _ => None,
                    })
                    .context("dag-pb link without a hash")?;
                node.links.push(hash);
            }
            _ => {}
        }
    }
    Ok(node)
}

fn decode_unixfs(data: &[u8]) -> Result<UnixFs<'_>> {
    let mut fs = UnixFs { kind: u64::MAX, data: &[] };
    for (field, value) in fields(data)? {
        match (field, value) {
            (1, Field::Varint(t)) => fs.kind = t,
            (2, Field::Bytes(b)) => fs.data = b,
            _ => {}
        }
    }
    Ok(fs)
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn fields(buf: &[u8]) -> Result<Vec<(u64, Field<'_>)>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let key = read_varint(buf, &mut pos)?;
        match key & 7 {
            0 => out.push((key >> 3, Field::Varint(read_varint(buf, &mut pos)?))),
            2 => {
                let len = read_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(len).filter(|&e| e <= buf.len()).context("truncated block")?;
                out.push((key >> 3, Field::Bytes(&buf[pos..end])));
                pos = end;
            }
            other => bail!("unsupported protobuf wire type {other}"),
        }
    }
    Ok(out)
}

fn read_varint(b: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*pos).context("truncated varint")?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("varint too long")
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_lowercase()).context("bad base32")? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Encode a file the way Kubo does by default (CIDv0, 256 KiB chunks,
/// dag-pb leaves, one level of links). Used to check CIDs and by tests that
/// stand in for Lighthouse. Returns the root CID and every block.
pub fn encode_file(bytes: &[u8]) -> (Cid, Vec<(Cid, Vec<u8>)>) {
    encode_file_with(bytes, CHUNK)
}

/// As `encode_file`, with a chosen chunk size.
pub fn encode_file_with(bytes: &[u8], chunk: usize) -> (Cid, Vec<(Cid, Vec<u8>)>) {
    fn unixfs(data: &[u8], filesize: usize, blocksizes: &[usize]) -> Vec<u8> {
        let mut v = vec![0x08, 0x02];
        if !data.is_empty() {
            v.push(0x12);
            write_varint(&mut v, data.len() as u64);
            v.extend_from_slice(data);
        }
        v.push(0x18);
        write_varint(&mut v, filesize as u64);
        for &b in blocksizes {
            v.push(0x20);
            write_varint(&mut v, b as u64);
        }
        v
    }
    fn node(links: &[(Cid, usize)], data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        for (cid, tsize) in links {
            let mut link = vec![0x0a];
            let h = cid.to_bytes();
            write_varint(&mut link, h.len() as u64);
            link.extend_from_slice(&h);
            link.extend_from_slice(&[0x12, 0x00, 0x18]);
            write_varint(&mut link, *tsize as u64);
            v.push(0x12);
            write_varint(&mut v, link.len() as u64);
            v.extend_from_slice(&link);
        }
        v.push(0x0a);
        write_varint(&mut v, data.len() as u64);
        v.extend_from_slice(data);
        v
    }
    let block_of = |b: Vec<u8>| (Cid::v0(Sha256::digest(&b).into()), b);
    if bytes.len() <= chunk {
        let (cid, b) = block_of(node(&[], &unixfs(bytes, bytes.len(), &[])));
        return (cid.clone(), vec![(cid, b)]);
    }
    let mut blocks = Vec::new();
    let mut links = Vec::new();
    let mut sizes = Vec::new();
    for piece in bytes.chunks(chunk) {
        let (cid, b) = block_of(node(&[], &unixfs(piece, piece.len(), &[])));
        links.push((cid.clone(), b.len()));
        sizes.push(piece.len());
        blocks.push((cid, b));
    }
    let (root, b) = block_of(node(&links, &unixfs(&[], bytes.len(), &sizes)));
    blocks.push((root.clone(), b));
    (root, blocks)
}

/// Fetches blocks from a list of gateways, trying each in turn.
pub struct Gateways {
    bases: Vec<String>,
    agent: ureq::Agent,
}

pub const DEFAULT_GATEWAYS: &[&str] = &[
    "https://gateway.lighthouse.storage",
    "https://trustless-gateway.link",
    "https://ipfs.io",
    "https://dweb.link",
    "https://w3s.link",
];

impl Gateways {
    /// `LIGHTHOUSE_SCROBBLER_GATEWAYS` (comma-separated) overrides the defaults.
    pub fn from_env() -> Gateways {
        let bases = std::env::var("LIGHTHOUSE_SCROBBLER_GATEWAYS")
            .ok()
            .map(|s| s.split(',').map(|g| g.trim().trim_end_matches('/').to_string()).filter(|g| !g.is_empty()).collect())
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_GATEWAYS.iter().map(|s| s.to_string()).collect());
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .build()
            .into();
        Gateways { bases, agent }
    }

    /// Fetch and verify a whole file.
    pub fn fetch_file(&mut self, root: &Cid, max_bytes: usize) -> Result<Vec<u8>> {
        assemble(root, max_bytes, &mut |cid| self.fetch_block(cid))
    }

    fn fetch_block(&mut self, cid: &Cid) -> Result<Vec<u8>> {
        let mut errors = Vec::new();
        for attempt in 0..3 {
            for i in 0..self.bases.len() {
                let base = &self.bases[i];
                let url = format!("{base}/ipfs/{cid}?format=raw");
                match self.agent.get(&url).header("Accept", "application/vnd.ipld.raw").call() {
                    Ok(mut r) if r.status().as_u16() == 200 => {
                        let block = r.body_mut().with_config().limit(MAX_BLOCK).read_to_vec()?;
                        if cid.verifies(&block) {
                            // Try the gateway that worked first next time.
                            self.bases.swap(0, i);
                            return Ok(block);
                        }
                        errors.push(format!("{base}: returned a block that doesn't match"));
                    }
                    Ok(r) => errors.push(format!("{base}: HTTP {}", r.status())),
                    Err(e) => errors.push(format!("{base}: {e}")),
                }
            }
            std::thread::sleep(Duration::from_secs(2u64.pow(attempt + 1)));
        }
        errors.dedup();
        Err(anyhow!("no gateway returned block {cid}: {}", errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_round_trips() {
        for s in [
            "QmapMmLhoJ7Cfq84o2xuB162pFqXUYYpBQ1ybhL4ztGw6h",
            "bafybeia6yiw7qurpkkapxl7aal3t6r6toopmb6i5tcs7dt2agrhnzkdocm",
        ] {
            assert_eq!(Cid::parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn small_and_large_files_rebuild_and_verify() {
        for len in [0, 10, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let (root, blocks) = encode_file(&data);
            let map: std::collections::HashMap<_, _> =
                blocks.iter().map(|(c, b)| (c.to_string(), b.clone())).collect();
            let got = assemble(&root, usize::MAX, &mut |c| {
                map.get(&c.to_string()).cloned().context("missing")
            })
            .unwrap();
            assert_eq!(got, data, "len {len}");
        }
    }

    #[test]
    fn tampered_block_is_refused() {
        let (root, blocks) = encode_file(b"hello");
        let mut bad = blocks[0].1.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(assemble(&root, usize::MAX, &mut |_| Ok(bad.clone())).is_err());
    }
}
