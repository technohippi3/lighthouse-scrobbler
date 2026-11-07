//! Print the CID Kubo (and Lighthouse) would give a file:
//! `cargo run --example cid -- <file> [chunk-size]`.
fn main() {
    let path = std::env::args().nth(1).expect("usage: cid <file>");
    let bytes = std::fs::read(&path).expect("read file");
    let chunk = std::env::args().nth(2).map(|c| c.parse().expect("chunk size")).unwrap_or(lighthouse_scrobbler::ipfs::CHUNK);
    let (root, blocks) = lighthouse_scrobbler::ipfs::encode_file_with(&bytes, chunk);
    println!("{root}  ({} block(s))", blocks.len());
}
