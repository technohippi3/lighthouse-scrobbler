//! Record Rhythmbox plays to a local SQLite history with encrypted backups
//! that a passkey unlocks. Recording and backups perform no outbound network
//! operations; passkey ceremonies use only a local loopback page.

pub mod backup;
pub mod ceremony;
pub mod daemon;
pub mod db;
pub mod folder;
pub mod install;
pub mod ipfs;
pub mod keys;
pub mod lighthouse;
pub mod lock;
pub mod mpris;
pub mod paths;
pub mod phrase;
pub mod recovery;
pub mod tracker;
