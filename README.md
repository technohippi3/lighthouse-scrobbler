# lighthouse-scrobbler

Records what you play in Rhythmbox to a local SQLite history and writes
encrypted backups of it that a passkey unlocks. Recording and backups perform
no outbound network operations.
A backup folder that you sync elsewhere will upload the ciphertext on its own,
but nothing in this program talks to the network.

## How a play is counted

The daemon watches `org.mpris.MediaPlayer2.rhythmbox` on the session bus and
ignores every other player, including browsers. It counts time only while
Rhythmbox reports `Playing`, using a monotonic clock. That clock does not
advance during suspend on Linux, and seeking does not add time.

A play is recorded once its listening time crosses a threshold. For a track
longer than 30 seconds, the threshold is half the track or four minutes,
whichever is shorter. When the duration is unknown, such as for internet radio,
the threshold is four minutes and the metadata must include an artist and a
title. Tracks of 30 seconds or less are never recorded. The row is written the
moment the play qualifies. When the play ends, its observed listening time is
added. If the daemon stops mid-play, that figure is a lower bound.

Only a new `mpris:trackid` starts a new play. Metadata-only updates for the same track,
which Rhythmbox sometimes sends twice, change nothing.

Some cases are deliberately not handled. A track that is already playing past
its first two seconds when the daemon starts is skipped, because a restart must
never record a song twice. Playing the same track twice in a row with nothing in
between looks identical to seeking back, so it counts once.

## Setup

```bash
cargo install --path .
```

```bash
lighthouse-scrobbler enroll-passkey --backups /path/to/backup/folder
```

That command opens your browser and asks you to create a passkey. Choose "Use
a security key" for a YubiKey or similar, or "Use this device or a phone" for
other providers that support the WebAuthn PRF extension. A security key needs
a free discoverable-credential slot. That passkey is the whole setup: no password and no
recovery words. The command writes the recovery file and a first backup into
the folder. Pick a folder that is not on this machine's own disk, such as an
external drive or a synced folder.

Run the same command again to add a second passkey. You approve an existing
one first, then choose a different provider or key. Do this: with a single
hardware key, losing the key loses the backups.

```bash
mkdir -p ~/.config/systemd/user && cp contrib/systemd/* ~/.config/systemd/user/
```

Point the `--to` folder in `lighthouse-scrobbler-export.service` at the same
backup folder, then enable both units:

```bash
systemctl --user daemon-reload && systemctl --user enable --now lighthouse-scrobbler.service lighthouse-scrobbler-export.timer
```

## Everyday use

```bash
lighthouse-scrobbler list -n 30
```

```bash
lighthouse-scrobbler stats
```

```bash
journalctl --user -u lighthouse-scrobbler -f
```

`list`, `stats` and `export` are safe while the daemon is recording. Recording
and the daily backups never ask for anything. They use only the public half of
the backup key.

## Restore

On a new machine, or after wiping this one, stop the daemon if it is running:

```bash
systemctl --user stop lighthouse-scrobbler
```

```bash
lighthouse-scrobbler restore --from /path/to/backup/folder
```

`restore` reads the recovery file, asks for any enrolled passkey, and restores
the newest backup in the folder.

Restore merges records by ID inside one transaction. Running it again changes
nothing, and a later snapshot only fills in observed listening times. A
truncated, corrupted or wrongly keyed file imports nothing. So does a record
that conflicts with a local one: the restore refuses rather than choosing.
When the profile is empty, restore also sets up its backup key, so new backups
continue where the old machine left off.

## Backup sets

A backup set is a folder holding encrypted archives together with the current
passkey recovery file. Every export writes both. The profile keeps its own
copy of the recovery file, so exporting to any folder, such as a second drive
or a synced folder, produces a set that restores on its own. Copying a folder
anywhere and running `restore --from` on the copy needs nothing else: no
storage account, no provider tools, and not the original machine. Exporting
into a folder that holds another profile's recovery file is refused, so two
profiles' sets don't get mixed.

Each archive is a complete snapshot named `scrobbles-<UTC time>.jsonl.zst.age`.
It holds a JSON header line and one record per line, compressed with zstd and
encrypted with [age](https://age-encryption.org). Export and restore both
stream: export reads rows from one SQLite read transaction, and restore merges
records into one write transaction that commits only after the whole archive
has checked out. Memory use stays flat. Measured with 200,000 plays, export
peaked at about 23 MiB and restore at about 14 MiB, against 17 MiB for a
100-play export, and the archive was 3.1 MB. Plaintext is never written to
disk. A failed export removes its partial file and leaves earlier archives
alone.

The archive format belongs to neither the database nor any destination. In
the code, `src/backup.rs` reads and writes archives as streams, and
`src/folder.rs` is the folder destination, the only one so far. It handles
temporary files, permissions, atomic renames and the recovery file. Playback
tracking and the database know nothing about storage.

## Fallback: recovery words

Passkeys are the normal path, and nothing asks for words along the way. Every
backup key does have a 12-word form as well, which you can keep as a paper
backup in case every passkey is lost:

```bash
lighthouse-scrobbler recovery-words --backups /path/to/backup/folder
```

That command asks for your passkey, then shows the words. To restore with them
instead of a passkey:

```bash
lighthouse-scrobbler restore --from /path/to/backup/folder --recovery-words
```

Anyone with the words and your backups can read your history.
`check-recovery-words` confirms that a saved set belongs to this profile.

Some systems have no working passkey. On those, `init` sets up backups with
words only, and a passkey can be added later with
`enroll-passkey --recovery-words`. A profile set up that way, like ones from
earlier versions, gets two choices when it moves to passkeys. With
`--recovery-words` it enters the words once and keeps its key, so existing
backups stay valid. With `--new-key` it starts a new key; recorded plays are
kept and go into the next backup.

## How the keys fit together

Each profile has one random 128-bit recovery secret. The age backup key is
derived from it with a frozen, documented scheme, which has test vectors in
[docs/recovery-phrase.md](docs/recovery-phrase.md). Each passkey wraps that
secret independently, using a key derived from its WebAuthn PRF output. The
wrapped copies sit in `lighthouse-scrobbler-recovery.json` next to the
backups, so the folder plus any one passkey is enough to restore. Adding a
passkey never re-encrypts backups. Enrollment refuses providers that return no
PRF output and saves nothing in that case.

## The passkey page

Passkeys belong to a website's domain. The ceremony page is a static page on
a Cloudflare Worker, currently the staging host
`lhs-passkey-staging.piratesocialclub.workers.dev`; its source is in
[web/](web/). It is the same `src/ceremony.html` the app serves itself in
`localhost` mode, which tests use. The app passes the session parameters in
the URL fragment, which browsers never send to the server. The page encrypts
its result to a throwaway key held only by the app: X25519, HKDF-SHA256 and
AES-256-GCM, bound to the session and the page origin. It then drops the
result in a one-shot mailbox on the same site. The app long-polls that
mailbox over HTTPS, and the mailbox empties once read or after ten minutes.
The Worker therefore only ever handles ciphertext and random IDs. Recording
and scheduled backups never contact it.

Two limits remain. Passkeys made on the staging host stay bound to it, so
shipping needs a domain we control, and moving to it means enrolling again.
And recovery is not proven until a restore succeeds on a different computer;
see [docs/passkey-compatibility.md](docs/passkey-compatibility.md).

## Files

With the default XDG locations, the history database is
`~/.local/share/lighthouse-scrobbler/history.sqlite` and the public backup key
is `~/.config/lighthouse-scrobbler/backup-recipient.txt`. Both directories are
owner-only (`0700`), and the program runs with umask `077`. Full-disk encryption such as LUKS
protects the database while the disk is locked; file permissions protect it
while you are logged in.

Setting `LIGHTHOUSE_SCROBBLER_HOME=/some/dir` puts the whole profile under
that directory, which is useful for testing.

## Tests

`cargo test` covers the play-counting rules, the archive format and its
frozen fixtures, recovery words, the passkey handoff with a simulated browser
for both the local and hosted transports, and backup-set portability.
`tests/daemon.rs` runs the real daemon on a private `dbus-daemon` against a
fake Rhythmbox that behaves like the real one: one signal per change,
repeated metadata, and stray `Volume` entries. It checks pauses, duplicate
metadata, track changes, the player quitting and coming back, starting
mid-track, and a clean stop on SIGTERM. That test takes about 35 seconds of
real time. Real passkeys and real browsers can't be automated this way; their
results are logged in
[docs/passkey-compatibility.md](docs/passkey-compatibility.md).

## Roadmap

These steps come after the MVP, in order, and each one is optional. The local
database stays the source of truth throughout.

1. A first remote destination, such as Lighthouse, Sia or Arweave. Folder
   sets already cover external drives and sync services. A remote destination
   adds only what it needs: a shared destination interface, once there are two
   implementations; incremental batches of new and updated records, because
   uploading full snapshots daily would pay again for the same plays and a
   play's observed duration can change after it qualifies; delivery
   bookkeeping, so finished uploads are never republished and failed ones are
   retried; and a way for a fresh machine to find the set (an object key, an
   IPFS CID and an Arweave transaction ID behave differently). Archives and
   the recovery file travel together, and the encryption key and enrolled
   passkeys stay the same whichever provider holds them.
2. ListenBrainz. Add a per-destination delivery queue with explicit outcomes
   (accepted, permanently ignored, deferred, transient, needs re-auth), and
   backfill the existing history.
3. Robustness and more sources. Add a configurable player allowlist,
   in-progress checkpoints, inference of repeated plays, and a podcast filter
   if needed.
4. Later work: your own player talking to the daemon over IPC, Windows and macOS
   adapters, Arweave, and Last.fm.
