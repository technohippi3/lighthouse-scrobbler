# Architecture: private backup and optional public publishing

This document records the boundary the project is built around. Private
backup works on its own. Public publishing is an optional layer on top that
private backup never depends on.

## Private history (v1)

The private side is made of these pieces:

- SQLite on the user's machine, which is the source of truth. Recording works
  offline, with no account and no network.
- age-encrypted archives in a versioned JSONL format, keyed by stable listen
  UUIDs. They are described in the README under "Backup sets", and the key
  scheme is in [recovery-phrase.md](recovery-phrase.md).
- A passkey recovery file that travels with the archives, so any copy of a
  backup set restores on its own.
- Destinations: a folder, and Lighthouse. Provider details such as CIDs and
  upload state live in separate delivery records (the `remote_files` table),
  never in the archive format or in listen records. Lighthouse receives
  incremental batches, the recovery file and a complete manifest, uploaded in
  that order. Restores verify every downloaded block against its CID.
  Lighthouse's free plan doesn't serve downloads (see the README), so the
  folder copy is the dependable restore for now.

Private backup needs no wallet, contract or public identity. Keeping it off
any chain avoids linking an account to its backups or exposing when they are
updated.

## Public history (later, opt-in)

The public side has these pieces:

- Export. The user explicitly chooses to publish, and the export contains only
  what they publish: listen UUIDs and selected metadata. It excludes local
  file paths and device-specific player identifiers, such as
  `player_track_id`.
- Manifest. This is a complete inventory of the files needed to rebuild a
  published history, including any matching and correction records, with a
  content hash and location for each file. It is published only after every
  upload it references has succeeded. Each manifest is complete on its own;
  it never depends on following a chain of earlier manifests.
- Tempo registry. It maps a profile to its controller, a revision number and
  the latest manifest reference, and it records nothing else. Updates carry
  the expected previous revision, so an old update cannot silently replace a
  newer one. Track descriptions and matching decisions stay out of any global,
  operator-controlled registry.
- Authenticity. The account's transaction commits to the manifest's hash,
  which commits to every file the manifest references. Committed batches
  therefore need no separate signatures. Verifiable updates before anchoring
  would be a separate feature, and that feature is deferred.
- Indexers. An indexer rebuilds public profiles from published records,
  deduplicates by listen UUID, and applies its own documented matching rules.
  Anyone can run one, and our first indexer's contents can be rebuilt from
  published histories.
- Sponsorship. Paying fees for users is an optional service with contract and
  function restrictions, request validation, abuse controls and a hard
  spending ceiling. The old testnet sponsor demonstrates the flow; it doesn't
  establish a production funding model.
- Writers. The prototype publishes from one device. A stream ID identifies a
  writer but doesn't resolve competing updates. Simultaneous publishing will
  need independently advancing streams or explicit conflict detection.
  Restore keeps historical stream IDs and gives the new install its own.

A signed or anchored scrobble means that this user reports this listen. It
does not prove the listen happened.

## Accepted risks for the MVP

Recovery hardening is deliberately out of scope for now. These risks are
known and accepted:

- One passkey can be the only way to restore a backup set. If it is lost and
  no recovery words were written down, the backups can't be read. The local
  database is unaffected.
- Passkeys are bound to the staging domain
  `lhs-passkey-staging.piratesocialclub.workers.dev`. Losing or changing that
  domain means enrolling again, and existing passkeys stop working.
- There is no account recovery, because there are no public accounts yet.

## Accounts and recovery (later)

These rules apply when public accounts arrive:

- The account's signing keys authorize publication and account changes. The
  age key protects private backups, and passkey PRF wrapping gives access to
  it. Recovering one does not recover the other.
- Two passkeys on the same domain protect against losing one authenticator,
  not against losing the domain. If recovery must outlive our service, at
  least one recovery method has to work without our domain. Choose the
  production relying-party ID before enrolling durable accounts, and test
  recovery rather than assuming that two signers are enough.
- Native multiple signers, rotation and recovery are on Tempo's Accounts
  devnet until T14 (testnet 2026-11-24, mainnet 2026-12-01). Activation and a
  tested recovery are prerequisites for relying on them.

## Matching

The original listen is never changed. A match is a separate, revisable record
holding the recording ID, the method, the resolver version and a confidence.
Ambiguous matches stay unresolved rather than merging live, studio and remix
versions. A metadata hash is a grouping heuristic, not proof of identity, and
adding duration to it would only improve the heuristic. Local fingerprinting
with Chromaprint and AcoustID can run as an occasional cached job, so the
recorder's everyday footprint doesn't grow.

## Resilience

The goal is independent copies of the data and the manifests, regular
retrieval checks, and repair. The acceptance test is that a fresh client can
restore, and later rebuild a public profile, while our API and Lighthouse are
both unavailable. Independent replication can move earlier if resilience
becomes more urgent than social features.

## Order

1. Lighthouse backup and cold restore, with identifier semantics documented
   and an installation stream ID recorded.
2. Optional matching, and a portable public-history format that preserves
   raw listens and UUIDs.
3. A Tempo prototype: ownership, sponsored manifest publication and one
   rebuildable indexer.
4. Independent replication, and a recovery test with our services down.
