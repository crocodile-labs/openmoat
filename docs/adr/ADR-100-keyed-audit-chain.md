# ADR-100: A keyed audit chain

Status: accepted · Date: 2026-11-14

## Context

The audit log's hash chain (schema 2, `store/chain.rs`) makes an edit, a deletion or a
reordering in the middle of the log visible, but it is unkeyed: whoever can write
`~/.moat/audit.db` can edit an event and recompute every hash after it, and the log
verifies again. Anchors (ADR-031) catch a rewrite up to an anchored event, but only
where a person anchors, off the machine, and only up to the newest anchor.

Several holders of the file cannot read OpenMoat's other secrets: a copy of the
database (a backup, a synced folder, a `doctor --bundle` attachment, a file handed to
a reviewer and back), and a process or sandbox granted the database and not the rest
of the state directory. For those, a keyed MAC turns "consistent" into "written by
OpenMoat on this machine". It does not help against code running as the user outside
any sandbox, which reads any key the user can.

OpenMoat already keeps per-install secrets: `proxy.key` (ADR-044), the remote approval
key (ADR-078), the proxy CA's key (ADR-043). Each is 32 random bytes or a private key
written once owner-only in the state directory, refused when others may read or
replace it (`key_file::read`), and denied to agents by `kernel-self`, which the host
sandboxes are generated from. HMAC-SHA-256 already exists over `sha2` in the CLI
(`proxy_session/hmac.rs`), checked against RFC 4231.

## Decision

1. **A MAC beside the hash, not a keyed hash.** Each event keeps its unkeyed chain
   hash and gains `mac`, `HMAC-SHA-256(key, "openmoat-audit-mac-v1\n" || hash)` in
   lowercase hex. The hash commits to every cell and, through `prev_hash`, to every
   event before it, so one MAC per event authenticates the chain up to it, and the
   first event a rewrite touched is the first whose MAC fails. Keeping the hash public
   keeps exports verifiable by anyone, keeps anchors (which record the hash) and live
   delivery records unchanged, and needs no new chain encoding.
2. **Its own key, `~/.moat/audit.key`.** Not `proxy.key` under another domain: a person
   replaces `proxy.key` to revoke session credentials, which must not leave the log
   unverifiable. The file is made and read as `proxy.key` is (`home::write_private_new`,
   `key_file::read`), is in `kernel-self`'s reads and, as everything under `~/.moat`, its
   writes. It holds two lines: the key as 64 hex characters, and `after <id>`, the
   newest event when the key was made.
3. **The boundary lives with the key.** Events up to `after` were written before the
   key and verify by their hashes only; every later event must carry a matching MAC.
   Schema 12 also records the boundary in the database (`meta.unkeyed_last_id`) for
   readers without the key, but a verifier with the key uses the key file's, so whoever
   can write the database but not the key cannot strip the MACs and move the boundary
   past them.
4. **Schema 12.** `ALTER TABLE events ADD COLUMN mac TEXT` (no row copied), the mark,
   and a trigger that refuses an insert past the mark without a MAC: a long-running
   process of an older build that opened the log before the upgrade (a standalone
   `openmoat proxy`, an `openmoat mcp proxy`) then fails closed until restarted, instead
   of appending events that would read as rewritten. Rows already present get no MAC:
   one made now would vouch for whatever they hold today, as schema 2 said of hashes. A
   database below version 12 opens read-only and verifies as before.
5. **Writers refuse rather than write unkeyed.** `Store::record` needs the key
   (`StoreError::KeyMissing`) and refuses an event at or before the key's `after`
   (`KeyAhead`: the log lost events since the key was made). Every writer of events
   opens the log through `audit_key::open_existing`, which makes the key only when there
   is none and no event is past the mark (at `openmoat init`, or at the first call after
   the upgrade); a missing key while later events exist, a key it cannot read, or a key
   others may read is an error. The guard denies a call it cannot record
   (`kernel-error`), so such a log denies every call until a person puts the key back,
   or moves the log aside as evidence and runs `openmoat init`, which starts a new log
   and, for a log without events, a new key. Writing unkeyed events instead would read
   later as a rewrite, and making a new key would let whoever deleted the key start a
   log that looks intact while leaving every keyed event unverifiable.
6. **Verification.** `Store::verify_chain` checks each MAC with the handle's key
   (`mac_missing`, `mac_mismatch`) and counts the events it checked (`keyed`). A handle
   without the key stops at the first keyed event (`key_unavailable`): on this machine
   the key is expected, and nothing after that event can be vouched for, so `doctor`,
   `audit anchor` and `audit verify --against` fail closed. Exports of keyed events are
   `moat-audit-export-v2` lines with `mac` and `key_id` (the first 8 bytes of the key's
   HMAC of a fixed text). `openmoat audit verify` checks the MAC of a line whose
   `key_id` is this machine's key, and once one has matched, fails a later line without
   one; elsewhere such lines are counted as `keyed_unchecked` and checked by their
   hashes.
7. **No new dependency.** HMAC-SHA-256 moves from the CLI into `openmoat-audit`
   (`hmac_sha256`, the CLI re-exports it); `zeroize`, already in the tree, zeroes the key.

## Consequences

- A rewrite by someone who can write the database but not read the key is detected at
  its first event; so is a log whose key was replaced, as a MAC mismatch at the first
  keyed event.
- Code running as the user outside any sandbox (hook-only agents' allowed commands,
  LIMITS) reads the key as it writes the log, and can rewrite both; anchors kept off
  the machine stay the defence there. A key in the OS keychain, which no sandbox grants,
  would raise that bar on macOS and Windows and is left for a later decision: the guard
  writes on every call and would need the keychain on every call.
- Deleting the newest events still leaves a valid shorter chain; the key file catches
  only a log cut below the event it was made at.
- Deleting the key stops the log until a person acts, and every call is denied
  meanwhile. That is a denial of service available to whoever can delete files in
  `~/.moat`, who can delete the log too.
- An export proves without the key what it proved before: the lines are consistent and
  link, not that nobody rewrote them. A line stripped of its MAC before the first line
  that verifies reads as one from before the key.
- Long-running processes of an older build refuse to record after the upgrade until
  restarted.
