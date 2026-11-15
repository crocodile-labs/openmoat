# ADR-101: A keyed audit chain

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
   through a temporary `audit.key.<pid>.<nanos>.tmp`, and `key_file::read`); `kernel-self`
   denies reading `audit.key*`, so the temporary file and kept old keys too, and, as
   everything under `~/.moat`, writing it. It holds two lines: the key as 64 hex
   characters, and `after <id> <hash>`, the newest event when the key was made and its
   chain hash (`none` for an empty log or an event from before the chain). A mode
   others may read is refused with advice that never says to remove the key alone.
3. **The start lives with the key.** Events up to `after` were written before the
   key and verify by their hashes only; every later event must carry a matching MAC,
   and event `after` must still be there with the recorded hash. Schema 12 also records
   the boundary in the database (`meta.unkeyed_last_id`) for readers without the key,
   but a verifier with the key uses the key file's. So whoever can write the database
   but not the key can neither strip the MACs and move the boundary past them, nor
   drop every keyed event and rewrite those before the key (the start's hash changes:
   `key_start_changed`), nor cut the log below the start (`truncated`); a writer
   refuses to record on top of either (`KeyStartChanged`, `KeyAhead`).
4. **Schema 12.** `ALTER TABLE events ADD COLUMN mac TEXT` (no row copied), the mark,
   and a trigger that refuses an insert past the mark without a MAC: a long-running
   process of an older build that opened the log before the upgrade (a standalone
   `openmoat proxy`, an `openmoat mcp proxy`) then fails closed until restarted, instead
   of appending events that would read as rewritten; an insert that leaves its id to
   SQLite is refused too. Rows already present get no MAC:
   one made now would vouch for whatever they hold today, as schema 2 said of hashes. A
   database below version 12 opens read-only and verifies as before.
5. **Writers refuse rather than write unkeyed.** `Store::record` needs the key
   (`StoreError::KeyMissing`) and refuses an event at or before the key's `after`
   (`KeyAhead`: the log lost events since the key was made). Every writer of events
   opens the log through `audit_key::open_existing`. A key is made only for an empty
   log, by the writer whose own open upgraded the log to version 12 (it added the MAC
   column; a version set back by hand keeps the column and does not count), or by a
   person's `openmoat init` when no event is past the mark. Any other writer that finds
   no key waits half a second for a concurrent upgrade to make it, then refuses; a key
   it cannot read, or one others may read, is an error too. The guard denies a call it
   cannot record (`kernel-error`), so such a log denies every call until a person puts
   the key back, or moves the log aside as evidence and runs `openmoat init`. Writing
   unkeyed events instead would read later as a rewrite, and making a key in any writer
   would let whoever can write the database strip the MACs, move the mark, delete the
   key and have a new one made over the rewritten log. `openmoat doctor` reports a
   missing key whenever a version-12 log holds events, whatever the mark says.
   `openmoat init` on a new log, or an empty one whose key was made for a longer log or
   cannot be used, starts a new key and keeps the old one as `audit.key.<ms>.old`
   (owner-only), saying so: it still checks a log the person moved aside as evidence.
6. **Verification.** `Store::verify_chain` checks each MAC with the handle's key
   (`mac_missing`, `mac_mismatch`) and counts the events it checked (`keyed`). A handle
   without the key stops at the first keyed event (`key_unavailable`): on this machine
   the key is expected, and nothing after that event can be vouched for, so `doctor`,
   `audit anchor` and `audit verify --against` fail closed. Exports of keyed events are
   `moat-audit-export-v2` lines with `mac` and `key_id` (the first 8 bytes of the key's
   HMAC of a fixed text). An export names one key at most: a line that names another
   than the lines before it fails (`key_mismatch`). With this machine's key, a file
   that names no other key is taken as this machine's log: every line with a MAC must
   verify with the key whatever its `key_id` says, and every line past the key's start
   must carry one. A file that names only another key is another log's: its MACs are
   counted as `keyed_unchecked`, unless a line before verified with this key, which
   makes the rest a forged tail (`key_mismatch`). `openmoat audit verify` says when no
   line verified with this machine's key. Without a key, MAC lines are checked by their
   hashes and counted as unchecked.
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
- Whoever can write the database and delete the key, and also set the schema version
  back and drop the MAC column, can still pass the log off as never upgraded and have
  the next call make a key over it. That is the same power as rewriting the log under
  an unkeyed chain, and only an anchor catches it.
- An all-version-1 export from another machine (or from before that machine's key)
  checked on a machine with an audit key is taken as this machine's log, so its lines
  past this key's start fail; check it where it was written, or where there is no key.
- On Windows the key file is protected by the state directory's access list (ADR-083),
  not by mode bits; `key_file` checks only that it is a regular file there, as for the
  other keys, and that follows the Windows access-list work.
- Deleting the key stops the log until a person acts, and every call is denied
  meanwhile. That is a denial of service available to whoever can delete files in
  `~/.moat`, who can delete the log too.
- An export proves without the key what it proved before: the lines are consistent and
  link, not that nobody rewrote them. A file whose every line names another key's id
  proves nothing about this machine's log, and `audit verify` says no line verified.
- Long-running processes of an older build refuse to record after the upgrade until
  restarted.
