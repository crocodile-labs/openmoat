# ADR-110: Signed audit checkpoints, and what a person was shown at a review

Status: accepted · Date: 2026-11-22

## Context

The audit log's chain (schema 2) and its audit-key MACs (ADR-101) show that the log is
as OpenMoat wrote it, but only to whoever holds `~/.moat/audit.key`: the MAC is a
symmetric secret, so nobody else can check it, and anyone who could check it could also
forge it. Code running as the user outside any sandbox reads the key as it writes the
log, and deleting the newest events leaves a shorter log that verifies; anchors
(ADR-031) catch that only up to the newest one a person made, off the machine.

Other tools in this space sign their audit records with Ed25519 and anchor them in a
transparency log (Sigstore Rekor). C2SP publishes the formats transparency logs and
witnesses share: `tlog-checkpoint` (a log's origin, tree size and RFC 6962 Merkle root)
inside a `signed-note`. A checkpoint copied off the machine, given to a reviewer or
cosigned by a witness can be checked by anyone holding the public key.

OWASP's Top 10 for Agentic Applications (2026) names human-agent trust exploitation
(ASI09): a person approves what they were shown, and something else runs. It asks for a
record of what was shown beside what ran. OpenMoat recorded the held call's action and
reasons, but not the text the host's prompt showed, nor whether the call that ran after
the approval was the one held.

`ring`, which rustls and rcgen already build OpenMoat with, implements Ed25519 (RFC
8032). No crate in the build reaches the macOS Keychain, the Secret Service or DPAPI;
`security-framework` is there on macOS only through `rustls-native-certs`.

## Decision

1. **A signing key separate from the audit key.** `~/.moat/audit.key.ed25519` holds an
   Ed25519 seed (a tag line, then 64 hex characters), written once and owner-only
   through `home::write_private_new` (temporary `audit.key.ed25519.<pid>.<nanos>.tmp`)
   and read through `key_file::read`, which refuses a file others may read. Its name
   starts with `audit.key`, so `kernel-self`'s existing `~/.moat/audit.key*` and
   `**/.moat/audit.key*` deny it, its temporary file and kept keys to agents, and the
   host sandboxes generated from the policy deny them too; attack fixtures say so.
   A person's `openmoat init`, `openmoat audit anchor` or `openmoat audit checkpoint`
   makes it when missing. No other writer does: a log without it (every install before
   this release) records as before and has no checkpoints, so an upgrade locks nobody
   out.
2. **Not the OS keychain, for now.** The guard signs from a hook on any call (point 4),
   so the key must be readable without a prompt from every hook process. A Keychain item
   is bound to the signing identity of the binary that made it, and `brew upgrade` or a
   new download changes that: the next hook would raise a dialog or fail. The Secret
   Service and DPAPI release a user's secrets to any process of that user, so they
   would add a dependency and no protection over an owner-only file. The file's limits
   are the audit key's (ADR-101): code running as the user outside any sandbox can read
   it and sign a checkpoint of a rewritten log. Moving it into a keychain or hardware
   key, used only by person-run commands, is left for a later decision.
3. **The format is C2SP's.** A checkpoint's text is the origin, the tree size in decimal
   and the root in base64, each on a line; the signed note adds a blank line and
   `— <name> <base64(key id || signature)>`, the key id being the first 4 bytes of
   `SHA-256(name || "\n" || 0x01 || public key)`. The verifier key is
   `<name>+<hex key id>+<base64(0x01 || public key)>`, the form Go's
   `golang.org/x/mod/sumdb/note` and the transparency-dev witness read. The name, and
   so the origin, is `openmoat.dev/audit/<first 16 hex of SHA-256(public key)>`: it
   identifies the key's log, nothing is fetched from it, and a new key is a new origin.
   Parsing is strict (one spelling of a size, canonical base64); extension lines after
   the root and other keys' signatures (a witness's cosignature) are allowed and
   ignored. The base64 and hex codecs are a few lines in `checkpoint/encoding.rs`,
   tested against RFC 4648.
4. **The tree is RFC 6962's, over the chain.** Its leaves are the chained events (those
   an export holds) in id order, each leaf's data the 32 bytes of the event's chain
   hash, which commits to every cell; a leaf hashes as `SHA-256(0x00 || data)`, a node
   as `SHA-256(0x01 || left || right)`. The chain encoding does not change and no schema
   version is added. `Frontier` keeps the roots of the perfect subtrees (one per set
   bit of the size), so a checkpoint reads only the events since the last one. The
   guard signs a checkpoint after each event whose id is a multiple of 1000, when the
   key is there, from the frontier kept in `~/.moat/checkpoints/frontier`, rebuilt from
   the first event when its last event is gone or has another hash; this is best
   effort and never changes a call's answer. `openmoat audit checkpoint` (person only,
   from a terminal, as an anchor is) and `openmoat audit anchor` read the whole log,
   refuse a chain that breaks, and sign. Checkpoints are kept as
   `~/.moat/checkpoints/<size>-<8 hex of the key's name>.txt`; nothing is sent anywhere.
5. **Checking needs only the public key.** `openmoat audit verify <export> --checkpoint
   <file> --pubkey <key or file>` checks the signature first, then the export's chain as
   before, then the Merkle root over its first `size` lines: an edited, deleted, inserted
   or rewritten event among them changes the root (`differs`), fewer lines than `size`
   are a cut log (`truncated`), and an export that does not start at the log's first
   event cannot be checked (`not_whole_log`). Without an export it checks this
   machine's log. `openmoat doctor` shows the public key and its fingerprint, and checks
   the newest checkpoint of the current key against the log. `openmoat audit checkpoint
   --new-key` starts a new key and keeps the old one as `audit.key.ed25519.<ms>.old`;
   checkpoints each key signed verify with its own public key only.
6. **Witnessing stays a documented step.** Submitting to a transparency-dev witness
   (`tlog-witness`'s `add-checkpoint` needs a consistency proof from the witness's last
   size, so the log must serve its tiles or proofs) or to Rekor v2 (an entry over the
   checkpoint's bytes, signed by the same key) needs a network client, a place to serve
   proofs, and a choice of which public service sees the log's existence. OpenMoat ships
   the format and the checks; USAGE says how to hand a checkpoint to either. No network
   is used.
7. **Shown versus ran (ASI09).** When the host's answer for a call is a `review` it puts
   to a person, the recorded row carries one more reason: `shown: ` and the exact text
   the host's reason field gets (`openmoat_hosts::reason_line` of that answer), redacted
   as every reason is. When the host reports that a call ran (Claude Code's
   `PostToolUse`, ADR-057) and the newest row with that host, session and call id held it
   for review, a row is recorded beside it with tool `ran-after-review`, verdict `allow`
   and rule `review-ran-as-shown` when the action that ran, recorded with the guard's
   known secrets masked, is the held one, or `review-ran-changed`, with the action that
   ran, when it is not. Both rows are chained, keyed and covered by checkpoints. They are
   not counted as an agent's calls (`audit stats`, `report`). A host without a report
   after the call, or without a call id, gets the `shown:` reason only.

## Consequences

- An export and a checkpoint can be checked on another machine by anyone with the
  public key, without the audit key: an edit or truncation among the checkpoint's
  events is found. Events after the newest checkpoint have only the chain and the MACs.
- A checkpoint kept off the machine, or witnessed, stays valid against later rewrites
  by code that holds both keys: the root it states cannot be made to match a rewritten
  log. A checkpoint kept only in `~/.moat/checkpoints/` can be deleted with the log by
  whoever can write there; `doctor` shows the newest one, and its absence.
- The key file can be read by code running as the user outside any sandbox, as the
  audit key can: such code can sign checkpoints of a rewritten log from then on. Copies
  made off the machine before that still show the rewrite; the public key a verifier
  already holds is the one to check with.
- At every thousandth event the guard reads the events since the last checkpoint and
  writes two small files; a frontier that no longer matches costs one read of the log.
- `ran-after-review` rows exist only where the host reports the call after it ran, with
  its call id; elsewhere the `shown:` reason records what was shown but nothing records
  what ran. A changed input is recorded, not blocked: the call has already run.
- The shown text makes review rows longer by the block message (ADR-059).
- `ring` becomes a direct dependency of `openmoat-audit`; it was already built for the
  CLI through rustls, so the build gains no crate.
