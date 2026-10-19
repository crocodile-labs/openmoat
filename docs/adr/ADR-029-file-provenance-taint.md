# ADR-029: Session taint follows the files a tainted session writes

Status: accepted · Date: 2026-10-18 · Refines ADR-020 (minimal session taint)

## Context

Session taint (ADR-020, POLICY.md §4.1) is per session: once a session reads
untrusted content (a fetch, a web search, an MCP result), its later writes to files
that run code or steer the agent ask. It does not follow what the session writes. An
injected session can write a payload into an ordinary file (`run.sh`, `tools/gen.py`,
a config a script loads) without any ask, and a later session, or a person's next
session, runs or reads that file with a clean taint. Nothing connects the two.

The guard sees every governed write before it runs, with its path, and for `Write`
the whole new content. It sees every read and every script a shell command runs as an
`fs.read` atom (`bash run.sh`, `python x.py`, `source x`, `cat x`), and a program
named by a path (`./run.sh`) as the first word of a `shell` atom. The audit log is
OpenMoat's own and the agent cannot write it (`kernel-self`).

## Decision

1. **Record.** When a call that may have run (allowed, deferred, or asked on a host
   that can ask) writes a file by a literal path in a session that read untrusted
   content, the guard appends a `tainted-write` row to a new `provenance` table of the
   audit database (schema 4): path, session, host, event, what the session had read,
   and for `Write` the SHA-256 of the content (CRLF hashed as LF). Every other write
   (`Edit`, `MultiEdit`, `apply_patch`, a shell write) has no hash: the guard runs
   before the write, and only `Write` sends what the file will hold.
2. **Follow.** When any later call reads or runs a path whose newest write row is
   tainted, and the regular file there still holds the recorded content (or the hash
   is unknown), the guard appends a `tainted-read` row for the session. The session's
   taint includes its `tainted-read` rows from then on, as if it had read untrusted
   content, with a reason naming the file and the writing session. Every existing
   consequence applies (protected writes ask, the push check counts it, `moat allow
   --last` answers it); provenance adds no ask of its own. What the same call writes
   is recorded as tainted too (`bash run.sh > out.txt`).
3. **Clear.** A `Write` by a clean session replaces the file and appends a
   `clean-write` row. A partial change by a clean session (`Edit`, a shell write) may
   leave the payload, so it keeps the file tainted with an unknown hash rather than
   letting a changed hash clear it. A change no session made (a person's editor, `git
   checkout`) changes a hashed file's content, and it no longer taints. No new command:
   the person answers the resulting ask with `moat allow` as for any taint ask.
4. **Store.** Rows are append-only (triggers refuse update and delete) and redacted
   like events. Lookups use an index on `(path, id)` and one on `(session_id, host,
   id)`; a clean session in a log without provenance rows does no lookup. The rows are
   not part of the session cache (#570): the cache holds only the fold of events.
5. **Switch.** `taint: { provenance: false }` in the user policy turns it off; it is
   on by default. A repository policy has no `taint:` section, so it cannot turn it off.

The design proposed recording in a new table or in event data. Event data would need
a scan of every session's events per read; a table keyed by path keeps the lookup to
one index probe per file. The schema version is bumped (unlike the session cache) because
these rows are a security record, not a shortcut, and the migration creates the index and
the triggers once instead of on every guard call.

## Consequences

- The cross-session persistence threat is partly covered: a payload written by a
  tainted session and later run or read by another one taints that session.
- Files are tracked by path. A copy or rename a command does out of sight, content a
  script or a build writes indirectly, and files read through `Grep` or `Glob` are not
  followed (THREAT_MODEL.md §5). A file without a hash taints every reader until a
  clean `Write`; this is stricter, and quiet, since only taint's existing asks follow.
- Sessions that read untrusted content are common (web search, MCP), so many files
  will carry tainted provenance; a session that reads them asks for protected writes
  as the writing session did.
- A schema-4 audit log is refused by older builds (`SchemaTooNew`), so going back to
  an older `moat` needs a new log.
- Each guard call classifies the call once more and probes the index per file it
  names; `scripts/ci/guard-session-latency.py` times reads after 500 tainted writes
  against the same budget.
