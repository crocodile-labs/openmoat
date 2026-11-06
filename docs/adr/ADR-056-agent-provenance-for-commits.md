# ADR-056: Agent provenance for commits, from the local audit log, kept in git notes

Status: accepted · Date: 2026-11-05 · Builds on ADR-029, ADR-031, ADR-039, ADR-048 and ADR-050

## Context

A reviewer looking at a pull request cannot tell which of its files and lines an agent
wrote, or whether that agent had just read a web page, an MCP result or an issue's text,
the content a prompt injection arrives in. OpenMoat's hook already records this on the
machine where the agent ran:

- every decided call is an event in the hash-chained audit log, with host, session,
  action and verdict;
- the files each session wrote, with the content hash the write leaves and the hash
  before it, when the hook knew them (`session_writes`, ADR-039 and ADR-048);
- the writes of a session that had read untrusted content, as tainted-write rows
  (`provenance`, ADR-029). These rows also cover a session that read a file a tainted
  session wrote.

None of this left the machine, and check-diff (ADR-050), which runs in CI where there is
no audit log, could not show it.

The threats:

- **Hidden agent work.** An injected agent's change is merged as if a person had written
  it, so it gets a person's level of review.
- **Forged records.** An agent rewrites or removes the record so that its work, or its
  having read untrusted content, does not show. It could do this by writing notes
  directly or by running the command that writes them.

## Decision

1. **Attribution is pure, in the core** (`openmoat-core/src/attribution.rs`). The caller
   passes each session's newest recorded write of the commit's files (`AgentWrite`) and
   the commit's changed files with content hashes (`ChangedFile`). For each file and
   session, the newest write up to the commit's time (plus 2 s, since git keeps whole
   seconds) gives one of three kinds of evidence:
   - `lines`: the write's after-hash equals the committed content and its before-hash
     equals the parent's. The write made the commit's whole change to the file, so every
     added line (from the `-U0` hunk headers) is claimed.
   - `content`: the after-hash equals the committed content but the start differs. The
     committed file is what the session left, but a person may have written some of it
     before, so no lines are claimed.
   - `touched`: there is no hash match, but the session wrote the file after the parent
     commit. The file may have changed since.

   A content match counts whenever the write happened, since content written long
   before the commit is still the agent's. A time match counts only after the parent
   commit. The core has no I/O and no hash function, so content hashes come in as text.
   `UntrustedKind` (web, MCP, unknown tool, file) is the one list of what taints a
   session. `CompiledPolicy::exposure` uses it, and so does the new
   `CompiledPolicy::untrusted_read`, which says what a call read.
2. **Untrusted content before the write** (`openmoat-cli/src/provenance/collect.rs`) is
   one of two things, whichever applies first:
   - the session's first call that ran and read untrusted content, if that call came
     before the write. It is classified by the installed policy, or the default one,
     with the same atoms session taint folds.
   - otherwise, the tainted-write row the hook recorded with the write (`kind: file`). It
     also covers a tainted file the session read, and it is all there is when the
     classification differs.

   Sources are redacted with `openmoat_audit::redact` and cut to 200 characters. **No
   schema change.** Two read-only store queries are added: `writes_up_to`, one pass over
   the bounded `session_writes` table, and `tainted_write_at`, which uses the provenance
   path index.
3. **`openmoat provenance [--range <rev-range>] [--write-notes] [--verify] [--format
   text|json]`**:
   - It prints the attribution. The default range is the commits `HEAD`'s upstream
     lacks, or `HEAD` alone.
   - `--write-notes` stores one compact JSON note (`openmoat-provenance-v1`) per commit
     that has any record, on `refs/notes/openmoat`. The note's blob is written with
     `hash-object`, then `git notes --ref refs/notes/openmoat add -f -C <blob>`. Nothing
     is pushed.
   - A note holds: repository-relative paths, the host and session ids as the log stores
     them, the cited event ids and their chain hashes, the log's head (event and hash),
     each claim, and `digest`. The digest is the SHA-256 of a length-prefixed encoding of
     all of these (`Note::digest_input`).
   - `--write-notes` is a person's command: like `openmoat audit anchor`, it refuses
     without a terminal or with an agent among its parent processes, and `kernel-self`
     denies it to agents at the hook.
4. **Verification against the log** (`--verify`; exit 64 on a mismatch, like `audit
   verify`). For each noted commit it checks:
   - the note names this commit;
   - the digest matches;
   - the chain verifies up to the note's head, and the head is still in the log with
     its hash;
   - every cited event is in the log with its hash, and is a call of the claimed host
     and session, recorded no later than the claimed write;
   - the commit, attributed again from today's log, agrees with the note (`compare`). A
     session the note leaves out, or a changed evidence kind, line set or untrusted kind,
     is a mismatch.

   A claim whose lookup row has since been replaced or aged out cannot be recomputed. It
   still has to cite a real event of that session. The agent cannot read the audit log
   (`kernel-self` denies reads, the sandboxes deny them too), so it cannot cite real
   hashes. A forged note fails, and so does a real note after the log is rewritten.
5. **Agents may not write the notes ref.** A new `review` group, `provenance-notes`,
   covers `git notes … *openmoat*`, `git update-ref … *notes/openmoat*` and `git
   update-ref --stdin`. `GIT_NOTES_REF` is already denied (`env-poison`), and `git config
   core.notesRef` and writes under `.git` already need review (`git-internals`). Other
   notes refs, reading history and the read-only report are unchanged, as the benign
   fixtures show.
6. **The check-diff hook** (`openmoat-cli/src/provenance/review.rs`) is the only
   interface between the two features. check-diff calls:
   - `review::section(base, head, level) -> Option<Section>`, which reads the notes of
     the commits from the merge base to `--head` itself (it does not use check-diff's
     input);
   - `review::write(format, &report, section, output::write)`, which prints check-diff's
     own report unchanged and adds the section: a `provenance` key in JSON (its other
     keys flattened beside it), `::warning` (or `::notice`) workflow commands, and lines
     after the text: "N files / M lines written by <host> (session …, after reading web
     content (…))".

   `--provenance review|info|off` (default `review`) is a flattened argument group of
   its own (`DiffProvenanceArgs`). The section never changes the exit code. With no
   notes in the range, or a diff on stdin, nothing is printed. A note that cannot be
   read is one line of the section, not an error.
7. **No signature in v1.** The policy-pack machinery (ADR-031, ADR-036) verifies
   OpenSSH signatures with keys a person trusted, so the CLI could sign notes with
   `ssh-keygen -Y sign`. That is not built:
   - A signature proves who wrote a note, not that it is true. The claims can only be
     checked against the log they came from, and `--verify` does that.
   - A CI runner has no trusted key of the developer's, so it would have to trust
     whatever key the repository names, and that proves nothing more.
   - Signing would add key handling to a command people run often.

   If teams need notes from many machines checked centrally, a later ADR can add
   `--sign` with the pack namespace scheme (ADR-036).

## Alternatives considered

- **A new append-only table of every write with both hashes.** It would chain several
  edits by one session, so more commits would get `lines`. It is not built here because
  it needs a schema migration, the parallel ADR-057/058 work may migrate the schema too,
  and `session_writes` covers the common case (one write, or the last one). It is the
  natural next step.
- **Trailers in the commit message, or a file in the tree.** They would change the
  commit (its hash, and its signature if it is signed). Notes leave commits untouched,
  and a person chooses whether to push them.
- **Attributing by time alone.** A file written by an agent and then rewritten by hand
  would be attributed to the agent. Content hashes come first, and time-only evidence is
  shown as `touched` with its caveat.
- **Failing check-diff on agent-written lines.** That would block normal agent work.
  Provenance is information for the reviewer (a `review`-level line by default,
  configurable down to `info` or `off`), never a verdict.

## Consequences and limits

- Only commits made on a machine running OpenMoat have records, and only what the hook
  saw: a script or an editor that writes files is not seen. The `session_writes` lookup
  keeps each session's newest write per file for 30 days (at most 100,000 rows). Shell
  writes and edits whose content the hook could not compute have no hash, so they give
  `touched` at best.
- Notes can be stripped, never pushed, or not fetched. **A missing note proves
  nothing**: check-diff says so and stays quiet.
- A note claiming more agent work than happened is not a security problem (it only
  invites more review). `--verify` reports a note that claims less.
- CI cannot verify a note, since it has no audit log. The section says the notes are
  claims, checkable with `openmoat provenance --verify` on the machine that wrote them.
- The Action fetches the notes ref so that check-diff sees them. A repository whose
  people do not push notes sees nothing.
- Public library API: `openmoat-core` adds the module `attribution`, the enum
  `UntrustedKind` and the method `CompiledPolicy::untrusted_read`; `openmoat-audit` adds
  `RecordedWrite`, `Store::writes_up_to` and `Store::tainted_write_at`. These are
  additions only.
