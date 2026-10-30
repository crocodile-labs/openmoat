# ADR-048: A person's answer to a taint ask covers the file

Status: accepted · Date: 2026-10-29 · Refines ADR-020

## Context

ADR-020 makes a write to a protected path ask once the session has read untrusted
content: the content may have steered the agent, and the file changes what runs or
what the agent is told later. The ask is right the first time. It then repeats for every
write of the same file for the rest of the session, although nothing new has happened:
the person already judged that file against that content. In ten days of one person's
daily use, `session-taint` was 70% of all asks (241 of 346), most of them repeated writes
to the same few files (agent memory notes, `AGENTS.md`, `Cargo.toml`); one memory file
drew 91 asks in one session. Asks that carry no new information teach people to approve
without reading, which is worse for the files this rule protects than fewer asks.

A person can already answer the ask once with `openmoat allow --last` (the grant stands
for that file while it is newer than the session's latest untrusted read, by audit row),
or with `s` for every protected write of the session. Almost nobody leaves the agent to
run that; they answer the agent's own prompt, and the hook learns nothing of it: no host
reports the answer, and a declined ask is not recorded (`taint::ran` counts an ask on a
host that can ask as having run, which is the conservative direction for taint).

So the hook needs evidence of the person's answer that the agent cannot forge:

- Counting the ask itself as the answer would let a declined write through on its
  retry: the person says no to `AGENTS.md`, the agent writes it again, silently.
- The file holding what the asked write sent shows the write ran, and after untrusted
  content a write to a protected path runs only when a person lets it. But a file that
  already held that content looks the same whether the write ran or not: an agent could
  ask to write the file's own content, be declined, and have the next write covered.
- The file holding what the asked write sent **and not what it held before** shows the
  write ran and changed the file. Only a party who knew the content could have produced
  that state, and the agent cannot write the file without the hook.

## Decision

1. **A write the person let run answers the taint ask for later writes of the same
   file in the same session**, until the session reads untrusted content again. The
   guard (`taint::answered`, `earlier_write_ran`) gives the untainted decision back,
   with the reason `an earlier write of <file> in this session was approved after the
   session last read untrusted content`, when for every file the call writes:
   - the session's newest write of the file (ADR-039's record, `session_writes`) was
     recorded **strictly after** the latest untrusted read, by audit row (rows only grow;
     the clock may step back), or by time for a database without rows;
   - the hook knew the content that write leaves: the whole file a `Write` sends, or
     for an `Edit`/`MultiEdit` the file as it was with the replacements applied as
     Claude Code applies them (`old_string` found exactly once unless `replace_all`,
     never a no-op; otherwise Claude Code refuses the edit and the content stays
     unknown). The record keeps that hash and the file's state before the call
     (`before_sha256`, `""` for no file; audit schema version 7);
   - the content differs from that state, and the file holds the content now.
2. **Scope, strictly.** Same host session, same canonical path (the lookup key the
   session-writes record uses, lowercased where file names ignore case), the
   `session-taint` reason from untrusted content only. A taint ask from a secret the
   session read is never answered this way: a write never raises one, and the check
   runs only after `answered` has shown the ask comes from untrusted content alone.
   Nothing here loosens a `deny`, and the covering adds no new allow: it gives back the
   decision the policy made before taint tightened it.
3. **What is no evidence**, and therefore asks: a declined write (the file does not
   hold it); a write of content the file already held (a retry or a probe); an edit
   whose outcome is not known (its `old_string` absent or found twice, a file that is
   not UTF-8 or too large to read); a patch (`apply_patch` with a hunk) or a shell
   write, whose resulting content the hook does not see; a write recorded before the
   latest untrusted read; another session's write; a file changed since by anyone.

## Consequences

- The first write of a protected file after untrusted content asks, as before. Once the
  person approves it in the agent, the second, third and ninety-first write of that file
  are allowed, each with a reason that says why. Reading untrusted content again asks
  once more for the next write of the file.
- `Edit` and `MultiEdit` are covered as `Write` is: the host adapter passes the
  replacements (`HookRequest::edits`) and the guard applies them to the file it reads.
  The uncovered writes are a patch hunk (Codex `apply_patch`) and a shell write (`echo
  >> AGENTS.md`), whose resulting content the hook does not see; they ask each time.
- The hook reads the target file of every `Write` and `Edit` once more when it decides
  it (it already reads files for provenance, ADR-029). The audit database gains a column; a
  database an older build wrote migrates on the first writable open, and its rows,
  which lack the state before the write, cover nothing.
- The record this relies on is bounded (ADR-039: 30 days, 100 000 rows); a session
  whose row was pruned asks again, which is the safe direction.
- `openmoat allow --last` and its `s` answer keep working as ADR-020 describes; they
  are checked first.
