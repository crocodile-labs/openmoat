# Agent provenance for commits

`openmoat provenance` shows which files of your commits an agent session wrote. Where
the record allows, it also shows which added lines. For each file it names the agent
and session, gives the time, and says whether that session had read untrusted content
(a web page, an MCP tool's result, an unknown tool's result, or a file such a session
wrote) before it wrote. The answer comes from what OpenMoat's hook recorded on your
machine, in the local audit log ([ADR-056](adr/ADR-056-agent-provenance-for-commits.md)).
`--write-notes` keeps it with the commits in git notes. `openmoat policy check-diff` and
the merge check Action show it to whoever reviews the pull request.

## Commands

```bash
openmoat provenance                          # the commits HEAD's upstream lacks (or HEAD)
openmoat provenance --range main..HEAD       # any range git rev-list reads, or one commit
openmoat provenance --format json            # for scripts
openmoat provenance --write-notes            # keep a note per commit on refs/notes/openmoat
openmoat provenance --verify                 # check those notes against this machine's log
```

`--write-notes` must be run by you, in your own terminal. Like `openmoat audit anchor`,
it refuses without a terminal or when an agent started it, and the default policy
denies it to agents (`kernel-self`). It writes nothing but notes, and it replaces a
commit's earlier note. It pushes nothing.

`--verify` exits 0 when every note matches and 64 when one does not. A note fails to
match when:

- it was edited after it was written, so its digest does not match;
- it cites events or a log head this log does not have with those hashes, which happens
  when the log was rewritten or the note was made up;
- it pins a write on an event that is not a call of that session;
- it differs from what the log says now: it leaves a session out, weakens the evidence,
  or hides that a session had read untrusted content.

## Example

```
$ openmoat provenance --range main..HEAD
9f2c41d0a7be
  src/fetch.rs: claude-code session 3c9e1a7f02d4 wrote the whole change (12 added lines: 40-51), after reading web content (fetch docs.example.com); event 2a1, 2026-11-05 10:42
  README.md: claude-code session 3c9e1a7f02d4 wrote the file after the parent commit (it may have changed since); event 2b0, 2026-11-05 10:44
```

How a write is tied to a file:

| Evidence | Meaning |
|---|---|
| `lines` | the write turned the parent's content into the committed content, so every added line is the session's |
| `content` | the committed content is what the write left; a person may have written some of it before |
| `touched` | the session wrote the file after the parent commit (a shell write, or an edit the hook could not hash); the file may have changed since |

## Sharing the notes

Notes stay in your clone until you push them:

```bash
git push origin refs/notes/openmoat
git fetch origin '+refs/notes/openmoat:refs/notes/openmoat'   # on another clone
git log --notes=openmoat                                      # read them next to the log
```

A note is one line of JSON (`openmoat-provenance-v1`). It holds repository-relative
paths, the host and session ids as the audit log keeps them, the cited audit events
with their chain hashes, the log's head, each claim and a digest. Untrusted-content
sources are redacted as the audit log redacts them. A note holds no file contents.

## In pull requests

`openmoat policy check-diff --base … --head …` reads the notes of the change's commits
and adds a line per session:

```
review  provenance: 2 files / 12 lines written by claude-code (session 3c9e1a7f02d4, after reading web content (fetch docs.example.com))
        1 of 3 commits have a note on refs/notes/openmoat; notes are claims from the machine that wrote them (`openmoat provenance --verify` there checks them), and a commit without one proves nothing
```

On GitHub these lines are `::warning` annotations, and in `--format json` they are a
`provenance` key beside the report's own keys. `--provenance info` shows them as
`::notice`, and `--provenance off` hides them. They never change the exit code or fail
the check. When no commit in the change has a note, nothing is shown.

The merge check Action ([MERGE_CHECK.md](MERGE_CHECK.md)) fetches
`refs/notes/openmoat` from `origin` before it runs the check. Its `provenance` input is
`review`, `info` or `off`. With `persist-credentials: false` on `actions/checkout`, that
fetch works only for a public repository. A private one needs the checkout's
credentials, or a step of its own that fetches the notes.

## Agents cannot write the record

- `openmoat provenance --write-notes` is for a person (see above).
- An agent's `git notes … openmoat …`, `git update-ref … refs/notes/openmoat …` and
  `git update-ref --stdin` need review (`provenance-notes`).
- Pointing git at the notes ref through `GIT_NOTES_REF` is denied (`env-poison`), and
  `git config core.notesRef` and writes under `.git` need review (`git-internals`).
- Other notes refs, reading history and `openmoat provenance` itself stay as they were.
- A forged note needs the cited events' chain hashes, which only the audit log holds,
  and agents cannot read the log. `--verify` catches it.

## Limits

- **Only commits made on a machine with OpenMoat, and only what its hook saw.** A script
  that writes files, an editor, or an agent without OpenMoat leaves no record. The
  record of each session's newest write of a file is kept for 30 days.
- **Lines only when one recorded write made the whole change.** Several edits of a
  file by one session keep only the last one, so the file is claimed but its lines are
  not.
- **Notes can be stripped, never pushed, or not fetched. A missing note proves
  nothing**, and a commit with no record is not shown to be a person's.
- **Only on the machine that wrote a note can it be checked.** In CI a note is a claim.
  A note that claims more agent work than happened only invites more review.
- Notes are not signed (ADR-056 §7).
