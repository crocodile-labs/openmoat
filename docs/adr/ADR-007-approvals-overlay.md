# ADR-007: Approvals as session grants plus a pinned policy overlay

Status: accepted · Date: 2026-10-03 (#20, #21)

## Context

`review` is answered by the host's own permission prompt (`DESIGN.md` §8.3 defers a prompt
of our own). Saying yes to the same `npm install` in every session is the prompt fatigue
that makes people turn security tools off (`STRENGTH.md` W6), and hand-editing
`policy.yaml` and re-pinning for one command is too much ceremony. Appending to
`policy.yaml` from a command would churn the user's file and the lock on every approval.

## Decision

- `moat allow --last` (or `moat allow <command> --host … --session …`) writes a session
  grant to `~/.moat/approvals.json`: host id, session id, exact command text.
  `moat guard` consults grants only when the verdict is `review` and the action is a shell
  command; a match becomes `allow` with rule `approved-session`. Grants never override a
  `deny`.
- `moat allow … --always` appends an allow rule group to `~/.moat/policy.d/approved.yaml`
  with id `approved-<n>` and a provenance `reason`. The overlay is merged into the
  policy's `allow` list at load time; `policy.yaml` is never rewritten. Overlay ids must
  start with `approved-`.
- Both files are pinned by the lock (ADR-006); `moat allow` re-pins after writing, must
  run from an interactive terminal, and is denied to agents by the default policy
  (`kernel-self`: `moat allow*`).
- Grant matching is exact text per host session; overlay rules have the normal shell
  pattern semantics, so an approved `npm install left-pad` is a prefix.

## Consequences

- A `review` can be made to stick without editing YAML, and the audit log names the rule
  that did it.
- The terminal check keeps hooks and scripts out; it is not a defence against a person
  running `script` or `expect`. The lock is what stops an agent from granting itself
  anything.
- A grant for the exact command also clears an `unparseable` review for it; that is intended
  (the person read the command) and is why grants are exact-match only.
- A terminal prompt of our own and Telegram approvals (`DESIGN.md` §8.4) will write the
  same two files rather than introduce a third store.

## Amendment 2026-11-07: directory grants follow the current policy

`moat allow --dir <D>` wrote an allow rule for `D` and `D/**` whose write exclusions were a
copy of the `.git` and `runs-later` paths of that day. An overlay allow overrides a
`review`, so every protection a later release added (all of `.vscode/`, `.idea/`, `.npmrc`,
`.cargo/config*`, a virtual environment's `bin/`, `.devcontainer`, …) was allowed inside `D`
without review.

- A directory grant now stores only what the person chose: the directory (as written and
  with its symlinks resolved) under `dirs:` in `approved.yaml`, with its id and reason.
- Each time the policy is loaded the grant becomes an allow rule that reads and writes `D`
  and `D/**` and leaves out of the writes every path a `review` rule of that policy (packs
  included) holds writes to, as it applies in `D`: `${project}/<p>` as `D/<p>`, `**/<p>` as
  `D/**/<p>`, and a fixed path (`~/…`, `/usr/local/bin/**`) when it can lie in `D`. So a
  directory grant never answers a review of the policy, today's or a later one's. Deny rules
  need no exclusion: no allow overrides a deny (invariant 1). Reads keep no exclusions, as
  before: the only per-path read review is the whole-home sweep, which a grant cannot name.
  This is the simplest rule that keeps the old grants' meaning (they copied exactly these
  `review` paths) and makes it follow the policy; the exclusions keep the shapes the OS
  sandbox generators already handle for a granted directory.
- A grant of one exact path (`--always` for a reviewed file) still overrides the review it
  was approved for: the person read that path.
- `moat policy upgrade` recognises a rule an earlier `--dir` wrote by its shape (its
  `--dir` reason, `D` and `D/**` read and written, exclusions only inside `D`, nothing
  else) and offers to turn it into a grant with the same id, re-pinned with the rest. An
  old exclusion the policy no longer names is kept in the grant's `except:`, so the change
  never allows more. `moat doctor` and `moat status` list such a rule until then.
