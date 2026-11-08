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

## Amendment 2026-11-08: standing grants can end

Session grants end 24 hours after they are written (`GRANT_TTL_MS`), but every entry of
`approved.yaml`, an `--always` rule for a command or files, a `--site` rule and a `--dir`
grant, lasted until a person removed it. A site or directory needed for an afternoon stayed
open for good unless someone remembered to take it out.

- `moat allow --always`, `--site` and `--dir` take `--for <n>s|m|h|d|w` (above 0, at most
  366 days; the span parser `report --since` uses, which now also reads `s` and `m`). The
  overlay stores an absolute window under `expires:`, keyed by the entry's id: `from`, when
  it was granted (rounded down to the second), and `until`, when it ends (rounded up), both
  RFC 3339 UTC. Without `--for` nothing changes: no window, the entry lasts until removed.
  A map beside the entries, rather than a field in each, keeps `RuleGroup` (the core's
  policy shape, `deny_unknown_fields`) free of a time concept the core does not have, and
  covers rules and directory grants alike.
- When the policy is loaded (`Home::with_merged`), an entry with a window is merged only
  while `from <= now < until`. The overlay is already read with the policy, so the only cost
  per hook call is reading the clock. A window that cannot be read (any other text or shape,
  or `until` not after `from`) counts as ended: a hand edit that breaks one ends the grant
  rather than making it permanent, and it does not stop the overlay from loading.
- Clock: the window is wall-clock time, as session grants are. A clock that reads earlier
  than `from` (set back since the grant) ends the grant too, as a session grant whose
  creation time lies in the future is invalid; so moving the clock back can stretch a grant
  by at most the amount the clock moved and never revive it from before it was made, and
  moving it forward only ends grants early. A monotonic or audit-row order (as session grants
  use for taint answers) does not survive the process and is not needed for a bound that
  the person set. Setting the system clock needs administrator rights, which already reach
  past every protection here, so the clock is trusted, not a boundary.
- Granting the same thing again (same `net` host, same directory spellings, or a rule with
  the same patterns) keeps the entry's id and replaces its window with the one given now, or
  removes it without `--for`. Nothing extends a window by itself, and two entries for the
  same thing, one ended and one not, never arise from `moat allow`.
- `moat allow --prune` removes every entry not in force and every window that names no
  entry, checks that the policy still lints, re-pins and updates the sandbox settings, as
  `--remove` does; it is part of `moat allow` because that is the command that writes the
  overlay and holds the terminal and lock checks, while `moat allowed` stays read-only.
  `moat allowed` shows each window and marks ended ones `EXPIRED`; `moat status` and
  `moat doctor` name entries that ended or end within 24 hours. Ids are numbered past every
  id a window names, so a window left behind never lands on a new entry.
- The file is written as `version: 2` while it holds a window and as `version: 1` otherwise.
  A release that does not know windows refuses version 2, so after a downgrade the policy
  fails to load and the hook denies (invariant 4) instead of reading every grant as
  permanent; a person removes the windows or upgrades again.
- An ended grant leaves the hook's decision at once. The OS layers compiled from the policy
  earlier keep it until rewritten: the agents' sandbox settings until `moat allow --prune`
  or `moat sandbox sync` (`moat doctor` reports them out of date), and a running `moat run`
  session or `moat proxy` until it restarts (`docs/LIMITS.md`). `--session` scoping for
  sites and directories was not added: hosts do not report when a session ends, so it would
  be the 24-hour lifetime again, which `--for 24h` already gives without a second store.
