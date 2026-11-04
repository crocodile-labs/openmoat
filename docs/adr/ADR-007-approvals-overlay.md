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
