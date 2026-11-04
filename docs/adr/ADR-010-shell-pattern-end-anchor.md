# ADR-010: A trailing `$` anchors the end of a shell pattern

Status: accepted · Date: 2026-10-05

## Context

Shell rules are token prefixes (`DESIGN.md` §6.2): `git status` also matches
`git status --short`. That is the right default, but it cannot express "this program with
no arguments". `env`, `printenv`, `set`, `export -p` and `declare -x` print every variable,
secrets included (T3), while `env FOO=1 cmd`, `set -e` and `printenv HOME` are ordinary.
A deny rule `env` would also deny every `env FOO=1 …` wrapper; the default policy
therefore only held the dumps for review (audit 2026-10-05).

## Decision

- A bare `$` as the **last** token of a shell pattern matches only the end of argv.
  `env $` matches `["env"]` and nothing longer. `*` before it works as usual
  (`* | sh $`).
- `$` anywhere else is an ordinary one-token glob, so existing patterns keep their
  meaning. A pattern consisting only of `$` is empty and fails lint.
- The default policy gains the deny group `env-dump` (`env $`, `printenv $`, `set $`,
  `export $`, `export -p $`, `declare $`, `declare -p $`, `declare -x $`, `typeset …`,
  `-0`/`--null` forms and `*/env $`, `*/printenv $`).
- Separately, `printenv NAME…` produces `env.read` atoms, so `env-secrets` applies to it.

## Consequences

- Policies can express exact commands. Pipelines still work: `env | grep KEY` is denied
  because the sub-command `env` is matched on its own.
- A literal trailing `$` argument can no longer be matched with a bare `$`; write `[$]`.
- Dumps through other programs (`cat /proc/self/environ`, `python -c 'print(os.environ)'`,
  `node -p process.env`) are not covered by this rule; a scrubbed environment under
  `moat exec` is the complete answer.
