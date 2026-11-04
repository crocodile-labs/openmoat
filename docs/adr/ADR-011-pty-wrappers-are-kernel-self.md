# ADR-011: Pseudo-terminal wrappers around `moat allow` / `doctor --accept` are denied by pattern

Status: accepted · Date: 2026-10-05 · Refines ADR-007

## Context

`moat allow`, `moat doctor --accept`, `moat init` and `moat policy …` re-pin or widen the
policy, so the default policy denies them to agents (`kernel-self`) and the commands refuse
to run without a terminal (ADR-006, ADR-007). The terminal check looks at whether stdin and
stdout are a TTY. An agent can give a command a pseudo-terminal: `script -q /dev/null moat
allow --last`, `script -qc 'moat allow --last' /dev/null`, `expect -c 'spawn moat allow …'`
or `unbuffer moat allow …`. `kernel-self` matched `moat …` as the first word only, so the
`script` and `expect` forms only needed review (audit 2026-10-05).

## Decision

- The `kernel-self` shell list also denies `script`, `expect` and `unbuffer` invocations that
  run `moat allow|doctor|init|policy`, as separate arguments (BSD `script file cmd …`,
  `unbuffer cmd …`) or inside one argument (Linux `script -c '…'`, `expect -c 'spawn …'`),
  with `moat` by name or by absolute path.
- The terminal check itself is unchanged. It still keeps hooks and scripts out, and the
  lock still stops a re-pin that did not come from a person.

## Consequences

- The named wrappers are denied before they run.
- This is a pattern list, not a guarantee. Other ways to allocate a pty (`python -c 'import
  pty; pty.spawn(…)'`, `socat … pty`, a compiled helper, a terminal multiplexer such as
  `tmux send-keys`) are not matched. The complete answer is OS enforcement: under
  `moat exec` the agent's process tree cannot write `~/.moat` at all, whatever terminal it
  fakes.
- `script` used to record an ordinary command (`script -q build.log make test`) is not
  affected.
