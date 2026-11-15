# ADR-100: A host's deny exit code is a fact of its spec

Status: accepted · Date: 2026-11-14 · Amends ADR-004 (exit code contract) for hosts
that read a block from the hook's output only

## Context

ADR-004 gives a deny exit 2, the code Claude Code and Codex read as "block". Not every
host reads it so. Antigravity CLI's hooks page documents one way for a `PreToolUse` hook
to block, `{"decision": "deny"}` on stdout, and names no exit code; its build-plugins
guide says a hook must "exit with code `0` and write a JSON response object to
`stdout`", and that "any non-zero exit code is logged as a hook execution error and
ignored (failing open)". The weekly `latest agents` run 43254846914 (2026-11-12) saw a
real `agy` block a call whose hook exited 1 with no output, and one whose hook binary was
missing, which contradicts that sentence. Until a run settles which reading holds, a deny
that exits 2 blocks under one of them only; a deny on stdout with exit 0 blocks under
both. The package's guard script already exited 0 (ADR-099, `PluginSpec::deny_exit`)
while `openmoat init`'s hook exited 2.

## Decision

- `HostSpec::deny_exit` is the exit code `openmoat guard` gives a deny whose response it
  wrote, and the code the host's package's guard script blocks with: 2 (the default) or
  0. `PluginSpec::deny_exit` is gone; the package reads the host's fact.
- Antigravity CLI's is 0, with the evidence for each reading in its spec and `HOST.md`
  as an open fact.
- A deny the guard could not write (stdout closed) still exits 2: with no output, the
  exit code is the only signal left.
- The weekly job's record carries `deny_exit` where it is not 2, and `check.py reply`
  expects it.

## Consequences

- No exit code changes meaning: 0 never allows where the response says deny, and 2 is
  still only a deny.
- If a later `agy` turns out to ignore a deny on stdout with exit 0, the weekly job's
  denied call fails, as it does today for exit 2.
