# ADR-004: Exit code contract for hooks

Status: accepted · Date: 2026-10-02

## Context

Claude Code and Codex treat a hook's exit code 2 as "block the tool call" and other
non-zero codes as non-blocking errors. `clap` exits with 2 on usage errors. A kernel
crash or a mistyped flag must never be read by a host as a deliberate block, and a
deliberate block must never be read as a crash.

## Decision

| Code | Meaning |
|---|---|
| 0 | allow, or review (called `ask` before ADR-053; the host prompts the user), or success of a non-guard command |
| 2 | deny |
| 3 | unresolved review from `moat policy check` (adapters treat as deny) |
| 64 | usage or configuration error; adapters fail closed |

`main` parses arguments explicitly so clap's usage errors map to 64. `moat guard`
answers every internal failure with a `deny` response and exit 2.

## Consequences

- Hosts see exactly one blocking code.
- End-to-end tests assert exit codes, not only output.
- Future commands must not use 2 or 3 for anything else.
