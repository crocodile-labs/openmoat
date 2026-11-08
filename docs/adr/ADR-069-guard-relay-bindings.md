# ADR-069: the guard relay is bound to the run's sandbox, host and sessions

Status: accepted · Date: 2026-11-08 · Amends ADR-028, ADR-045

## Context

ADR-028 lets the hooks inside `openmoat run` send their calls to the `openmoat run`
process, which decides them outside the sandbox. Two variables name the relay:
`MOAT_GUARD_SOCKET` and `MOAT_GUARD_TOKEN`.

The guard relayed whenever it found both variables. Nothing checked that it really ran
in a run's sandbox. A host that builds its hooks' environment from a file or setting
OpenMoat does not guard could hand them to a hook outside any run. A listener that
repeats the nonce would then answer every call.

## Decision

1. **Relay only from the run's sandbox.** A guard with both variables first opens its
   own lock (`guard_relay/inside.rs`). It relays only when it cannot, and the refusal
   is the one the run's sandbox gives:
   - macOS: `EPERM` from Seatbelt. A file mode gives `EACCES` and a missing file
     `ENOENT`; neither counts.
   - Linux: any failure while a seccomp filter holds the process (`Seccomp: 2` in
     `/proc/self/status`). `openmoat run` always applies one, under `--isolate` too, and
     no process can drop it. Landlock refuses with `EACCES`, as a file mode does, so
     the error alone cannot tell.
   - Elsewhere `openmoat run` has no sandbox, so the guard never relays.

   Anywhere else the guard decides the call itself. It records a row beside the call's
   own: tool `guard`, verdict `deny`, rule `run-guard-outside`. That row says the relay
   was refused, not the call. The heartbeat (ADR-042) uses the same test.

## Consequences

- A hook outside any run whose environment names a relay is decided as it would be
  without one. The person finds the setting from the `run-guard-outside` row.
- The same hook environment can still set `MOAT_HOME`. That picks the state directory,
  and with it the policy and the lock. Inside another seccomp sandbox on Linux (a
  container's default profile), it can point `MOAT_HOME` at a directory the guard
  cannot open and get the relay. The agent's own shell cannot set `MOAT_*`
  (`env-poison`), and the known hosts' settings files are under `kernel-self`. Moving
  the state directory into the hook command line `init` writes would close this. It is
  not done here, because every host's hook command and its pin would change.
