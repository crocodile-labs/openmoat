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

2. **Only the run's agent and sessions.** Every process in the run's sandbox holds
   `MOAT_GUARD_TOKEN`, not only the agent's hooks. `kernel-self` denies the agent's shell
   the `openmoat guard` command line, but a script or a test runner can open the port
   and send any payload. So the service (`guard_relay/service.rs`) decides a call only
   when it is the run's:
   - *Host.* The host of the program `openmoat run` started (`Owner::Agent`). For a
     program OpenMoat does not know, the host of the first call. The call's `--host`,
     or the host its payload says it comes from (the Continue CLI through Claude Code's
     hook), must be that one.
   - *Session.* One the service took before. A new one is taken when the audit log
     holds no row of it. A session with rows is taken only on the agent's own session
     start for it, when its first row is the same host's: that is a resume. A `run-…`
     session is never taken, and a run takes at most 64 sessions.

   Any other call gets a deny (exit 2) and a row in the run's session: tool `guard`,
   rule `run-guard-host` or `run-guard-session`. A payload the guard cannot parse is
   still sent to it, and it denies that call (`kernel-error`).

3. **No MCP tickets from relayed calls (amends ADR-045).** Inside the run no
   `openmoat mcp proxy` can read the audit log, so a wrapped server refuses to start
   there (ADR-049). A ticket from a relayed call could only let a gateway outside the
   run pass a call that no hook outside decided. So `openmoat guard --relayed` writes
   none. The call's row is still written.

## Consequences

- Code in the run's sandbox can still add rows to the run's own sessions, with payloads
  it chose. Each is decided by the policy as the agent's call would be. It cannot reach
  a session outside the run, another agent, a ticket or a proxy credential.
- An agent that starts another agent inside the run gets the second agent's hook calls
  denied (`run-guard-host`). Give each agent its own `openmoat run`.
- A host that starts sessions without a session start event, after its first one, gets
  their calls decided only while the audit log has no rows of those sessions. That is
  always true of a new session.
- A hook outside any run whose environment names a relay is decided as it would be
  without one. The person finds the setting from the `run-guard-outside` row.
- The same hook environment can still set `MOAT_HOME`. That picks the state directory,
  and with it the policy and the lock. Inside another seccomp sandbox on Linux (a
  container's default profile), it can point `MOAT_HOME` at a directory the guard
  cannot open and get the relay. The agent's own shell cannot set `MOAT_*`
  (`env-poison`), and the known hosts' settings files are under `kernel-self`. Moving
  the state directory into the hook command line `init` writes would close this. It is
  not done here, because every host's hook command and its pin would change.
