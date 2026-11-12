# ADR-082: Use newer Landlock ABIs where the kernel has them, beside seccomp, and no eBPF

Status: accepted · Date: 2026-11-11 · Builds on ADR-018 (sandboxes from the IR), ADR-028 (guard relay), ADR-077 (full boundary), ADR-080 (Isolated tier by default)

## Context

On Linux `openmoat run` applies Landlock rules for files and TCP ports, and a seccomp
filter for what Landlock at its floor ABI cannot scope: it refuses Unix sockets, UDP,
new namespaces and joining one, `ptrace`, the keyrings and `TIOCSTI`
([SANDBOX.md](../SANDBOX.md)). Both go on the one thread that starts the agent, so
OpenMoat's own proxy and relay threads stay outside them (`commands/run/linux.rs`).
The floor is ABI 4 (Linux 6.7, TCP by port); ABI 6 (scopes) was added where present.

eBPF (BPF LSM, Tetragon-style overrides) could decide more finely, but loading a
program needs `CAP_BPF` or `CAP_SYS_ADMIN`, or a BPF token a privileged process
delegates (<https://docs.kernel.org/admin-guide/sysctl/kernel.html>,
<https://docs.ebpf.io/linux/concepts/token/>). OpenMoat runs as the person, with no
daemon and no root.

### What each Landlock ABI adds, checked

Checked on 2026-11-11 against the kernel's documentation
(<https://docs.kernel.org/userspace-api/landlock.html>, then at 7.4.0-rc2, and the
per-release copies at <https://www.kernel.org/doc/html/vX.Y/userspace-api/landlock.html>
for 6.15, 7.0, 7.1, 7.2 and 7.3: the newest ABI each describes) and against the
`landlock` crate in `Cargo.lock`, 0.4.7 (its `ABI` enum, `CHANGELOG.md` and bindings):

| ABI | First Linux | Adds (kernel names) | In `landlock` 0.4.7 |
|---|---|---|---|
| 4 | 6.7 | `LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP` | yes |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` | yes |
| 6 | 6.12 | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL` | yes |
| 7 | 6.15 | `LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`, `_LOG_NEW_EXEC_ON`, `_LOG_SUBDOMAINS_OFF` | yes (0.4.5) |
| 8 | 7.0 | `LANDLOCK_RESTRICT_SELF_TSYNC` | yes (0.4.6) |
| 9 | 7.1 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` | yes (0.4.7, newest it knows) |
| 10 | 7.2 | `LANDLOCK_ACCESS_NET_BIND_UDP`, `LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP`, `LANDLOCK_ADD_RULE_QUIET` and the `quiet_*` fields | no |
| 11 | 7.3 | `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS` | no |
| 12 | 7.4 (release candidate on 2026-11-11) | `LANDLOCK_PERMISSION_CAPABILITY_USE`, `LANDLOCK_PERMISSION_NAMESPACE_USE`, `LANDLOCK_RULE_CAPABILITY`, `LANDLOCK_RULE_NAMESPACE` | no |

All are usable unprivileged. Where the draft of this ADR was wrong:

- It listed ABIs 7 to 12 as if all could be used. The crate stops at ABI 9; ABIs 10
  to 12 need a newer crate or a raw-syscall module, and the workspace forbids
  `unsafe_code`. So the UDP and namespace steps wait for the crate.
- ABI 10 also adds the `quiet` rule flag; ABI 12's capability and namespace controls
  are *permissions* with their own rule types, not access rights, and 7.4 was not
  released yet.
- It said "TSYNC used when present". That would be wrong here: TSYNC puts the
  ruleset on every thread of the process, which would restrict OpenMoat's proxy
  thread and the relay threads that connect to the proxy's Unix socket in the network
  namespace (`linux/isolate.rs`). The agent is started from the one restricted thread,
  so every process it starts inherits the rules already; TSYNC adds nothing.
- It took `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` for "connecting to pathname sockets".
  The kernel's text is narrower and wider at once: it covers `connect(2)` and
  `sendmsg(2)` with an explicit address, and only to sockets created *outside* the
  Landlock domain (the same semantics as the scopes); a socket made inside stays
  reachable. A refusal is `EACCES`.
- It assumed seccomp's Unix-socket refusal was complete. It is not: `socketpair()`
  was allowed for every type, and a datagram pair can be connected again or sent to
  with an address, which reaches any pathname datagram socket (`/dev/log`, journald's
  socket) that the person may write. Landlock below ABI 9 does not look at that path.

## Decision

1. **No eBPF in OpenMoat.** Not as enforcement, not as a required observer.
2. **A Landlock ABI ladder** (`sandbox/landlock/abi.rs`, one table): per ABI from the
   floor up, what it adds, whether `openmoat run` uses it and what holds without it.
   A step is only ever added beside what holds without it; no seccomp rule is removed
   because Landlock covers the same calls, so an older kernel falls back to exactly
   the previous behaviour, never to less.
   - ABI 4: the floor, a hard requirement, as before.
   - ABI 5: not used. Handling `IOCTL_DEV` would refuse the terminal's own `ioctl`
     calls unless granted per device; seccomp keeps refusing `TIOCSTI` and `TIOCLINUX`.
   - ABI 6: used where present, as before.
   - ABI 7: not used; the kernel's logging defaults stay. OpenMoat does not read the
     kernel's audit log.
   - ABI 8: not used, on purpose (above).
   - ABI 9: **used where present.** The ruleset handles `RESOLVE_UNIX` and no rule
     grants it, so a pathname Unix socket made outside the sandbox cannot be
     connected or sent to, beside the seccomp filter.
   - ABI 10 and 12: not used until the crate has them; the seccomp filter keeps
     refusing UDP and namespaces.
   - ABI 11: nothing to add; `no_new_privs` is set before the rules apply.
3. **The seccomp filter refuses datagram socket pairs** (`socketpair()` is allowed
   only for `SOCK_STREAM` and `SOCK_SEQPACKET`, with `SOCK_NONBLOCK` and
   `SOCK_CLOEXEC`), so the gap above is closed on every kernel, and ABI 9 holds the
   same where present.
4. **Never quieter.** The kernel's ABI is read without restricting anything (the
   crate's `RestrictSelf` with no flag skips the syscall; `no_new_privs` is not set)
   and shown:
   - `openmoat doctor`: one row, `landlock  Landlock ABI N here: openmoat run applies
     ABI 4, 6[, 9]`, naming what the seccomp filter alone holds; a warning below the
     floor; each step with `--verbose`;
   - `openmoat sandbox show`: the same lines, and `lightweight.landlock.abi` in JSON;
   - `openmoat run --verbose`: the same lines before the agent starts;
   - the audit log: every Linux run writes a row (host `moat-run`, tool `landlock`,
     rule `run-landlock-abi`) with the summary, before the agent starts. A row that
     cannot be written stops the run, as the tier's row does (ADR-080).
5. **The relay stays TCP.** A relay over a pathname Unix socket under ABI 9 is not
   built; the TCP path is the one EVIDENCE.md proves.

## What this must never do

- Remove a seccomp rule because Landlock "should" cover it.
- Ask for root, a capability, a setuid helper or a daemon.
- Put any of this in `openmoat-core`: the IR stays as it is; the Linux backend reads
  the ABI.

## Tests

- `sandbox/landlock/abi/tests.rs` (every OS): the table runs from the floor one ABI
  at a time; below the floor and without Landlock the summary says `openmoat run`
  refuses; an ABI 6 kernel applies 4 and 6 and names the seccomp fallback for 9; an
  ABI 12 kernel applies 4, 6 and 9 and says ABI 10 is available but not used; a
  kernel newer than the table says so; the JSON.
- `commands/run/linux/abi.rs` (Linux): the ladder matches the crate (a step marked
  used is one the crate knows, a step marked not in the crate is past its newest
  ABI, so a crate upgrade fails this test until the ladder moves); the status maps
  to the kernel's ABI, also one newer than the crate; reading it leaves
  `NoNewPrivs` as it was.
- `commands/run/linux/tests.rs` (Linux): the real seccomp filter refuses a datagram
  pair with `EPERM` and keeps the stream pair; the Landlock rules alone, on a thread
  of their own, refuse a datagram send to a socket bound outside with `EACCES` on a
  kernel with ABI 9, and let it through below (the case the filter closes).
- `tests/e2e/run/unix_sockets.rs` (Linux): under `openmoat run`, a datagram pair is
  refused, stream and sequenced-packet pairs work, and nothing reaches a datagram
  socket bound outside the project; the run's audit log has its `run-landlock-abi`
  row.

## Consequences

- On the kernels CI runs today (below 7.1) the ABI 9 rule is not exercised by the
  e2e tests; the unit test above shows the fallback there, and covers ABI 9 on any
  runner that has it.
- A program that needs a datagram `socketpair()` fails under `openmoat run` with
  `EPERM`. Stream and sequenced-packet pairs, which Node, Python and Chromium use,
  still work.
- Moving to a crate with ABI 10 to 12 is a later change: add the UDP and
  namespace steps beside seccomp, with differential fixtures for each.

## Open questions

- When ABI 9 and later reach Ubuntu LTS, Debian stable, Fedora and the WSL2 kernel.
- A Tetragon and Falco page beside OpenMoat (how to join their events to OpenMoat's
  audit rows by session id): docs only, no code.
