# ADR-028: Hook decisions inside `moat run` come from the run's own process

Status: accepted · Date: 2026-10-18 · Refines ADR-018 (Lightweight tier) and ADR-027
(per-session proxy credentials)

## Context

`moat run -- <agent>` puts the agent and everything it starts in one sandbox. The
agent's hooks are among those processes: Claude Code, Codex and the others start `moat
guard` as their child, so it runs inside the same sandbox. That sandbox gives no read
or write access to OpenMoat's home (`~/.moat`):

- macOS: the Seatbelt profile starts from `(deny default)` and never grants the home,
  and the policy's `kernel-self` rule denies writes to it last.
- Linux: Landlock grants only the platform paths, the program, the project's trees, the
  read roots, the temp directory and `--write` paths, and refuses a grant inside a
  denied path.

`moat guard` must read the policy lock and the policy before it decides, and must
write the audit row before it answers (ADR-004, invariant 9). Inside `moat run` both
fail, so every governed call was denied as a `kernel-error`, nothing was recorded, and
the run's proxy never saw the link rows that carry session taint to egress (ADR-027,
Consequences).

Opening the home to the sandbox is not an option: a process in there could then forge
audit rows, rewrite the lock or the policy, and read brokered secret sources.

## Decision

The `moat run` process, which already runs outside the sandbox and serves the run's
proxy, also decides the hook calls made inside it.

### Transport: the proxy's port

The relay uses the one connection the sandbox already allows: TCP to the proxy's
loopback port.

- A connection that starts with `MOAT-GUARD/1\n` is handed to the decision service
  instead of being read as an HTTP request (`openmoat_proxy::LocalService`). No HTTP
  request line starts with it, and a connection that sends only part of it is read as
  HTTP and refused as malformed.
- Until it is answered, such a connection counts against the proxy's slots and the
  share of connections that have not authenticated yet (ADR-027), so it cannot hold
  more than the proxy already allows a silent client.

The design first proposed a Unix socket in a private directory, with one Seatbelt rule
to connect to it. The code argues against it:

- On Linux, the seccomp filter refuses `socket()` for every family but IPv4 and IPv6
  streams. Landlock does not restrict connecting to a Unix socket by path at the ABI
  `moat run` uses (4, with ABI 6 scoping only for abstract sockets), so the filter is
  the one thing that keeps the user's D-Bus session bus, the Docker socket and the SSH
  agent out of reach. Allowing Unix sockets for the hook would reopen all of them.
- A second TCP port would be a second port Landlock allows on every host, since
  Landlock restricts connections by port only.
- Under `--isolate`, the proxy's port is already relayed into bubblewrap's network
  namespace; a socket would need another bind mount and relay.

So the profiles do not change at all: the Seatbelt golden and the Landlock rules are
the same as before, on both tiers.

### The environment

`moat run` gives the agent two more variables:

- `MOAT_GUARD_SOCKET`: the proxy's address, `127.0.0.1:<port>`.
- `MOAT_GUARD_TOKEN`: 64 hex characters (256 bits) from `/dev/urandom`, made for this
  run and never written to disk.

### The sandboxed guard

`moat guard` checks for the variables first. With both set it never opens OpenMoat's
home. It:

1. reads the payload from standard input with the usual 1 MiB limit;
2. sends the token, a random 128-bit nonce, its `--host`, its working directory,
   whether the Continue CLI started it, and the raw payload;
3. waits at most what is left of the guard's 10 s budget;
4. prints the reply's standard output and error as they came, and exits with its code.

The reply must start with `MOAT-GUARD-REPLY/1\n`, repeat the nonce, and carry exit code
0 or 2. Anything else denies with a `kernel-error` in the format the payload's hook
expects: only one of the variables set, an address that is not loopback, a failed
connection, a timeout, an oversize payload, a reply for another request, a malformed
reply, or a connection closed without one. Each field has a limit, checked from its
length before it is read. Nothing is recorded from inside the sandbox.

### The decision outside

The service (`crates/openmoat-cli/src/guard_relay/service.rs`):

- compares the token in full, in time that does not depend on where a guess differs
  (`constant_time_eq`);
- with a wrong token, records a row in the run's audit session (host `moat-run`, tool
  `guard`, rule `run-guard-token`, naming the host only when it is one OpenMoat knows)
  and closes the connection: the call gets no decision;
- with the right token, runs `moat guard --host <host>`, the binary of the `moat run`
  process, outside the sandbox. It gets the payload on its standard input, the run's
  `MOAT_RUN_SESSION`, the Continue CLI variable when the request says so, and the
  request's working directory when that is an existing absolute directory. The two
  relay variables are removed, so it decides itself.

That child is the same `moat guard` that runs outside `moat run`: lock check first,
the effective policy, grants, session taint, the audit row and the link row (ADR-027).
Any exit code but 0 is relayed as 2. An answer over 4 MiB is replaced by a deny.

### Egress taint

The child records with `MOAT_RUN_SESSION` set to the run's session, so the link rows of
ADR-027 are written. The run's proxy (`RunTaint`) folds the linked sessions' history
from the same audit log, so a secret read decided through the relay makes later proxy
requests to other hosts refused (`session-taint`).

### Windows

`moat run` refuses on Windows (no sandbox), sets neither variable, and nothing changes
there.

## Consequences

- Hooks work inside `moat run`: every governed call gets the real decision and an
  audit row, and session taint reaches the run's proxy.
- The sandbox still cannot read or write OpenMoat's home. A process in it can ask for
  a decision, and the decision recorded is the real one for the payload it sent. That
  is what a process outside `moat run` can do today by running `moat guard` itself. It
  cannot write a row with a verdict of its choosing, change the lock or the policy, or
  read a secret source.
- **What the token proves.** Every process in the sandbox can read the token from its
  environment, as with the proxy credential; they are all the run. The token keeps out
  processes outside the run (another user's, or one of the same user that never saw the
  agent's environment), which can reach a loopback port. A process of the same user
  outside the sandbox that can read the agent's environment can use it too
  (THREAT_MODEL.md). A sandboxed process can make the run's taint stricter, never
  looser: link rows only add sessions, and taint only tightens.
- **The endpoint cannot be taken over.** `moat run` holds the port for the whole run,
  and the sandbox lets nothing bind a port. The address comes from the environment the
  host started the hook with; a command in the sandbox cannot change the environment
  of hooks its host starts later.
- **A wrong token costs one audit row** per attempt.
- **Each hook call starts a second process**, outside the sandbox, as the host's own
  call of `moat guard` did before.
- **A slow reply.** Each read and write waits at most until the budget runs out; a
  reply that trickles in past it is ended by the guard's own 10 s deny.
- The proxy crate stays free of storage: the service is a trait the CLI implements.
