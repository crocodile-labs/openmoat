# ADR-122: `openmoat run --listen` on macOS stays refused

Status: accepted · Date: 2026-11-24 · Builds on ADR-108 §7 (one loopback port to listen
on), ADR-023 (the Isolated tier on macOS), ADR-018 (OS enforcement)

## Context

ADR-108 §7 lets `openmoat run --listen PORT` serve one TCP port on loopback, for
OpenClaw's Gateway. On Linux the port lives inside the agent's own network namespace,
whose only interface is loopback, and `openmoat run` forwards `127.0.0.1:PORT` in. On
macOS the Seatbelt profile allowed `(network-bind (local ip "localhost:PORT"))`, and the
end-to-end test (`run/listen.rs`, CI's macOS 15 runner) found that a bind to every
address (`0.0.0.0:PORT`) goes through that filter too: the port could be reachable from
the network. `openmoat run` has refused `--listen` on macOS since (`listen_refused_here`),
so OpenClaw gets no confined start there.

This ADR records what was examined to lift that refusal and why none of it holds.

## What was examined

1. **Another Seatbelt filter.** The profile language's network filters are `(local …)`
   and `(remote …)` over `ip`, `ip4`, `ip6`, `tcp`, `tcp4`, `tcp6`, `udp`, `udp4` and
   `udp6`, and the address part takes only `*` or `localhost` with a port or `*`
   (Apple publishes no reference for the language; every network filter in the
   profiles macOS 12 ships in `/System/Library/Sandbox/Profiles` names `*` or
   `localhost`, such as `(local tcp "*:445")` and `(remote ip "localhost:631")`). There is
   no form that names `0.0.0.0` to deny it, nor one that means "loopback and not the
   unspecified address". Seatbelt's own reading of `localhost` for a bind is what lets
   the unspecified address through.
2. **Holding the unspecified address first ("wildcard guard sockets").** `openmoat run`,
   outside the sandbox, binds `0.0.0.0:PORT` and `[::]:PORT` (`IPV6_V6ONLY`), TCP and
   UDP, with neither `SO_REUSEADDR` nor `SO_REUSEPORT`, before it starts the agent, and
   never listens on them. Under the BSD binding rules a second bind to the same
   unspecified address and port then fails with `EADDRINUSE` whatever options the agent
   sets, while a bind to `127.0.0.1:PORT` with `SO_REUSEADDR` (Node, Go and Python
   servers set it) succeeds and takes loopback's connections. A connection from the
   network to the machine's address meets the bound, not listening, guard and is
   refused. The agent cannot close the guards: Seatbelt lets it signal and inspect only
   processes of its own sandbox. This holds **while `openmoat run` lives**, and fails
   after it:
   - The guards are sockets of `openmoat run`'s process. When the agent's first process
     exits, `openmoat run` exits; a process the agent left behind (`nohup`, a daemon,
     `setsid`) keeps its sandbox and its `network-bind` allowance, and can then bind
     `0.0.0.0:PORT`. macOS gives an unprivileged program no way to find or end the
     processes of one sandbox once they left the process group: no PID namespace,
     no `--die-with-parent`, and the audit session cannot be set without privilege. On
     Linux the namespace dies with `moat isolated`, so ADR-108's design has no such
     afterlife.
   - A server that binds loopback without `SO_REUSEADDR` would fail to start, which is
     a compatibility cost, not a hole.
3. **A relay, as on Linux.** The agent would serve on an address only it can reach and
   `openmoat run` would relay `127.0.0.1:PORT` to it. On macOS that address is still a
   TCP port of the host's network stack (Seatbelt has no private interface), so the agent's
   bind to it has the same `localhost` filter and the same unspecified-address hole; a
   Unix socket would need OpenClaw to serve on one, which it does not.
4. **Filtering what arrives instead of what binds.** `(network-inbound (remote ip
   "localhost:*"))` would refuse a connection from another machine at `accept` if the
   kernel checked the peer there. That is undocumented, and a refusal at `accept` comes
   after the handshake; it could not be checked on the development machine (Seatbelt
   does not nest, and the runner's behaviour is not specified). Not a basis for a
   security claim.
5. **The system's own filters.** `pf` and the Application Firewall need administrator
   rights per run; a Network Extension content filter needs a signed system extension.
   `openmoat run` starts without either.

## Decision

1. `openmoat run --listen` stays refused on macOS. The refusal now names this ADR's page
   and the command that runs OpenClaw under its hook, so a person sees what to do.
2. OpenClaw keeps no confined start on macOS: the spec, `openmoat status`, `openmoat
   init`'s question and the generated docs are unchanged.
3. The way to a held port on macOS is ADR-023's Isolated tier: a Linux guest whose
   network is its own, with the port forwarded in, as on Linux. When it lands, `--listen`
   follows the Linux design there.
4. The wildcard guards (2) are not shipped as a partial answer: a boundary that lasts
   only as long as the agent's first process is the kind of claim ADR-018 rules out.

## Consequences

- Nothing changes for a person on macOS: OpenClaw runs under its hook, as in 0.27.0;
  `openmoat run` without `--listen` is unchanged for every agent.
- The end-to-end test `run/listen.rs` keeps asserting the refusal on macOS (CI's macOS
  job), and the Linux assertions are unchanged.
- If Apple documents a Seatbelt filter that excludes the unspecified address, or a way to
  end every process of a sandbox, this ADR is the place to supersede: the guard sockets
  of (2) plus such a guarantee would hold, and the e2e test already probes a bind to
  `0.0.0.0` and to loopback.
