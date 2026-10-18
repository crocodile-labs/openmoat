# ADR-027: Per-session proxy credentials, with session taint at the egress proxy

Status: accepted · Date: 2026-10-18 · Refines ADR-020 (egress proxy and secrets broker)

## Context

ADR-020 put a default-deny proxy between the agent and the network. It records every
connection but cannot tell who made it. That leaves three gaps (#558, #555):

1. **Taint stops at the hook.** Session taint (POLICY.md §4.1) follows the host's tool
   calls: after a session reads secret material, the hook asks before its network calls.
   A script the hook never sees (`npm test`) can still post that material to an allowed
   host through the proxy, because the proxy's connections carry no session.
2. **Any local process can use the proxy.** It listens on loopback and asks for nothing,
   so another program on the machine, or another agent, can use it.
3. **One client can take every slot.** `max_connections` (256) is shared by everyone. A
   client that opens connections and sends nothing holds them for the handshake timeout,
   and a session that opens hundreds of tunnels starves the others.

## Decision

### Credential

In session mode every request must carry `Proxy-Authorization: Basic
base64(<session>:<token>)`, on `CONNECT` and on plain HTTP alike.

- `<session>` is the audit session id the request is recorded under.
- `<token>` is a random secret that only that session's processes were given.
- Clients send the credential when their proxy URL has userinfo. `moat run` sets
  `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` (both cases) to
  `http://<session>:<token>@127.0.0.1:<port>`.

`moat run` creates one credential per run:

- The session is `run-<ms>-<8 hex>`.
- The token is 64 hex characters (256 bits), read from `/dev/urandom`.
- Both use only letters, digits, `.`, `_` and `-`, so the URL needs no escaping
  (`openmoat_proxy::Credential::new` refuses anything else, and a token under 32
  characters).

The proxy (`openmoat-proxy/src/session.rs`):

- decodes the credential;
- compares it with every session it serves, in full, in time that does not depend on
  where a guess first differs (`constant_time_eq`);
- treats a request with two `Proxy-Authorization` headers as malformed.

The value is kept apart from the request (`ProxyCredential`: zeroed on drop, never
printed). It is already one of the hop-by-hop headers removed before a plain-HTTP head
is forwarded. It never reaches the upstream or an audit row.

### A request without a valid credential

In session mode, a request with a missing, malformed or wrong credential gets
`407 Proxy Authentication Required` with `Proxy-Authenticate: Basic realm="moat"`:

- the 407 does not say whether the id or the token was wrong;
- the request is recorded (`proxy-session`, no session) and goes nowhere;
- its host is not decided.

A client that sends its credential only after being challenged (git's default
`http.proxyAuthMethod=anyauth`) gets the 407 and retries on a new connection, because
the proxy closes this one. Each attempt without a credential is one audit row.

### Which proxy runs in session mode

- **`moat run` (both tiers):** session mode, serving its one session. The proxy is
  private to the run, on an ephemeral port, and ends with it.
- **The standalone `moat proxy`:** serves without sessions (`Proxy::sessions = None`).
  The host sandboxes that route through `sandbox.proxy_port` cannot send a credential:
  Claude Code's `httpProxyPort` and the variables Codex reads name a fixed port in
  settings written once for every session. At start-up the proxy says on stderr that it
  has no session credentials, so any local process may use it and taint does not apply.
  Nothing changes for existing users of the Standard tier.

### Rotation and expiry

A credential lives exactly as long as its `moat run`. It is not rotated within a run,
and the next run gets a new one. No credential is written to disk.

### Session id and taint

The hooks record under the agent's own session id (Claude Code's, Codex's), which
`moat run` cannot know when it starts. So:

1. `moat run` gives the agent `MOAT_RUN_SESSION=<session>`.
2. `moat guard`, started by the agent with its environment, records once per agent
   session a link row in the run's audit session. The row has host `moat-run`, the
   agent's host id as the tool, the agent's session id as the call id, and rule
   `run-session` (`crates/openmoat-cli/src/taint/run.rs`).
   - Link rows are ordinary events in the hash chain.
   - A link that cannot be written fails the guard call, as the event row itself would.
   - A link only adds a session to a run's taint; nothing removes one.
3. The proxy calls a `TaintLookup`, which the CLI implements as `RunTaint`. It folds
   every linked agent session with the guard's own fold, over the project's effective
   policy, and keeps where each fold reached between requests.
4. A history that cannot be read refuses the request (`proxy-session`).

The decision at egress reuses the core (`CompiledPolicy::with_taint`), so it cannot
drift from the hook's. `decide::tainted` asks it about `net` to the request's host:

- **After a secret read:** a CONNECT or plain-HTTP request to any host but that secret's
  own would ask. The proxy cannot ask, so it refuses (`session-taint`). The reason says
  why, that `moat allow` does not answer a secret's taint (POLICY.md §4.1), and to start
  a new session.
- **Registries:** these hosts are refused too. They are the relays the taint exists
  for (`npm publish`, a gist), and the hook asks for them as well.
- **After untrusted content alone:** nothing changes at egress; that taint protects
  writes.

With the default policy `secrets-paths` denies, so no secret read runs and no session is
tainted. Only a policy that moves those reads to `ask` sees a change.

### Connection shares (#555)

In session mode, no single holder may keep more than half of `max_connections` (at
least one) open (`openmoat-proxy/src/slots.rs`):

- One holder is each session.
- The connections that have not presented a credential yet share one holder of their
  own, counted from accept until their head is read.
- The next connection over a share gets 503 (`proxy-session`).

So silent clients hold at most half the slots, each for at most the handshake timeout,
and a busy session leaves half to everyone else.

## Consequences

- Proxy rows in `moat run` carry the run's session. With a policy that lets secret
  reads run, a script the hook never sees can no longer send them through the proxy to
  another host, once a hook-visible call of the session has read them.
- **A run has only half the connections.** `moat run` serves one session, so it may
  hold 128 of the default 256 at once.
- **The token is shared within the sandbox.** Every process in the run's sandbox can
  read it from its environment; they all are the session. A process of the same user
  outside the sandbox that can read the agent's environment can use the session too
  (THREAT_MODEL.md).
- **Clients that ignore userinfo lose network.** A client that drops userinfo from its
  proxy URL gets 407 under `moat run`. There is no opt-out (an open proxy for `moat
  run`) for now.
- **Taint is only as complete as the hook's history.** A secret read by a command the
  hook never sees taints nothing (THREAT_MODEL.md "Session taint is minimal").
- **Limit: hooks inside `moat run` may not be able to write the links.** As the code
  stands, the run's sandbox gives the agent's processes, hooks included, neither read
  nor write access to the OpenMoat state directory:
  - macOS: the Seatbelt profile starts from `(deny default)`
    (`crates/openmoat-cli/src/sandbox/seatbelt.rs:100`) and allows reads only of the
    platform paths, the program, the project, the agent temp dirs and the read roots
    (`tests/fixtures/sandbox/seatbelt-default.sb:17-50`). It denies writes to
    `~/.moat` last (`seatbelt.rs:171`; golden lines 161 and 172).
  - Linux: Landlock grants only the platform paths, the program, the IR's allow trees,
    the read roots, the temp directory and `--write` paths
    (`crates/openmoat-cli/src/sandbox/landlock.rs:55-102`), and refuses a grant inside
    a denied path, `--write ~/.moat` included (`landlock.rs:157-166`).
  - `moat guard` reads the lock first (`crates/openmoat-cli/src/commands/guard.rs:168`)
    and must write the audit log (`guard.rs:239`). Either failure is a fail-closed deny.

  So a hook started inside `moat run` would deny every governed call and record
  nothing, link rows included, and egress taint then has no history to apply. This ADR
  does not widen any sandbox rule to change that. Whether hooks should run inside `moat
  run`, or be answered by a decider outside the sandbox, is a separate decision. Until
  then egress taint takes effect only where hook events reach the audit log for the
  run's linked sessions.
- The proxy crate stays free of storage. Taint comes in through a trait the CLI
  implements, as audit rows go out through `Recorder`.
