# ADR-044: Every request through the standalone proxy belongs to an agent session

Status: accepted · Date: 2026-10-28 · Refines ADR-020 (egress proxy) and ADR-027
(per-session proxy credentials) · Closes the design of #558

## Context

ADR-027 gave `openmoat run`'s private proxy per-session credentials: its requests are
recorded under the run, decided with the run's taint, and no session holds more than
half the connections. The standalone `openmoat proxy`, which the host sandboxes use when
the policy sets `sandbox.proxy_port`, was left without sessions, because "the host
sandboxes cannot send a credential". Two limits followed (THREAT_MODEL.md):

- **Session taint is minimal.** A Claude Code session that read secret material could
  still send it through the proxy, from a script the hook never sees, to any allowed
  host.
- **Any local process may use the proxy.** It listens on loopback and asked for
  nothing.

#558 asks how each host sandbox can carry a per-session credential, how the token
reaches only that session's processes, how it rotates and expires, what a request
without one gets, and how limits become per session.

### What each host sandbox can carry

**Claude Code.** `sandbox.network.httpProxyPort` and `socksProxyPort` take a port, not a
URL (sandboxing docs, "Custom proxy configuration"): Claude Code points its sandboxed
commands at `localhost:<port>` with `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their
lower-case forms, with no userinfo, and settings are written once for every session.
But Claude Code also has a per-session channel: a `SessionStart` hook gets
`CLAUDE_ENV_FILE`, "a file path where you can persist environment variables for the
shell commands Claude runs later in the session", and "each Bash command runs the
file's contents as shell code before the command itself" (hooks reference, "Persist
environment variables"; the input carries `session_id`). An `export HTTP_PROXY=…` there
runs inside the command's shell, after the sandbox set its own value, so it replaces
it at the same port. `SessionStart` fires on `startup`, `resume`, `clear` and
`compact`. A reported issue (anthropics/claude-code#43236, closed as not planned) says
Claude Code inlines the file's contents into the `bash -c` command line rather than
sourcing it by path, and creates the file world-readable.

**Codex.** Its network proxy sends what it allows on to an upstream proxy read from the
Codex process's own `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, when
`allow_upstream_proxy` is on (`codex-rs/network-proxy`, `README.md` and
`src/upstream.rs`, `ProxyConfig::from_env`). `config.toml` cannot set those variables;
whoever starts Codex does. Codex's hooks cannot set environment variables for later
commands: `SessionStart` only adds model context (Codex hooks documentation), and
rewriting each command with `updatedInput` would put the secret in the model's history.
So no per-session credential can reach Codex's upstream from OpenMoat unless OpenMoat
starts Codex, which `openmoat run -- codex` already does (ADR-027).

**Cursor.** `sandbox.json` has no proxy setting; its sandboxed commands never reach
`openmoat proxy` (`sandbox/cursor.rs`, `cursor.proxy`). Nothing to carry.

### Why the credentials must be signed

`openmoat run`'s proxy holds its one credential. The standalone proxy runs for days as a
user service and serves sessions that start after it, from hooks in other processes.
It could read a registry of tokens the hooks write, but that is shared mutable state on
every request, with races and growth to manage. A signed credential needs none: the
hook and the proxy share one key, and the proxy recomputes each signature.

## Decision

### The credential

`user:password` of a `Basic` proxy credential, as in ADR-027:

- `user` is `v1.<host>.<expires>.<session>`: the agent host's id, the Unix time in
  seconds from which it is refused, and the host's own session id, which every proxy row
  is recorded under. A session id that would need escaping in a URL, a `Basic`
  credential or a shell word (anything but ASCII letters, digits, `.`, `_`, `-`, at most
  128) gets no credential, nor does a session the host did not name.
- `password` is the lowercase hex HMAC-SHA-256 of `user`, with the domain string
  `openmoat-proxy-session-v1\n` in front, under a 256-bit key.

HMAC is built on the `sha2` crate the CLI already uses (RFC 2104), checked against the
RFC 4231 test vectors. The key comes from the OS random source (`getrandom`, which is
already in the lock through `tempfile`, and which works on Windows, where
`/dev/urandom` does not exist).

### The key

`~/.moat/proxy.key`: 64 hex characters, owner-only, made by `openmoat proxy` at start-up
or by the first hook that needs it. It is created with a hard link from a complete
temporary file, so two processes making it at once keep the first one's and never see
a half-written file.

The default policy's `kernel-self` denies reading it (`~/.moat/proxy.key`,
`**/.moat/proxy.key`), with conformance attacks for the path, `cat` and a moved
`MOAT_HOME`. That deny is compiled into every host sandbox as well (Claude Code's
`denyRead`, Codex's profile, the Seatbelt profile of `openmoat run`). Whoever reads the
key can make a credential for any session, a clean one included.

### Issue: Claude Code's `SessionStart` hook

`openmoat init` installs a `SessionStart` entry (matcher
`startup|resume|clear|compact`, 60 s) that runs `openmoat guard --host claude-code`. For
that event the guard (`commands/guard/session_start.rs`):

1. checks the policy lock first, as for every call; drift denies, and nothing is issued;
2. issues nothing, and says why on the row (rule `session-start`), when the policy sets
   no `sandbox.proxy_port`, when `openmoat run` relayed the hook (the run's own credential
   applies), or for a host other than Claude Code;
3. otherwise issues the credential, records an allow row with rule `proxy-credential`
   and the session's working directory, and only after that row is written appends to
   `CLAUDE_ENV_FILE`:
   `export HTTP_PROXY=http://<user>:<password>@127.0.0.1:<port>`, the same for
   `HTTPS_PROXY` and `ALL_PROXY`, and the lower-case forms;
4. makes that file owner-only, refusing it when it is a symbolic link or not a regular
   file.

The response is always empty: Claude Code adds a `SessionStart` hook's stdout to the
model's context. A failure (no absolute `CLAUDE_ENV_FILE`, no working directory, an id
that cannot carry a credential, a file that cannot be written) exits 2, whose stderr
Claude Code shows the person. Claude Code cannot block a session from starting, so the
session then runs with commands the proxy refuses, which fails closed.

The lines are plain `export NAME=value` assignments, which Claude Code also copies into
the environment of PowerShell commands (hooks reference).

### Verify: the standalone proxy

`openmoat proxy` serves sessions only. `openmoat-proxy` gains a `Verify` trait, which
the CLI implements (`proxy_session::Verifier`), beside the credentials it holds
(`Sessions::issued`). The proxy crate stays free of storage and of the key.

For each request the verifier recomputes the signature, compares it in constant time,
and accepts it while `now < expires ≤ now + 24 h + 60 s`. At most once a second it
looks at the key file (its length and modification time) and reads it again when it
changed. The signature
is computed whatever the expiry says, so the time taken does not tell an expired
credential from a forged one.

### Rotation and expiry

- A credential is accepted for 24 hours from issue. Claude Code issues a new one at
  every start, resume, `/clear` and compaction, appended after the old lines, so the
  newest wins.
- A session open for longer without any of those gets 407 once its credential expires;
  `/clear` or a new session gets a new one. A connection opened before the expiry runs
  on until it ends (the idle timeout closes an idle one after 2 minutes).
- Replacing (or deleting) `~/.moat/proxy.key` revokes every credential within a second,
  without restarting the proxy; while the file is missing or unreadable no credential is
  accepted. No credential is ever stored.

### A request without a credential

Refused with `407` and `proxy-session`, recorded with no session, before its host is
decided, as under `openmoat run`: a missing, malformed, wrong, edited or expired
credential alike. The reply does not say which.

`sandbox.proxy_serve_without_credential: true` is the named fallback for clients that
cannot send one (Codex's upstream): a request with **no** `Proxy-Authorization` at all is
served with no session and no taint, as before this ADR, in a share of its own. A
request with a wrong credential is still refused, so a session cannot fall back by
sending a bad one. `openmoat policy lint`, `doctor` and `status` warn about the key: with
it, any local process may use the proxy, and a session escapes its taint by sending no
credential.

### Taint

The proxy records under the host's own session id, the one the hook calls of that
session are recorded under, so no link rows are needed (contrast ADR-027).
`taint::issued::IssuedTaint` folds a session's events with the guard's own fold, over
the effective policy of the directory on its `proxy-credential` row (the user policy
with the project's repository policy, as the guard decides), keeps each fold between
requests, and keeps at most 1024 sessions (least recently used first). A session with
no `proxy-credential` row, or whose history cannot be read, is refused (fail closed).
The decision at egress is ADR-027's `decide::tainted`: after a secret read, a request to
any host but that secret's own is refused (`session-taint`), and open connections are
checked again every second.

### Per-session limits

ADR-027's shares apply: no session holds more than half of `max_connections`; the
connections that have not authenticated share one holder, and with the fallback the
requests served without a credential share another. The proxy forgets the recent taint
of sessions idle for ten minutes once it follows 1024.

### `status` and `doctor`

With `sandbox.proxy_port`, each host sandbox present gets a line:

- Claude Code: each session's sandboxed commands send their own credential;
- Codex (a warning): its proxy sends none, so `openmoat proxy` refuses what it hands on,
  or with the fallback serves it without a session; `openmoat run -- codex` gives each
  run its own;
- Cursor: its sandboxed commands do not reach `openmoat proxy`;
- with the fallback, a warning that any local process may use the proxy.

### Migration

- After upgrading, `openmoat doctor` and `openmoat status` report Claude Code's hook
  entries as out of date until `openmoat init` adds `SessionStart`; until then, and in
  sessions started before it, Claude Code's sandboxed commands get 407 from `openmoat
  proxy`. Run `openmoat init`, then start a new session.
- A Codex started with `HTTP_PROXY` naming `openmoat proxy` gets 407 for what its proxy
  hands on. Set `sandbox.proxy_serve_without_credential: true` to keep the old behaviour
  (and lose taint and the local-process check for that traffic), or run
  `openmoat run -- codex`.
- `openmoat run` is unchanged.

## Consequences

- Claude Code sessions through `openmoat proxy` get what `openmoat run` sessions got:
  rows under their session, egress taint after a secret read, and their own share.
  Other local programs are refused.
- **The credential is as private as Claude Code keeps the environment file.** By the
  reported behaviour Claude Code inlines the file into the command line of each Bash
  command, and the files of all sessions sit side by side under
  `~/.claude/session-env/`. OpenMoat makes the file owner-only, which keeps other users
  out, but a process of the same user that can read another session's file or command
  lines can send as that session; a tainted session doing so sends under a clean
  session's taint. The default policy does not deny `~/.claude/session-env/` to
  sandboxed commands: whether Claude Code reads the file inside its sandbox is not
  documented, and a deny there would then cut every session's commands off. This is in
  THREAT_MODEL.md.
- **Codex is not covered** by the standalone proxy: no credential can reach its
  upstream from OpenMoat. `status` and `doctor` say so, and `openmoat run -- codex` is
  the per-session path.
- **One more process per session start.** Checking a credential costs about 22 µs
  in-process (an HMAC-SHA-256 and the `Basic` decoding), against about 3 µs for
  `openmoat run`'s held credential, measured in an optimised test build on an
  Intel Mac (macOS 12); a connection's own setup (TCP, DNS, TLS) takes milliseconds. The key
  file is looked at at most once a second.
- The SessionStart hook's effect on the real Claude Code (that the exported variables
  replace the sandbox's at the same port inside sandboxed Bash) is documented behaviour
  but not exercised by the test suite, which runs Claude Code with `--bare`; the smoke
  test with the real agent is where it is seen.
