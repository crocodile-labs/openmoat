# ADR-043: TLS termination for brokered secrets, with method and path rules

Status: accepted · Date: 2026-10-28 · Refines ADR-020 (egress proxy and secrets broker),
ADR-027 (per-session proxy credentials) and ADR-028 (hook decisions inside `moat run`) ·
Builds on ADR-044 (the standalone proxy serves agent sessions only)

## Context

ADR-020 keeps a brokered secret's value from the agent: the agent holds a placeholder,
and the proxy puts the value into requests to the secret's one host. Until now the proxy
could do that only in plain HTTP (`plain_http: true`, #172), because it never decrypted
a CONNECT tunnel. Almost every API worth brokering is HTTPS, so an HTTPS request kept
the placeholder and failed upstream.

ADR-020 also names the second half of the design: rules for which methods and paths a
host may receive. A token for `api.github.com` opens much more than the agent needs
(gists, keys, pushes), and every one of those is a relay for exfiltration.

Both need the proxy to read the request, which inside TLS means terminating it with a
certificate the agent's clients accept. The design in #172 set the conditions: opt-in per
secret, a CA a person makes, limited by name constraints, pinned in the lock, trusted
only where OpenMoat confines the agent, and a request loop that reuses the proxy's
parser and its leak check.

## Decision

### Opt-in per secret: `tls: terminate` and `allow`

```yaml
secrets:
  - id: gh
    host: api.github.com
    header: Authorization
    source: { env: GITHUB_TOKEN }
    tls: terminate
    allow:
      - GET /repos/**
      - POST /repos/*/*/issues
```

- `tls: terminate` makes `openmoat run`'s proxy decrypt every CONNECT to `host` (any
  port the policy allows). Off unless set. The host must be a DNS name: the CA signs no
  address.
- `allow` lists the only requests that may receive the value, `METHOD /path` each: the
  method in capitals, compared exactly; path segments that are literals, `*` (exactly
  one non-empty segment) or `**` (any number). The query is not matched. `TRACE`,
  `TRACK` and `CONNECT` cannot be named. At most 64 rules.
- `allow` needs `tls: terminate` or `plain_http: true`, where the proxy reads requests;
  a policy that sets it without either does not load. Rules apply in plain HTTP too.
- **Every request that would get the value is checked**, with or without the
  placeholder in it (the proxy adds the header when it is absent, ADR-020). A request
  the rules do not name is refused with 403 and recorded (`proxy-secret-route`) before
  anything is sent upstream: no connection to the host is even opened. The row names the
  method and why, never the path, which can hold what the request is about.
- **A path the server could read as another is refused, not matched.** Each segment is
  percent-decoded once, as the server reads it. Refused: a `.` or `..` segment in any
  spelling (`%2e%2e`, `.%2E`), a segment that decodes to `/`, `\`, `%` (a second layer of
  encoding), `;` or a control byte, a raw `;` (matrix parameters, Tomcat's `..;`), an
  empty segment (`//`), invalid UTF-8, a byte outside visible ASCII, `\` and `#`.
- **A method override is refused**: the `X-HTTP-Method-Override`, `X-HTTP-Method` and
  `X-Method-Override` headers and a `_method` query parameter, which frameworks read
  as the real method.
- Matching is pure and lives in `openmoat-core` (`secret/route.rs`), with the schema.

### The request loop inside a terminated tunnel

`openmoat-proxy/src/exchange.rs`, after the CONNECT is decided as any tunnel is (host
allow, session taint, ports) and its `ClientHello` names the CONNECT host (SNI, ECH
refused as before):

1. The proxy finishes the TLS handshake with a leaf for the host. It offers ALPN
   `http/1.1` only, so an HTTP/2-only client fails the handshake
   (`no_application_protocol`) instead of sending frames the proxy does not parse.
2. It reads **one** request head, in origin form, with the same parser rules as plain
   HTTP (`request/origin.rs`): unambiguous framing (`check_framing`), hop-by-hop headers
   removed, `Connection: close` added. On top: the target must be a path (the absolute
   form could name another host), `Host` must name the tunnel's host and port exactly
   once, `Accept-Encoding` becomes `identity`, and `Expect: 100-continue` is answered by
   the proxy and not forwarded.
3. The leak check of ADR-020 runs on the head and on every body byte, raw and without
   its chunked framing: a placeholder or value of a secret bound elsewhere is refused.
4. The `allow` rules (above), then session taint (ADR-027): the taint of the session
   whose credential the CONNECT carried, read again during the exchange.
5. Only then the proxy resolves and connects to the host, with the usual address
   checks, and verifies its certificate against the system's roots
   (`rustls-native-certs`, then `webpki`) **with the CONNECT host as the server name**.
   A certificate that does not verify ends the request with 502 (`proxy-tls`) before
   any byte of it is sent.
6. It records the request (method, host, port, the rule matched; marked `terminated`,
   shown as `https://host:port`), puts the value in, and forwards the head and body.
7. It relays the answer: head checked (no `101`, no content or transfer coding but
   `chunked`, no conflicting lengths; `Connection` becomes `close`), head and body
   searched for **every** brokered value. The body is released as it arrives, less as
   many bytes as the longest value has minus one, so no released byte starts a whole
   value; a chunked body is searched without its framing and sent in the proxy's own
   chunks. A value stops the answer before it (`proxy-secret`): the agent gets a 502
   when nothing was sent yet, otherwise a cut connection, never a shorter whole answer.
8. Then the tunnel closes. **One request per tunnel**: whatever the agent sends after
   the first request's body is never read, so it cannot switch host or follow a checked
   request with an unchecked one. Clients open a new tunnel for the next request, as
   after any `Connection: close`.

### The certificate authority

- **Made by a person only:** `openmoat proxy ca init` refuses without a terminal, with
  an agent among its parents, and over a lock that shows drift, like the other
  commands that change what OpenMoat trusts (AGENTS §7). It shows the hosts and asks
  first. `openmoat secret add --tls-terminate` offers to run it when no CA covers the
  new host.
- **Key:** ECDSA P-256 (rcgen with `ring`), basic constraints CA with path length 0,
  key usage `keyCertSign` and `cRLSign`, subject `CN=OpenMoat proxy CA, O=OpenMoat`,
  valid from yesterday for 365 days.
- **Name constraints:** permitted DNS subtrees are exactly the hosts of the secrets
  that say `tls: terminate` (and, as RFC 5280 defines a DNS subtree, names under them);
  excluded are all IPv4 and IPv6 addresses. A client checking name constraints, which
  rustls, Go, OpenSSL 1.1+, BoringSSL, NSS and Apple's Security framework all do,
  accepts nothing else the key signs, even if the certificate leaked into a wider
  trust store.
- **Leaves** are made in memory per host, valid from yesterday to the day after
  tomorrow, cached per day, with a fresh key each, never written to disk.
- **Storage:** `~/.moat/proxy-ca/key.pem` (PKCS #8 PEM, mode 0600 in a 0700 directory,
  written atomically through `write_private`) and `~/.moat/proxy-ca/ca.pem`. A file, not
  an OS keychain item: the proxy runs inside `openmoat run`'s own process, the files sit
  with the other state the sandboxes already keep from the agent, and a keychain item
  would be readable by any process of the user that can run `security`. Windows has no
  `openmoat run`, so the key is never used there.
- **Kept from the agent:**
  - `openmoat run` on macOS: the Seatbelt profile starts from `(deny default)` and never
    grants `~/.moat`;
  - `openmoat run` on Linux: Landlock grants no path in `~/.moat` and refuses a grant
    inside a denied path; under `--isolate`, bubblewrap does not mount it;
  - the hook: `kernel-self` now denies `fs.read` of `~/.moat/proxy-ca/**` (and
    `**/.moat/proxy-ca/**` for a state directory elsewhere);
  - Claude Code's sandbox: that rule becomes a `denyRead` entry; Codex's and Cursor's
    sandboxes grant reads of named paths only, and `~/.moat` is not one.
- **The lock pin:** `openmoat proxy ca init` pins both files, as `openmoat policy
  trust-key` pins the signing files (ADR-031): other re-pins keep the pins and never
  add them. `openmoat run` uses the CA only while both files are pinned and intact (the
  lock is verified before the run starts), and only when a leaf it signs verifies today
  for every terminated host, checked with `webpki` against the CA alone, as a client
  will check it. Otherwise the run does not start and says to run `openmoat proxy ca
  init`.
- **Rotation:** `openmoat proxy ca init` again makes a new key and certificate and pins
  them; a run already going keeps the CA it loaded until it ends. It is also how the CA
  comes to cover a host added later. `openmoat run` warns from 30 days before the CA
  expires. Nothing needs revoking: no trust store outside a run ever held the old CA.

### Which clients trust the CA, and where

Only the commands `openmoat run` starts. Before the agent starts, the run writes the CA
certificate, and a bundle of the system's roots plus the CA, to
`$TMPDIR/moat-run-<pid>-ca/` (owner-only; bound in read-only under `--isolate`, whose
temp directory starts empty), and sets in the agent's environment only:

- the CA alone: `NODE_EXTRA_CA_CERTS` (Node.js adds it to its roots);
- the bundle: `SSL_CERT_FILE` (OpenSSL and what is built on it, Go on Linux),
  `REQUESTS_CA_BUNDLE` and `PIP_CERT` (Python), `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
  `CARGO_HTTP_CAINFO`. The bundle starts from the person's own `SSL_CERT_FILE`, or the
  first system bundle found; without one, only the adding variable is set and the run
  says so.

No system or user trust store changes, and the files go when the run ends. These files
are not a boundary: a command in the run can change them or the variables, which only
changes what it itself trusts. The proxy verifies every upstream on its own, outside the
sandbox, and the value is added there.

### Sessions (ADR-044)

A tunnel is terminated only for a request of an authenticated session. The session
credential is checked first, before the host is decided, as for every request (ADR-027
in `openmoat run`, ADR-044 in the standalone proxy). The terminated requests are
recorded under that session, decided with its taint, and count against its share of the
connections. A request the proxy serves without a credential
(`sandbox.proxy_serve_without_credential`, ADR-044) belongs to no session, so its tunnel
is never terminated: it is relayed as any tunnel and keeps the placeholder.

The standalone `openmoat proxy` never terminates, even for an authenticated session: the
credentials of ADR-044 reach Claude Code's commands through `CLAUDE_ENV_FILE`, but the CA
would have to reach them too, and the host sandboxes read their trust from settings
written once for every session, not from the run's own files. It says so at start-up for
each terminated host; HTTPS there keeps the placeholder. Doing it there would need the
trust files to reach the session the same way, a later decision.
Claude Code's own broker (`sandbox.credentials`) keeps masking secrets without rules,
and is not given a secret with `allow` rules, which it could not hold to them.

### What happens on a pinning client

A client that pins the host's own certificate or key, or ships its own roots and ignores
the variables (Go programs on macOS use the system verifier; some SDKs bundle roots),
refuses the leaf. The handshake fails, the row says why (`proxy-tls`, with what to do),
no request is read and nothing reaches the host. The secret stays unused, which is the
safe failure. `tls: terminate` is for hosts the agent's tools reach with ordinary
clients.

### Dependencies

`rustls` 0.23 (`ring` provider, `std`, `tls12`; no `aws-lc-rs`, which needs a C and
cmake build), `rcgen` 0.14 (`ring`, `pem`, `zeroize`) and `rustls-native-certs` 0.8.
Their trees are MIT, Apache-2.0, ISC and BSD-3-Clause (`ring`: Apache-2.0 AND ISC),
inside `deny.toml`. Not `webpki-roots` (CDLA-Permissive-2.0, outside the allow list):
upstreams are verified against the system's store, as the agent's own clients would.
Not `rustls-platform-verifier`: it pulls Android and wasm-only crates and verifies
differently on each platform. The proxy stays on `std::net` and one thread per
connection; the TLS state machines are driven synchronously.

## Consequences

- A token for an HTTPS API can be brokered end to end: the agent holds the placeholder,
  the host gets the value, and the agent cannot read it back from the host's answer
  unless the host sends it encoded.
- A brokered token opens only what its rules name. Exfiltration through the token's own
  host is limited to those requests, not closed: an allowed `POST` can still carry data
  (THREAT_MODEL.md).
- **The proxy now decrypts.** Inside `openmoat run` it holds the plaintext of terminated
  requests and answers, in memory, and is security-critical in a new way: a bug in the
  loop is a bug in what reaches the host. The loop reuses the request parser, the
  framing checks and the leak check, and refuses anything ambiguous.
- **One request per tunnel** costs a TLS handshake per request to a terminated host.
  Leaves are cached, so it is one ECDSA signature on each side.
- Clients that do not read the variables, pin, or speak HTTP/2 only cannot use a
  terminated host; their requests fail closed and are recorded.
- The crate rule "nothing is decrypted" (`crates/openmoat-proxy/AGENTS.md`) now reads
  "nothing is decrypted except for a secret that says `tls: terminate`, inside
  `openmoat run`".
