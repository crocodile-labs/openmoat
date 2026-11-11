# ADR-020: One egress proxy, and secrets the agent never holds

Status: accepted · Date: 2026-10-06 · Decided by the maintainer

## Context

- Seatbelt and Landlock cannot filter by host, so every enforcement tier (ADR-018) needs a proxy
  for the `net` allowlist.
- An allowlisted host is still a relay. `api.github.com` accepts gists and pushes, and a
  registry accepts uploads. Read-then-exfiltrate through an allowed host is the most realistic
  attack that a host allowlist leaves open.
- Today a token in the agent's environment, or in a dotfile it can read, is one prompt
  injection away from leaving the machine.
- Claude Code (credential masking) and Docker Sandboxes (a credential-hiding proxy) have started
  to keep secrets out of the agent's reach. Most products still hand the agent its tokens.

## Decision

- **`moat proxy` is the only network exit in every tier.** Claude Code gets it through
  `httpProxyPort`, Codex through its own proxy, configured as an upstream. Isolated and
  Lightweight guests get no other route.
- **Default deny.** Hosts come from the policy's `net`/`fetch` allow lists. `cloud-metadata`
  and link-local addresses are denied by name.
- **What the proxy checks:**
  - It checks the TLS SNI against the CONNECT host.
  - It resolves DNS itself, so the guest needs no resolver.
  - It can restrict HTTP methods and paths per host, for example GET-only to a docs site.
- **It logs every connection to the audit log.**
- **Secrets broker.**
  - A secret the policy names (`secrets:` with host, header and source) is kept by moat. The
    source is a file moat reads, an OS keychain item, or an environment variable on the host.
  - The proxy injects the secret into requests to that host only.
  - The agent and its scripts see a placeholder, never the value.
  - A request to any other host that carries the placeholder or the value is blocked and
    recorded.
- **Session taint**, the minimal form for the beta:
  - Once a session has read secret material (a `secrets-paths` read the user approved, or a
    brokered secret used), later network to hosts outside that secret's own host needs review.
  - Once it has fetched untrusted content (`fetch`, an MCP result), later writes to protected
    paths need review.
- **Reuse before writing:**
  - Evaluate the Apache-2.0 `codex-network-proxy` (Rust) and Anthropic's `sandbox-runtime`
    proxy as the base, with a license and maintenance review.
  - TLS termination for method and path rules is opt-in per host. It needs a local CA that only
    the guest trusts.

## Consequences

- Stealing a brokered token through the agent needs a proxy bug, not a prompt.
- Exfiltration through an allowed host is limited by method and path rules and by taint, not
  closed. Covert channels (timing, data hidden in allowed requests) stay out of scope and are
  listed in THREAT_MODEL.
- Tools that ignore proxy settings lose network in Isolated and Lightweight. This is intended,
  and `moat doctor` and the audit log make it visible.
- The broker and proxy are security-critical services on the host. They get fuzzing (request
  parsing), the "never widens" property tests from ADR-019, and their own threat-model section.

## Note (2026-10-11): the placeholder in a body sent to its own host

This note explains the accepted decision above; it does not change it.

A plain-HTTP request to a secret's own host may carry the placeholder in its body.
`moat proxy` neither replaces it with the value there nor refuses the request, and both
are deliberate:

- **Not substituted.** Writing the value into a body would let the server send it back:
  an API that echoes the request, an error page that quotes it, or a search index that
  stores it. The agent would then read the real secret in the response, which is what
  the broker exists to prevent. The value goes into the secret's header only.
- **Not refused.** The agent already holds the placeholder, so the request tells the
  owner nothing the agent could not send anyway, and the placeholder alone does not
  authenticate anywhere. Refusing it would break ordinary requests that mention it, for
  example a script that posts its own configuration, without protecting the value.

A placeholder or value in a request to any other host is still refused and recorded.

## Note (2026-11-08): which allow patterns name a private address

This note explains the accepted decision above; it does not change it.

A private or unique local address is reached only when an allow rule names the
address. A pattern names one when it starts with a digit (`10.0.0.*`) or is IPv6 text
(`fd12::*`, `fe80:*`). A `host:port` pattern is judged by its host part: `fac*:5432` is
a name on port 5432, even though the text of the unique local address `fd00::1:5432`
matches it as a glob. The policy engine already never matched a pattern with a port
against IPv6 text; the proxy's address policy now drops such a pattern too, so neither
layer depends on the other for this.

## Note (2026-11-08): reserved and site-local space, and ECH drafts

This note explains the accepted decision above; it does not change it.

- `240.0.0.0/4` (reserved) and `fec0::/10` (site-local, deprecated by RFC 3879) are
  refused like private space: no public server has such an address, but some networks
  still route them inside (a cloud may use `240.0.0.0/4` for pod ranges). They are
  `Private` rather than never reachable, so an allow rule naming the address opens it,
  as for `10.0.0.0/8`. Before, `fec0::/10` was allowed on purpose as possibly public
  space; refusing fails closed, and an allow naming the address is the way to reach it.
- A `ClientHello` carrying an `encrypted_client_hello` extension under the codepoints
  of ECH drafts 08 to 12 (`0xfe08` to `0xfe0c`) is refused like one with `0xfe0d`: a
  server speaking a draft acts on the encrypted inner name all the same.

## Note (2026-11-10): the session cache and the working directory

This note explains how session taint is computed in long sessions; the decision above
does not change.

Session taint is the fold of a session's earlier calls. Since #570 the guard keeps that
fold in the audit database (`session_folds`, see ARCHITECTURE.md, "Session cache"), so a
late call folds only the calls recorded since. No ADR introduced that cache; this note
records the rule it follows now.

- **What a row is keyed by.** The digest covers this build's version, the host, the
  effective policy and its context. The context's working directory is left out: the
  fold classifies each call in the directory it was recorded with, never in the
  context's. Before, the digest held the directory of the call being decided, so the
  first call after the agent moved to another folder found no row, folded the session
  from its first call, and in a long session ran out of time on every call (each one
  denied with `kernel-error`).
- **Calls recorded without a directory.** Such a call is taken to have run in the
  directory of the call being decided, so a fold that holds one belongs to that
  directory. The fold records whether it took one in. A fold that took in none is the
  same in every directory and is kept in the shared row; one that did is kept in a row
  of its directory's own, which only that directory reads. A call reads the further on
  of the two rows it may use.
- **Why the answer is the same as a full fold.** A fold is a left fold over the
  session's calls in order, so reading on from a fold of the first `k` calls gives the
  fold of them all. The directory of the call being decided enters it only through the
  calls without a directory; a fold that holds none of those is the fold every directory
  would compute. A test compares the cached answer with a fold from the first call, at
  every call, over sessions that mix directories, calls without one, a relative read that
  is a secret from one directory only, stopped calls and catch-ups.
- **Unchanged.** A fold that runs out of time still saves what it reached and denies the
  call: part of a session is never an answer. An upgrade, a policy edit or a move to
  another project still changes the digest, and the session is folded again from its
  first call; that is what the classifier of the new build or policy would answer. Each
  fold now classifies a call once for its taint and its collection (ADR-061) instead of
  twice, and `openmoat doctor` lists the calls the guard could not decide in the last day,
  so a guard that denies every call is never shown as all good.
- **Measured** (release build, default policy, one macOS 12 laptop): classifying is
  what a fold spends its time on. 2,000 distinct calls took 2.27 s classified twice and
  1.41 s once; reading 50,000 events took 0.69 s; a fold of 50,000 calls with 2,000
  distinct, from the first, 2.2 s. The first call after a move to another folder of the
  project, 50,000 calls in, folded one event and took 0.14 s, policy compile included.
  Real agents' commands are longer than these (heredocs, long pipelines), so a refold
  after an upgrade or a policy edit can still take more than one call's 20 s; each call
  then reads on from where the last one stopped.
