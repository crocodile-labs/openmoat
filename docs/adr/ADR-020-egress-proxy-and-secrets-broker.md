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
    brokered secret used), later network to hosts outside that secret's own host asks.
  - Once it has fetched untrusted content (`fetch`, an MCP result), later writes to protected
    paths ask.
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
