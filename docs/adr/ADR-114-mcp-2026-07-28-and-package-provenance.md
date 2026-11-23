# ADR-114: The MCP gateway speaks MCP 2026-07-28, and a server's package release is pinned

Status: accepted · Date: 2026-11-23 · Builds on ADR-026, ADR-032, ADR-045, ADR-049,
ADR-058 and ADR-069

## Context

The MCP gateway (`openmoat mcp proxy`, ADR-045) pins what a stdio server says to the
model. ADR-069 built the pins of a server's own text on the `initialize` handshake: its
`instructions` and `serverInfo`. The MCP revision of 2026-07-28 changed the protocol
under that design
([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)):

1. **No handshake.** `initialize` and `notifications/initialized` are gone (SEP-2575).
   Every request carries its protocol version and client capabilities in `_meta`
   (`io.modelcontextprotocol/protocolVersion`, `…/clientCapabilities`), and a server
   SHOULD name itself in every result's `_meta` (`io.modelcontextprotocol/serverInfo`)
   ([base protocol, `_meta`](https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta)).
   Its instructions, capabilities and supported versions come from `server/discover`,
   which every server MUST implement
   ([discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)).
   A server may serve both revisions at once, picking per request by how the client
   opens ([versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)).
2. **Multi Round-Trip Requests.** A server no longer sends `sampling/createMessage`,
   `elicitation/create` or `roots/list` as requests; it answers `tools/call`,
   `resources/read` or `prompts/get` with `resultType: "input_required"` and an
   `inputRequests` map, and the client retries with `inputResponses` (SEP-2322,
   [MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)).
   The gateway checked server requests (ADR-069 §8); an `inputRequests` map inside a
   result passed unchecked.
3. **Arguments that become headers.** A tool may mark a parameter with `x-mcp-header`,
   and a client on Streamable HTTP copies its value into `Mcp-Param-<name>` (SEP-2243,
   [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#x-mcp-header),
   [transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#custom-headers-from-tool-parameters)):
   where an argument goes is part of the definition. Schemas may be any JSON Schema
   2020-12, and implementations MUST NOT fetch a network `$ref` and SHOULD bound the
   work a schema causes (SEP-2106,
   [`$ref` resolution](https://modelcontextprotocol.io/specification/2026-07-28/basic/index#%24ref-resolution)).
4. **Cache hints.** Listings and the discovery answer carry `ttlMs` and `cacheScope`
   (SEP-2549), which change between answers of an unchanged server.

Two older gaps sit beside these. URL-mode elicitation (2025-11-25) has the host offer
to open a page the server names; the specification asks the client to show it and ask
([safe URL handling](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#safe-url-handling)),
nothing checked where it points. And a definition such as `npx -y postmark-mcp` stays
the same text when the package changes: `postmark-mcp` 1.0.16 added a hidden BCC to
every mail it sent ([Snyk](https://security.snyk.io/vuln/SNYK-JS-POSTMARKMCP-13052679)),
and a pin of the definition's text accepted it unseen.

Remote (HTTP) MCP servers are still outside the gateway (ADR-045 consequences).

## Decision

1. **Both revisions, read per message.** The relay reads the revision from what the
   host sends: a request whose `_meta` names a protocol version is 2026-07-28,
   `initialize` is earlier, and both may happen in one process. Every answer the host
   gets is checked against the pins of what it is: an `initialize` answer as ADR-069
   says, a `server/discover` answer and every result's `serverInfo` as below. Nothing
   is chosen once for the process, so a server that answers both revisions is checked
   on the answer the host reads, and a switch of revision passes no text unchecked.
   The relay's own `tools/list` (ADR-045 §5) carries the host's protocol version in
   `_meta` when the host speaks 2026-07-28.
2. **The discovery answer is pinned like the `initialize` answer.** The pin is the
   result without `resultType`, `ttlMs`, `cacheScope` and `_meta` (the identity is
   pinned on its own, below). A held answer reaches the host as the accepted one, or
   without `instructions` when none was accepted; accepted instructions are kept as
   untrusted content of each session served (ADR-069 §7). A server a person accepted
   under the older revision is not asked again when its host moves to 2026-07-28 while
   the discovery's instructions are the accepted `initialize` instructions, and the
   other way round.
3. **The identity is pinned, and a change holds the server.** Each result's
   `_meta["io.modelcontextprotocol/serverInfo"]` is compared, its version number pinned
   as any version as `initialize`'s is (ADR-069 §5), with the accepted identity: the
   2026-07-28 one, else the accepted `initialize` answer's `serverInfo`. One that
   differs, or one no person accepted, is held: every `tools/call`, `prompts/get` and
   `resources/read` of the server is refused until `openmoat mcp accept`, and the host
   is given the accepted identity in the result instead. Within one process the server
   must name itself the same way in every result (version included); a server that
   changes its name mid-run has its calls refused until it is started again. The
   specification calls `serverInfo` unverified and for display only; a server that
   names itself differently is still not the program a person accepted, and holding it
   costs one review.
4. **Tool listings are pinned as a set; cache hints are not pinned.** Tool pins were
   already keyed by name, whatever the order (ADR-026, ADR-045); `ttlMs` and
   `cacheScope` are fields of the result, never of an entry, so neither a new order nor
   a new freshness hint asks a person again.
5. **A result's `inputRequests` get the server requests' checks.** One check covers a
   2025 server request and each entry of a 2026-07-28 `inputRequests`:
   - sampling is refused unless the policy sets `mcp: { allow_sampling: true }`
     (honoured only while the lock is intact; `openmoat policy lint` warns, and turning
     it on is a widening for `policy diff`); then a request that asks for the session's
     context is still refused (ADR-069 §8). The 2026-07-28 revision deprecates sampling
     (SEP-2577), and a server that needs a model can call one itself;
   - a URL-mode elicitation is refused unless its URL is `https`, has no user name or
     password, names a host that is not a loopback, private, link-local (169.254.0.0/16,
     `fe80::/10`, the cloud metadata services), shared (100.64.0.0/10) or unspecified
     address, nor `localhost`, nor a number in another notation, and the policy does
     not deny a connection to that host (decided as a `resources/read` of the URL is,
     ADR-045 §6). A `review` passes: the host shows the URL and asks before opening it;
   - an entry that is not one of the three request kinds, or more than 64, refuses the
     result.
   One refused entry refuses the whole result: the host gets error -32001 (with only
   the URL's scheme and host in the message) instead of a partial set of questions,
   and the refusal is recorded (`mcp-server-request`). Each entry that passes is
   recorded and its text kept as untrusted content, as a server request's is (ADR-069
   §8). A host that speaks only 2026-07-28 gets no server request at all: the stdio
   binding forbids them, so one is refused.
6. **Header mappings are pinned with the tool; bad schemas are refused.** A tool's pin
   covers its whole `inputSchema` (ADR-069), so a changed `x-mcp-header` holds the tool;
   `openmoat mcp accept` names each mapping (`argument region is sent as HTTP header
   Mcp-Param-Region`). A tool whose `inputSchema` or `outputSchema` breaks the rules is
   left out of the listing and its calls refused, and it cannot be accepted: an
   `x-mcp-header` that is empty, not an HTTP token, given twice (in any case), on a
   parameter that is not a string, integer or boolean, on one not reached from the root
   through `properties` alone, or in an output schema; a `$ref` that leaves the schema
   (OpenMoat fetches nothing), names an anchor, does not resolve, takes part in a loop,
   or starts a chain deeper than 16; a schema nested deeper than 64 or holding more
   than 4096 schema objects. Refusing loops also refuses a recursive schema (a tree
   type) that a validator could handle; the bound is chosen over the work of proving a
   loop harmless.
7. **A server's package release is pinned with its definition.** When `openmoat mcp
   accept`, `openmoat doctor --accept` or `openmoat init` pins a stdio definition, the
   pin also records the release its command runs (`mcp/provenance.rs`), read offline
   from the command line and the package manager's own files: npm (`npx`, `npm exec`)
   from npx's `package-lock.json` under the npm cache (version and the registry's
   SHA-512 `integrity`), else an exact `pkg@1.2.3`; PyPI (`uvx`, `uv tool run`, `pipx
   run`) from a `uv tool install` (version, SHA-256 of its `RECORD`), else
   `pkg==1.2.3`; images (`docker run`, `podman run`) by the digest the command line
   names, else the tag. No network request is made. A release that differs from the
   recorded one holds the server as a changed definition does: the hook denies its
   tool calls (`mcp-server-changed`) and the proxy does not start it (ADR-049) until a
   person accepts, and the review names both releases. A release that cannot be read
   holds nothing (the package manager may not have installed it yet; the next check
   reads it), and a pin from before this records one without holding when a person
   next accepts.

## Remote MCP: future work, not built

The gateway stays stdio-only. A remote gateway is designed here so the stdio work does
not close it off, and LIMITS.md states the limit. It would:

- **Keep tokens.** The person authorises the remote server to the gateway, which keeps
  the upstream OAuth tokens in OpenMoat's own store and gives the agent a separate,
  local credential bound to that one server (the shape Pomerium documents). The
  agent's token never reaches the server, and the server's never reaches the agent:
  no token passthrough, which the specification forbids
  ([security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)).
  Credentials are keyed by the authorisation server's issuer, re-registered when it
  changes, and an authorisation response's `iss` is checked against it (RFC 9207,
  SEP-2468, SEP-2352).
- **Discover safely.** Protected-resource and authorisation-server metadata are fetched
  only over `https`, from a pinned server URL, with every redirect checked again and
  loopback, private, link-local and metadata addresses refused after resolution; an
  authorisation URL with another scheme (`javascript:`, `data:`, `file:`) is refused.
- **Check the transport's own channels.** `MCP-Protocol-Version`, `Mcp-Method`,
  `Mcp-Name` and each `Mcp-Param-*` header is checked against the body before the call
  is decided, and a tool's header mappings come from its pin, not from the listing of
  the moment.
- **Reuse the pins.** Discovery, identity, listings, `inputRequests` and call tickets
  work as for a stdio server; the server's URL takes the place of its command line in
  the definition pin.

## Consequences

- A server a person accepted under the older revision keeps working when its host moves
  to 2026-07-28 only while what the model reads stays the same; anything else asks once.
- A 2026-07-28 server whose identity nobody accepted has its calls refused from its
  first result: on first sight its tools are held anyway, and one `openmoat mcp accept`
  covers both.
- Sampling through a wrapped server stops by default, for 2025 servers too. A policy
  that needs it says `mcp: { allow_sampling: true }`.
- A URL elicitation to a host the policy denies (the default policy denies unlisted
  hosts for connections) is refused; a server that sends people to its own sign-in page
  needs that host allowed.
- A 2026-07-28 retry that answers an `input_required` result (`inputResponses`) is a
  new `tools/call`: it passes only on a hook decision of its own, as every call does
  (ADR-045 §7). A host that does not run its hook for the retry gets it refused
  (`mcp-unattributed`).
- Recursive schemas and schemas with external `$ref`s are refused.
- A package manager OpenMoat does not read (bunx, pnpm dlx, a global install, a `node`
  path into `node_modules`) or an image tag without a digest leaves the release
  unrecorded or recorded by its tag; a version range reads only what npx installed.
  The guard reads npm's and uv's directories on each MCP call it checks; the cost is a
  few small file reads.
