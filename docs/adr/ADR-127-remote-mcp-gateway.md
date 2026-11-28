# ADR-127: The MCP gateway for remote servers: a pinned URL, a token the agent never holds, every address checked

Status: accepted, released as a preview in 0.28.0; its "Not built" part stays proposed · Date: 2026-11-24 · Builds on ADR-020, ADR-026, ADR-045, ADR-069,
ADR-081, ADR-114 and ADR-117

## Context

The MCP gateway (`openmoat mcp proxy`, ADR-045) checks what a stdio server and an agent
say to each other: pinned tools and identity, a hook decision for every call, result
checks (ADR-058, ADR-069, ADR-114). Remote servers, reached over HTTP, had none of it.
The hook decides their calls, but nothing pins what they list, and the agent holds their
tokens: the host's MCP client signs in and keeps the OAuth token where the agent (and
any code it runs) can read it. ADR-114 designed a remote gateway as future work: keep
tokens, no passthrough, discover safely, reuse the pins.

The MCP specification's own advice is the same list. Clients must not pass a token
through to another server, and must check where discovery leads
([security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices));
OAuth discovery (RFC 9728, RFC 8414) is a request to a URL a server names, which is how
server-side request forgery into a local network or a cloud metadata service happens.

OpenMoat already makes outbound requests safely in two places: the egress proxy
(`openmoat_proxy::connect`: resolve once, check every address, connect to exactly those)
and live audit delivery (ADR-081: `https` verified, no redirect). Neither is an MCP
client.

## Decision

1. **The gateway is a stdio server the agent starts.** `openmoat mcp remote --server
   <name> --url <url>` takes the place of the remote entry in the agent's configuration.
   It runs the same relay as `openmoat mcp proxy` (pins, held tools, identity, the hook's
   decision per call, result checks, `inputRequests`, all unchanged); where the relay
   writes toward the server, each line becomes one `POST` to the URL, on a thread of its
   own, and the answers (one JSON message, or the events of a `text/event-stream`) are
   handed back to the relay as the server's output. A request that cannot be sent is
   answered with JSON-RPC error -32603 naming why, so the agent does not wait. The agent
   speaks stdio to OpenMoat and never reaches the server's HTTP itself, so it cannot add
   a header, and no response header reaches it.

2. **A person pins the URL and gives the token.** `openmoat mcp login <name> --url <url>
   [--no-token | --forget]` is a person's command (terminal, no agent among its parents,
   intact lock, the possession gate of ADR-117, and `kernel-self` denies it to agents).
   It writes `~/.moat/mcp-remote/<name>.json`, owner-only, holding the URL and the token;
   `kernel-self` gains `~/.moat/mcp-remote/**` and `**/.moat/mcp-remote/**` among the
   state files an agent may not read (and already denies writing anything under
   `~/.moat`). `openmoat mcp remote`
   refuses any URL other than the pinned one, a drifted lock, and a host a deny rule of
   the policy names (the catch-all for unlisted hosts does not count: a person named
   this server). The token goes in `Authorization: Bearer` of each request, and only to
   that URL's origin.

3. **Every address is checked, through the egress proxy's connect.** The URL must be
   `https`, or plain `http` to a loopback literal (`127.0.0.1`, `[::1]`; not the name
   `localhost`), with no user name, password or fragment, and no host in an unusual
   address notation. Every address the name resolves to is checked by
   `openmoat_proxy::connect` with the policy's address rules
   (`openmoat_proxy::address_policy`), and the connection goes to one of exactly those
   addresses (no second lookup to race): private and shared addresses only when an allow
   rule names the address, loopback only when the URL writes it and an allow rule names
   it with its port, link-local and the cloud metadata services never. No redirect is
   followed. TLS is verified against the system's roots (rustls, already in the
   workspace). No new crate.

4. **Discovery only names, and is checked like a request.** `openmoat mcp login` reads
   the server's Protected Resource Metadata (RFC 9728 §3.1: the `/.well-known/
   oauth-protected-resource` path on the server's own origin), over `https` only,
   through the same connect and with no token. Its `resource` must be the server it was
   asked about (origin and path), and every authorization server an `https` URL that
   passes the checks of §3; anything else is refused and named. The authorization
   servers are shown so the person knows where to get a token. A `401` or `403` from the
   server tells the agent a person must run `openmoat mcp login`, naming only the
   metadata's origin.

5. **The transport's own channels are OpenMoat's.** Every header is written by the
   gateway from the checked body and the record: `Accept`, `Content-Type`,
   `MCP-Protocol-Version` (the 2026-07-28 request's own, else the version the
   `initialize` answer gave), `Mcp-Session-Id` (from the `initialize` answer, visible
   ASCII only), and for 2026-07-28 requests `Mcp-Method` and `Mcp-Name` from the body. A
   value with anything but visible ASCII is not sent. A session the server ended (`404`
   with a session) is forgotten and the request answered with an error.

6. **Pins are the stdio server's.** Tool pins, identity and `server/discover` pins are
   kept under the server's name as for a stdio server; the URL takes the place of the
   command line (ADR-114 "Remote MCP"). The agent's configuration entry is pinned in the
   lock like any definition (ADR-026), so changing it needs `openmoat mcp accept`, and a
   changed URL is refused by §2 whatever the entry says.

## Not built (this ADR's remaining work)

- **Signing in.** The OAuth authorization code flow with PKCE, dynamic client
  registration, the browser hand-off and a loopback redirect, token refresh, and the
  issuer check of an authorization response (RFC 9207). Today the person types a token
  (an API key, or an access token the authorization server issued); one that expires is
  replaced with `openmoat mcp login` again.
- **The older HTTP+SSE transport** (2024-11-05), and a `GET` stream for messages the
  server starts on its own (notifications, 2025 server requests).
- **`Mcp-Param-*` headers** from a tool's pinned `x-mcp-header` mappings (ADR-114 §6).
- **`openmoat mcp wrap` for remote entries**, which would write the `openmoat mcp remote`
  entry and run the login itself; and the token in the system keychain instead of a file.
- **Keeping connections open.** Each request is its own connection (`Connection:
  close`); a slow server costs a TLS handshake per message.

## Alternatives considered

- **Extend `openmoat mcp proxy` with `--url`.** Its startup check (ADR-049) compares a
  command line with accepted definitions; a URL pinned by a person's own command is a
  simpler and stricter check, and the two commands read differently in a configuration.
- **Keep the token in the policy's `secrets:`.** Brokered secrets belong to `openmoat
  run`'s proxy and its request rules; a gateway token is used by one process for one
  origin. The record keeps the URL and the token together, so neither can be changed
  alone.
- **The live audit delivery client (`Poster`).** It reads only an accepted answer's head
  and body, lets private addresses through (a collector lives there), and has no way to
  return response headers or stop at an event; the proxy's `connect` is the stricter
  address check.
- **An HTTP client crate.** Every one brings an async runtime or a second TLS stack; the
  workspace already has `httparse`, `rustls` and the proxy's connect.

## Consequences

- An agent whose remote server goes through the gateway never holds its token, and a
  token typed once reaches only the pinned origin.
- A remote server on a private network or this machine needs an allow rule naming its
  address; one that resolves to a link-local or metadata address is never reached.
- Tests: the URL checks, the record, the event stream, the sign-in metadata and the
  answer reader run without a network; one transport test against a local server binds
  a loopback port (CI); end-to-end tests run the binary's refusals, the pin and its undo,
  and a pinned server at an address no rule names, without opening a connection.

## Implementation

`openmoat`: `mcp/remote.rs` (the record, the URL checks), `mcp/remote/transport.rs`
(requests, the answer reader), `mcp/remote/sse.rs` (event streams),
`mcp/remote/discovery.rs` (RFC 9728), `commands/mcp/remote.rs` (the gateway),
`commands/mcp/login.rs` (the person's command), `cli/mcp.rs`. Default policy:
`kernel-self` names `mcp login` and denies reading `mcp-remote/` under the state
directory.
