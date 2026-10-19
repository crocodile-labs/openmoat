# ADR-032: `moat mcp proxy` holds a new server's tools until a person accepts them

Status: accepted · Date: 2026-10-19 · Supersedes the first-sight part of ADR-026 §5

## Context

ADR-026 §5 has `moat mcp proxy` pin every tool the first time it sees a server
(`~/.moat/mcp/<name>-<hash>.json` absent), and hold only a tool that changed or is
new after that. That trusts first sight. A server that is already malicious on first
contact (a typosquatted package, a compromised release, a definition planted and then
accepted by name) gets its tool descriptions pinned as good, and the model reads its
instructions from the first call on. The pins then protect the poisoned text against
being changed back.

The proxy is opt-in per server (`moat mcp wrap`, `moat init --mcp-proxy`), so the
people who use it have chosen to review that server. One review per server is a
small cost for them.

## Decision

1. **First sight holds.** When the proxy starts for a server with no pins file, every
   tool the server lists is held, exactly like a changed tool today: left out of
   `tools/list`, recorded as pending in the pins file, and a `tools/call` for it (or
   for any tool before the first listing) is answered by the relay with error -32602
   naming `moat mcp accept <server>`. The call never reaches the server.
2. **A person accepts.** `moat mcp accept <server>` (person-only, as before) shows each
   pending tool's name, description and input schema as a diff against nothing, asks
   `[y/N]`, and on yes pins them. Later changes are held as ADR-026 describes.
3. **Wrapping says so.** `moat mcp wrap` and `moat init --mcp-proxy` print one line
   naming the wrapped servers with no pins yet: their tools wait for `moat mcp accept`
   after the server's first start.
4. **Existing pins stay.** A server whose pins file exists (pinned on first sight by an
   earlier release) keeps those pins; only a server with no pins file is held.
5. **A switch restores the old behaviour.** `mcp: { trust_first_sight: true }` in the
   user policy has the proxy pin a new server's first listing as it is. It is off by
   default, `moat policy lint` warns while it is on, and the proxy honours it only
   while the policy lock is intact; a policy it cannot read or a drifted lock holds.

## Consequences

- A newly wrapped server shows no tools in the agent until a person runs
  `moat mcp accept <server>` after its first start. The note at wrap time and the
  -32602 error say what to run.
- A server that lists no tools at first writes no pins file, so its first non-empty
  listing is still held.
- `openmoat-core`'s `Policy` gains the optional `mcp:` section (`McpSettings`); the core
  stays pure.
- The rest of ADR-026 stands: prompts, resources, `outputSchema`, annotations, tool
  results, remote (HTTP) servers, plugin servers and managed MCP configuration are
  still not covered by the proxy.
