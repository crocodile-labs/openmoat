# ADR-107: Correlate Codex MCP metadata with one hook ticket

Status: proposed · Date: 2026-11-22 · Builds on ADR-045 (the MCP gateway's hook
tickets), ADR-069 (the gateway's whole-server surface) · Numbered 107: 103 to 106 were
taken when it was merged (it was written as 103)

## Context

`openmoat mcp proxy` passes a `tools/call` on only when the agent's hook allowed a
matching call: the guard writes an MCP ticket for each allowed MCP call, and the proxy
takes one (ADR-045). Without anything that names the call, the ticket is matched by
host, tool and argument digest (ADR-069). Independent Codex threads can issue
identical MCP arguments and reuse a JSON-RPC request id, so one thread's call could
take the ticket another thread's hook earned.

Codex puts its own ids in the `_meta` of the `tools/call` it sends. In Codex's source
(`codex-rs/core/src/mcp_tool_call.rs` in
[openai/codex](https://github.com/openai/codex/blob/main/codex-rs/core/src/mcp_tool_call.rs)),
`build_mcp_tool_call_request_meta` inserts `callId`, and `with_mcp_tool_call_ids_meta`,
called for an approved tool call, inserts `threadId` and `sessionId`. That is the path
of a tool call the model makes in an agent turn. The contributor observed it with
Codex 0.169.0: two isolated Codex sessions with a trusted hook produced the same call
id and arguments but distinct thread ids, and each hook's `session_id` and
`tool_use_id` matched the `threadId` and `callId` of the frame the upstream received.
A call made straight through Codex's app server may carry neither id; this was
observed, not read in Codex's documentation, which does not describe these keys.

## Decision

1. For a proxy whose agent is Codex, when the call's `_meta` has `threadId` or
   `callId` (the keys are a fact of the agent's spec, `McpSpec::call_ids`, so
   another agent that sends such ids gets the same check), both must be
   non-empty strings, and the proxy takes only an `allow`
   ticket with exactly that session, call id, tool and argument digest. An
   incomplete, empty or mismatched pair is refused; it never falls back to ADR-069's
   argument matching.
2. Other agents, and Codex calls with neither id, keep ADR-069's matching.
3. The guard writes the MCP ticket after every other write the call needs (the audit
   row, provenance, the `openmoat run` taint link). A write that fails makes the guard
   deny, and must not leave a ticket behind that lets the proxy pass the call on.
4. When either side of the proxy stops, the server gets a bounded shutdown: a short
   wait for its output to close and for it to exit, then `SIGTERM` to its process
   group, a few more seconds, and `SIGKILL` (on Windows, the process is killed). The
   server runs in its own process group on Unix, so what it started is stopped with
   it.

## Consequences

The ids correlate a call with its hook decision; they do not authenticate the client.
Anything that can write to the proxy's stdin can write any `_meta`. A gateway shared
by several agents must bind the agent and thread itself before it takes tickets: Unix
socket permissions restrict the operating-system user, not the agent session, and
`openmoat run`'s relay credential is shared inside a sandbox and identifies no
particular client (its hooks write no MCP tickets). Neither is a session credential.
This decision does not let a bare app-server call through, and does not make a
shared daemon safe to deploy.

If a Codex release sends `callId` without `threadId` on a path this ADR did not see,
its MCP calls through the proxy are refused, not passed: the failure is closed and
shows in the audit log. It stays proposed until the ids are confirmed on every Codex
path that reaches an MCP server, or Codex documents them.

A server started by hand with `openmoat mcp proxy` in a terminal no longer receives
the terminal's Ctrl-C itself, since it is in another process group: Ctrl-C stops the
proxy, and the server then reads the end of its input, as when an agent closes it. A
server that ignores that keeps running and is stopped by hand (`kill -- -<pid>`).
