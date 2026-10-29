# ADR-045: `openmoat mcp proxy` passes on only what it checked, and only the calls the hook decided

Status: accepted · Date: 2026-10-28 · Builds on ADR-026 and ADR-032

## Context

`openmoat mcp proxy` relays one stdio MCP server's JSON-RPC (ADR-026). Until now it checked
one thing on the way in: a `tools/call` of a tool the pins hold, or one nobody accepted, was
answered by the proxy and never reached the server (ADR-032). An audit of the relay found
these paths by which a call or a listing still went past it unchecked:

1. **Parser differences.** The relay checked the message it parsed and then passed on the
   line as the host wrote it. A key given twice (`"method":"ping"…"method":"tools/call"`,
   two `params.name`) is one message to `serde_json`, which keeps the last, and another to a
   reader that keeps the first. A `\r` is JSON whitespace, so one line could hold a checked
   `ping` whose middle, cut at each `\r` as Python's universal newlines read stdin, is a whole
   `tools/call` nobody checked. U+0085, U+2028 and U+2029, which JSON leaves raw in strings,
   end a line for `str.splitlines`. From the server, a line the relay could not read (a lone
   surrogate, `NaN`) was passed on untouched, though a JavaScript or Python host reads it:
   an unfiltered listing reached the model.
2. **Shapes.** A batch inside a batch, or a batch member that is not an object, passed
   unchecked. A message with both `method` and `result` was filtered as neither. A method
   in another case (`Tools/Call`) was not checked.
3. **Responses.** Any response the server sent reached the host, whatever its id: a server
   could answer a call the relay had refused, or send a listing nobody asked for.
4. **First sight.** Under `mcp.trust_first_sight`, a call made before the first listing
   passed for any tool name.
5. **A tool that changes mid-session.** After `notifications/tools/list_changed` the relay
   held a changed tool only if the host listed the tools again; a host that keeps its first
   listing went on calling the changed tool.
6. **Arguments and other methods.** A call of an accepted tool passed whatever its
   arguments named; `resources/read`, `prompts/get` and the server's own requests
   (`sampling/createMessage`, `elicitation/create`) passed unrecorded.
7. **Who made the call.** The proxy's audit rows carried a session of its own
   (`mcp-<server>-<pid>-<ms>`): nothing tied a relayed call to the agent session, its taint
   or the person's answer to an `ask`.

## Decision

1. **The relay passes on only what it read, written again by itself.** Every message it
   sends, to the server or to the host, is the value it parsed and checked, written as
   compact JSON with U+0085, U+2028 and U+2029 escaped. No byte the relay did not check
   reaches the other side. A line from the host it cannot read is answered with a parse
   error; one from the server is dropped and reported on the proxy's standard error.
2. **Strict shapes.** A message is a request (`method`, no `result` or `error`), a
   notification (a request without `id`) or a response (`result` or `error`, no
   `method`); anything else is refused (-32600 to the host) or dropped (from the server),
   batch members included. A request id is a string or a number. A method that is a checked
   one in another case or with spaces is refused.
3. **A response must answer a request.** The relay keeps the ids of the host's requests the
   server has not answered (at most 4096; `notifications/cancelled` frees one). A response
   with any other id is dropped, except an error with a `null` id, which names no request.
   A host request may not reuse an unanswered id or use the ids the relay keeps for itself
   (`openmoat-relay-…`).
4. **No pin, no call.** A `tools/call` of a tool with no accepted pin is refused, before the
   first listing too, whatever `trust_first_sight` says.
5. **The relay reads the tools again itself.** On `notifications/tools/list_changed` the
   relay asks the server for its tools (every page, up to 100) and holds each changed one
   as in any listing, whether or not the host lists again. Calls wait (are refused with a
   retry message) until the listing arrives, for at most 10 s; a server that never answers
   gets its calls checked against the pins it had.
6. **The gateway decides each call on the policy, as it reaches the server.** A
   `tools/call` the pins let through is decided by the user's policy, with the lock checked
   first, under the name `mcp__<server>__<tool>` and with the paths and URLs its arguments
   name read exactly as the hook reads them (`openmoat_hosts::mcp_call_action`). A deny
   refuses it (-32001, the rule and reason in the message) and nothing reaches the server.
   `resources/read` is decided the same way, a `file:` URI as the file it names and a URI
   whose scheme connects somewhere (`https:`, `ws:`, …) as a host; any other URI names what
   only the server resolves. `prompts/get` and the server's requests are recorded.
7. **A call passes only on a hook decision for exactly that call.** Each time `openmoat
   guard` decides an MCP call it does not deny (an `ask` where no person can see it counts
   as a deny), it adds a row to the audit database's `mcp_tickets` table: the event, the
   host, session and call id, the tool name and the SHA-256 of the arguments in canonical
   form (keys sorted, `{}` for none). The proxy passes a `tools/call` on only when it can
   take such a row: the same arguments, the tool its server and name spell, under an hour
   old. Taking the row removes it, so one decision lets one call through. The proxy's audit
   row then carries the hook's session and call id. A call with no such row is refused
   (`mcp-unattributed`): the host did not run its hook for it, or sent other arguments than
   the hook checked.
8. **The audit schema is version 6.** `mcp_tickets` is a lookup, not a record: rows are
   removed when taken or an hour old, and both decisions are in the events table.

## Consequences

- The hook stays where the person's answer, the session's taint (every MCP call asks after
  the session read a secret, ADR-020), `openmoat allow` grants and the repository policy
  are known. The proxy enforces that decision for the exact call that reaches the server,
  and enforces the policy's denies again on what the server receives, so a host that skips
  its hook, changes the arguments after it, or names the tool another way gets nothing
  through. Every agent whose MCP servers OpenMoat pins runs its hook for MCP calls; a
  wrapped server used by anything else (an agent with no hook, a script) has its calls
  refused. That is a change for whoever ran a wrapped server outside an agent.
- The binding is to the call, not to a process: a proxy cannot know which session sent a
  call except through the decision it matches. Two sessions sending the same tool the same
  arguments are told apart only by which decision each takes; one decision still lets only
  one call through.
- An `ask` is honoured as the host reports it: after the host asked and the person said
  no, the host sends nothing, and the decision row expires unused. A host that sent the
  call anyway would find that row. Hosts are trusted to honour their own answers, as they
  are without the proxy.
- A tool name an agent shortens to fit a limit (Hermes Agent past 64 characters) cannot be
  matched to its decision, so that tool's calls are refused through the proxy.
- Every relayed message is written again: keys come out sorted, and an integer beyond 64
  bits arrives as the nearest double, as a JavaScript host sends it anyway.
- Each `tools/call` costs the work of one hook decision (the lock check, the policy read
  and compiled, an audit row), without starting a process; reading and writing the
  messages themselves is a small part of it. Caching the compiled policy while the lock is
  unchanged would remove most of that work, and is left for later.
- Still not covered: remote (HTTP) MCP servers, which the hook alone checks; tool results
  and resource contents, which reach the model unchecked (a result marks the session
  untrusted, ADR-020); plugin and managed MCP servers (ADR-026).
