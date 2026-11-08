# ADR-069: The MCP gateway checks everything a server says to the model

Status: accepted · Date: 2026-11-08 · Amends ADR-026, ADR-032, ADR-045, ADR-057 and ADR-058

## Context

ADR-026 and ADR-032 pin each tool's definition and hold a change until a person accepts
it; ADR-045 has the gateway pass on only what it checked; ADR-057 and ADR-058 keep what a
tool's result names for the session that called it. A review of the gateway found
channels those decisions did not reach, each a way for a server to put text in front of
the model, or to have it counted for the wrong session, that a person never reviewed:

- the `instructions` of a server's `initialize` answer, which Claude Code puts in the
  model's system prompt, and its `serverInfo` reached the host unpinned, unrecorded and
  without taint, so a server could change what it tells the model at any start and no
  hold, review or audit row followed; the descriptions in `prompts/list`,
  `resources/list` and `resources/templates/list` were unpinned too;
- the server's requests to the host (`sampling/createMessage`, `elicitation/create`,
  `roots/list`) were recorded as allowed under the gateway's own session, never the
  agent's, so their text tainted nothing; a sampling request with `includeContext`
  had the host add the session's context, other servers' results included, to what it
  sent this server, which the cross-server flow check never saw; and the host's
  answers were passed on without checking that they answer a request the server sent;
- the review a person reads in `openmoat mcp accept` showed some invisible characters
  as `?` but not all of them: tag characters (U+E0000 to U+E007F) spell ASCII text no
  terminal draws, so a description could look harmless and still carry instructions;
- a JSON-RPC error answer to a tool call skipped the gate: its `message` and `data`
  reach the model as a result does, but left no injected-input fingerprints and no
  cross-server flow pieces, and the call stayed in the gateway's table of calls
  awaiting an answer;
- the gateway took a hook decision of any agent and any session with the same
  arguments, so with two agents, or two sessions, sending the same call, a result's
  pieces and fingerprints could be kept for the session that did not read it;
- the taint exemption for Claude in Chrome's tab lists (ADR-057 amendment of
  2026-11-07) was keyed by the tool's name alone, so a configured server named
  `claude-in-chrome` with a `tabs_context_mcp` tool got it too.

## Decision

1. **What a person accepts is what the model reads.** The cleaner every review goes
   through (`render::clean`) shows as `?` every format character (Unicode General
   Category Cf: the bidirectional controls, the zero-width characters, the soft hyphen,
   the invisible operators U+2061 to U+2064, the deprecated format characters U+206A to
   U+206F, the tag characters), the variation selectors (U+180B to U+180F, U+FE00 to
   U+FE0F, U+E0100 to U+E01EF), the combining grapheme joiner and the blank Hangul
   fillers, as well as the control characters it already did. Under a definition that
   holds any, `openmoat mcp accept` says how many. A tool whose definition holds one is
   never pinned on first sight under `mcp.trust_first_sight`: a person reviews it.

2. **An error answer is an answer.** The relay hands the gate a tool call's `error`
   object as it hands it a `result`; the gate keeps its pieces (ADR-058) and the
   fingerprints of what it names (ADR-057) under the session of the hook's decision,
   and forgets the call either way. An error the gate cannot record reaches the host
   as OpenMoat's own error, never as the server's text. Claude Code reports a failed
   call of its own tools in `PostToolUseFailure`, which the hook does not read yet:
   that needs a real machine to confirm the payload, and stays a documented gap.

3. **A decision is taken from the agent and the session the proxy serves.**
   `openmoat mcp wrap` writes `--host <agent>` into the definition it wraps (and adds it
   to one wrapped before), part of the command line the startup gate checks (ADR-049).
   The gateway then takes only that agent's decisions. Among them it takes one of the
   session it last passed a call for when one matches, and another session's only when
   none does: a host starts a stdio server for a session, but may go on using it after
   it starts a new one (Claude Code's `/clear`), so a strict binding would refuse every
   call after that. A proxy started without `--host` takes any agent's decisions, as
   before. A proxy still cannot know which session sent a call, only which decision it
   matched (ADR-045).

4. **The tab-list exemption is for the server the host provides.** Claude in Chrome is
   not defined in any MCP configuration file: Claude Code provides it itself (the
   browser extension, `claude --chrome`). Its name is the only thing that reaches the
   hook, so a server some configuration defines is told apart by being defined: when
   the lock pins a definition whose tools are named as `claude-in-chrome`'s
   (`takes_builtin_name`, the hosts' own spellings), the CLI adds that name to
   `taint.defined_servers` of the policy it decides with, and the core applies the
   built-in metadata list only while that list does not name it. A definition nobody
   accepted has its calls denied (`mcp-server-changed`), so it needs no entry; a lock
   that cannot be read leaves the exemption off. `openmoat mcp accept` says, when it
   shows such a server, that its tab lists will taint the session. A command, package
   or pinned tool definition was not used to recognise the real one: the real one has
   none of them in a file OpenMoat reads, and any of them can be copied. A tool the
   policy names in `taint.metadata_tools` keeps its exemption: a person listed it by
   its full name.

5. **The whole server surface is pinned with the tools.** The pin file of a server
   (`mcp/tools.rs`) also pins (`mcp/tools/surface.rs`) its `initialize` answer's
   `instructions` and `serverInfo` as one entry, and each entry of its prompt, resource
   and resource-template listings by its name, URI or URI template, each by the SHA-256
   of the whole entry in canonical JSON. One that differs from the accepted pin, or has
   none, is held as a tool is (ADR-032): held instructions are taken out of the answer
   and the host gets the accepted `serverInfo` (or one naming only the server), a held
   listing entry is left out, and a `prompts/get` of a held prompt is refused; a prompt
   never listed is not refused, since its content is the server's output either way.
   `openmoat mcp accept` shows each with a diff and accepts it with the tools, so a
   server is reviewed once, not per part. A `version` that reads as a version number
   (at most 32 letters, digits, `.`, `+`, `-`, `_`) is pinned as any version: an upgrade
   alone does not ask again; any other text there is pinned. Under
   `mcp.trust_first_sight`, a part never read is pinned as first read, unless it holds
   invisible characters (§1).
6. **A server accepted before this is not asked about again.** A pin file without
   these pins, of a server whose tools a person accepted, has each part pinned as the
   server first says it after the upgrade; listings the server's `initialize`
   capabilities do not offer then count as read, so ones it offers later are held. A
   server nobody accepted has everything held.
7. **Accepted instructions are still untrusted content.** The relay hands the gate the
   instructions it passes on; the gateway keeps them, and before it passes the first
   call of each session it serves, it records for that session a row that marks it
   untrusted (rule `mcp-server-text`, under the session's own host, as the hook's
   `mcp__<server>__<tool>` rows do), the instructions' pieces (ADR-058) and the
   fingerprints of what they name (ADR-057), with `mcp__<server>__initialize` as the
   source. A failure to record refuses the call. The proxy learns a session only from
   the hook decision a call matches, so a session that never calls one of the server's
   tools is not marked; what its model read is only text a person accepted.

8. **The server's requests to the host are checked.** A `sampling/createMessage`
   whose `includeContext` is anything but `none` is answered with error -32001 and
   recorded as refused (rule `mcp-server-request`): the host would add the session's
   context to what it sends this server. Every other request is recorded under the
   session the proxy served last, and its text (a sampling request's messages and
   system prompt, an elicitation's message) is kept as untrusted content of that
   session, as instructions are (§7), with `mcp__<server>__<method>` as the source; one
   sent before the proxy served any session is kept for the next one it serves (at
   most 64). The relay keeps the ids of the server's requests the host has not
   answered (at most 4096, as for the host's), forgets one the server cancels, and
   drops a host answer to any other id.

## Consequences

- A server's first start through the proxy holds its instructions with its tools: the
  agent runs without them until a person accepts the server, as it runs without its
  tools.
- An emoji's variation selector or zero-width joiner shows as `?` in reviews and logs;
  OpenMoat's own output uses none.
