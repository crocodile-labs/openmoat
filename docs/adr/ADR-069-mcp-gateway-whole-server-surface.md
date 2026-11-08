# ADR-069: The MCP gateway checks everything a server says to the model

Status: accepted · Date: 2026-11-08 · Amends ADR-026, ADR-032, ADR-045, ADR-057 and ADR-058

## Context

ADR-026 and ADR-032 pin each tool's definition and hold a change until a person accepts
it; ADR-045 has the gateway pass on only what it checked; ADR-057 and ADR-058 keep what a
tool's result names for the session that called it. A review of the gateway found
channels those decisions did not reach, each a way for a server to put text in front of
the model, or to have it counted for the wrong session, that a person never reviewed:

- the review a person reads in `openmoat mcp accept` showed some invisible characters
  as `?` but not all of them: tag characters (U+E0000 to U+E007F) spell ASCII text no
  terminal draws, so a description could look harmless and still carry instructions;
- a JSON-RPC error answer to a tool call skipped the gate: its `message` and `data`
  reach the model as a result does, but left no injected-input fingerprints and no
  cross-server flow pieces, and the call stayed in the gateway's table of calls
  awaiting an answer;
- the gateway took a hook decision of any agent and any session with the same
  arguments, so with two agents, or two sessions, sending the same call, a result's
  pieces and fingerprints could be kept for the session that did not read it.

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

## Consequences

- An emoji's variation selector or zero-width joiner shows as `?` in reviews and logs;
  OpenMoat's own output uses none.
