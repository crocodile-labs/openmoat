# ADR-095: Another agent running a host's hook

Status: accepted · Date: 2026-11-14 · Builds on ADR-025 (defer), ADR-004 (fail closed) and
the Cursor reading of Claude Code's hook (`host/claude_code/from_cursor.rs`)

## Context

Several agents load the hook files of Claude Code and Cursor and run the hooks they find
with input of their own:

- **Grok Build** (`grok`) reads `~/.claude/settings.json` (not gated by its folder trust),
  a project's `.claude/settings*.json` and `.cursor/hooks.json`. It sends its own
  camelCase envelope (`hookEventName`, `sessionId`, `toolName`, `toolInput`,
  `workspaceRoot`) with Claude Code's snake-case names added beside it, and keeps its own
  tool names (`run_terminal_command`, `search_replace`); only a matcher's Claude names are
  mapped onto Grok's (`xai-org/grok-build` at `2bdd1d6a`,
  `crates/codegen/xai-grok-hooks/src/{event,matcher,discovery}.rs`). Only exit 2 or
  `{"decision": "deny"}` blocks; a timeout, a crash, malformed output or any other answer
  runs the call (<https://docs.x.ai/build/features/hooks>).
- **The Devin CLI** loads `.claude/` hooks by default (`read_config_from.claude`) and
  sends Claude Code's field names with its own tool names (`exec`, `read`, `edit`, `grep`,
  `webfetch`). It reads a top-level `decision` (`approve`, `block`) or exit 2 and runs the
  call on anything else (<https://docs.devin.ai/cli/extensibility/hooks/overview>,
  <https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks>).

`openmoat guard --host claude-code` read such a call with Claude Code's mapping, which knows
none of those tool names: the call was recorded `ungoverned` and deferred, so the other
agent ran it unchecked, a secret read included. A `review` sent as Claude Code's `ask`
ran too. Neither agent is a host of OpenMoat's; their users are protected only where
`openmoat run` applies.

## Decision

1. Claude Code's adapter treats a `PreToolUse` or `PostToolUse` payload as another
   agent's when it carries Grok Build's envelope (`hookEventName`, a key Claude Code never
   sends) or names a tool OpenMoat's own `PreToolUse` matcher does not match. Claude Code
   asks the hook only about the tools that matcher matches, an unanchored regular
   expression (`Write` matches `TodoWrite`), and the test follows the same rule, so its
   own payloads are not affected.
2. Such a tool is read as an unknown tool (`wire::unknown`): every path, URL and command
   its arguments name is checked, and `defaults.tool.unknown` decides the tool itself
   (`defer` in the default policy). A tool the matcher names keeps Claude Code's reading.
3. The call is decided as one that cannot prompt (`HookEvent::PreToolUseNoPrompt`): a
   `review` is a deny that says how to approve it. A deny exits 2, which both agents read
   as a block. A `defer` gives no answer and leaves the call to the agent, as it does for
   Claude Code.
4. A payload that is not a JSON object with a tool name, or whose arguments cannot be
   read, stays an error, which `guard` denies (ADR-004). Cursor's hook refuses a Grok
   payload (its event is not one of Cursor's), so a Grok call that reaches it is denied.
5. No `Host` variant is added: the call is recorded under the hook that ran it. A real
   adapter for either agent is a separate piece of work.

## Consequences

- A secret read or an exfiltration through Grok Build or the Devin CLI that reaches
  OpenMoat's Claude Code hook is denied instead of run.
- Claude Code's own calls are read as before: a tool it adds reaches the hook only when
  the matcher matches it, and then it keeps Claude Code's reading.
- A foreign tool whose name contains one of the matcher's names (case-sensitive) is
  told apart only by Grok's envelope; the Devin CLI's lower-case names contain none.
- Grok's tool argument names and the Devin CLI's `read` argument are not documented;
  the fixtures guess them, and the generic reading finds paths and URLs by their look
  under any key, so a wrong guess still checks what the call names.
