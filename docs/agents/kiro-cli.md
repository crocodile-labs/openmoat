# Kiro CLI (draft, no adapter): #261

A draft of the adapter's `HOST.md`, kept until Kiro's documentation states enough to
build one. **No adapter ships**: `openmoat init` does not set Kiro up, and `openmoat run`
is the way to sandbox it today. Every fact below comes from Kiro's documentation, read
2026-11-19; nothing was installed or run.

Sources:
[hooks](https://kiro.dev/docs/hooks/) (updated 2026-11-12),
[hook types](https://kiro.dev/docs/hooks/types/),
[hook actions](https://kiro.dev/docs/hooks/actions/),
[CLI V3 hooks migration](https://kiro.dev/docs/cli/v3/hooks-migration/),
[CLI 2.x reference](https://kiro.dev/docs/cli/2x-reference/).

## What the documentation states

- Files: CLI V3 reads standalone hook files from `.kiro/hooks/*.json` in the workspace
  and `~/.kiro/hooks/*.json` globally; both run. A file is `{"version": "v1", "hooks":
  [...]}`, each hook with `name`, `trigger` (`PreToolUse`, …), an optional `matcher`, an
  `action` (`{"type": "command", "command": …}`), `timeout` (seconds, default 60, `0` for
  none) and `enabled`. CLI 2.x kept hooks in the agent profile instead
  (`"preToolUse": [{"command": …, "matcher": …}]`).
- Matchers: a tool ID, a category (`read`, `write`, `shell`, `web`, `spec`), a source
  (`@builtin`, `@mcp`, `@<server>`, `@<server>/<tool>`) or a regular expression; empty
  matches every tool.
- Input: "session context as JSON on STDIN". The only example (MCP) has
  `hook_event_name`, `cwd`, `session_id`, `tool_name` and `tool_input`. MCP tools reach a
  hook as `mcp_<server>_<tool>`.
- Blocking: the actions page says any non-zero exit of a `PreToolUse` command blocks the
  call and sends stderr to the agent. The 2.x reference says only exit 2 blocks and any
  other non-zero exit is a warning (the call runs).

## What it does not state, and why that stops an adapter

- **The built-in tool IDs of CLI V3** ("You can ask Kiro for the names of the available
  tools"). 2.x named `execute_bash`, `fs_read`, `fs_write`, `grep`, `glob`, `code`; the
  migration page says V3 rewrote them to the shared groups. An adapter that matches tool
  names it guessed would miss a renamed shell tool, and that tool's calls would run
  undecided.
- **The `tool_input` fields** of any tool (the one example has `{}`): the command of a
  shell call and the path of a file call cannot be read without guessing a key.
- **What a timeout or a crash does** with the call. The two pages disagree on non-zero
  exits, so whether a guard that cannot start blocks the call is unknown.
- Whether `PreToolUse` blocks in every approval mode, and what a hook's stdout may say
  (only `hookSpecificOutput.updatedInput` is named, from CLI 3.4.0).

## The safe choices an adapter would make, once the facts are there

- `PreToolUse` with an empty matcher (every tool) in `~/.kiro/hooks/openmoat.json`, the
  global file, never a workspace one (a repository could edit that).
- A deny as exit 2 with the reason on stderr, which blocks under both readings; `allow`
  only once Kiro documents how a hook says it.
- An unknown tool name decided as `tool.unknown` with every path and URL in its input
  checked (ADR-097), never `allow`.
- The timeout at the most the file allows, and `kernel-self` covering `~/.kiro/hooks/`
  and `.kiro/hooks/` (a hook file an agent writes runs later).
