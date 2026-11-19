# Junie CLI (draft, no adapter): #266

A draft of the adapter's `HOST.md`, kept until Junie's documentation states enough to
build one. **No adapter ships**: `openmoat init` does not set Junie up, and `openmoat
run` is the way to sandbox it today. Every fact below comes from JetBrains'
documentation, read 2026-11-19; nothing was installed or run.

Source: [Junie CLI hooks](https://junie.jetbrains.com/docs/junie-cli-hooks.html). Hooks
are in Junie's Early Access Program: they need the Early Access build of Junie CLI, and
no release version is named.

## What the documentation states

- Files: `~/.junie/config.json` (or a file given with `--config-location`). A project's
  `.junie/config.json` is ignored unless passed with `--config-location`, so a repository
  cannot add hooks of its own. Extensions bring `hooks/hooks.json` in the same schema.
- Format: Claude Code's nested layout. `"hooks"` maps an event (`PreToolUse`, …) to
  entries with an optional `matcher` (a regular expression on the tool name) and
  `hooks: [{"type": "command", "command": …}]`, run by `sh -c` (`cmd /c` on Windows).
  `timeout` is in seconds, 10 by default for `PreToolUse`.
- Blocking: exit 2 blocks the call whatever stdout says. Stdout JSON may give
  `"decision"`: `"allow"` (or none), `"ask"` (Junie asks the person) or `"block"`/`"deny"`,
  with `"reason"`. Any other non-zero exit is a warning and **the call runs**, unless the
  entry sets `blockOnError: true`; then a non-zero exit, a timeout, a launch failure or a
  configuration error blocks it. An adapter would set `blockOnError: true`.
- Input: one line of JSON. The `PreToolUse` example is `{"hook_event_name":
  "PreToolUse", "tool_name": "Bash", "tool_input": {"command": …, "run_in_background": …,
  "timeout": …}}`; `session_id`, `cwd` and `project_path` come "when the session provides
  them", and "more fields may be present".
- Tools: `Bash` (`command`), `Write` (`file_path`, `content`), `Read` and `Edit`
  (`file_path`), `Glob`, `Grep`, `apply_patch` (`patch`), and `powershell`.

## What it does not state, and why that stops an adapter

- **`session_id` and `cwd` are not promised for `PreToolUse`.** Without a session the
  taint of what a session read cannot follow its later calls, and without a directory
  `${project}` cannot be placed: every rule that holds the project would be guessed.
- **The input of `Edit`, `Glob`, `Grep` and `powershell`**, and the format of
  `apply_patch`'s `patch` (Codex's, or another), are not given.
- **The name an MCP tool reaches a hook with** (only "e.g. `github`").
- What `"ask"` does where no person can answer (a run without a terminal), and whether
  `"allow"` skips Junie's own prompt.
- That hooks run for subagents.

## The safe choices an adapter would make, once the facts are there

- One `PreToolUse` entry without a matcher (every tool) in `~/.junie/config.json`, with
  `blockOnError: true`, and `kernel-self` covering `~/.junie/`.
- A deny as exit 2 with the reason in stdout's `"reason"`; `review` as `"ask"` only where
  Junie is known to have a person to ask, a deny otherwise.
- A call without `session_id` or `cwd` decided as unparseable, never `allow`; an unknown
  tool as `tool.unknown` with its paths checked (ADR-097).
