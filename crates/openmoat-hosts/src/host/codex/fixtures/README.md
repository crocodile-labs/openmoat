# Codex hook payloads

The `pretooluse-*.json` and `permission-request-shell.json` payloads follow Codex's
hooks page (<https://learn.chatgpt.com/docs/hooks>) and the hook runner's source
(`codex-rs/hooks/src/events/`), as `codex.rs` cites them.

## After-call payloads (`PostToolUse`)

`posttooluse-shell.json` has the fields, and the type of each, that the weekly
`latest agents` run 42853181916 (2026-11-10, `main`) recorded from a real Codex on
macOS and Linux (`scripts/ci/latest-agents/after_call.py`, whose notice prints field
names and types, never values): `session_id`, `turn_id`, `transcript_path`, `cwd`,
`model`, `permission_mode`, `hook_event_name` (`PostToolUse`), `tool_name`,
`tool_use_id`, `tool_input` (`command`) and `tool_response`, a string for a shell
call. The hooks page types `tool_response` as any JSON value ("MCP tools send the MCP
call result"). The values are made up: the run's call was a harmless `echo`, and this
one carries a fetched page that names a host and a command.
`posttooluse-missing-response.json` has no `tool_response`, so the adapter refuses it.
