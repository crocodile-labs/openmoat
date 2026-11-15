# Crush fixtures

Not captured from a running `crush`: every payload here is built from Crush's
documentation and source at `charmbracelet/crush` `main`, read 2026-11-14 (latest
release v0.101.0), with the project at `/p` and the home directory at `/Users/me`. No
weekly job installs Crush yet, so none has been compared with a real payload.

| Source | What it gives |
|---|---|
| `docs/hooks/README.md` | the payload of its `PreToolUse` example (`event`, `hook_event_name`, `session_id` `313909e`, `cwd`, `tool_name`, `tool_input`, `tool_use_id`), the decision format, exit codes |
| `internal/hooks/input.go` (`Payload`) | the same fields; no `transcript_path` or `permission_mode` |
| `internal/config/config.go` (`allToolNames`), `internal/agent/tools/*.go` | the tool names and each tool's `*Params` keys |
| `internal/agent/tools/mcp-tools.go` | `mcp_<server>_<tool>` |

| Fixture | Tool | Notes |
|---|---|---|
| `bash.json` | `bash` | |
| `view.json` | `view` | a secret file |
| `view-malformed.json` | `view` | `path` in place of `file_path`: refused |
| `write.json`, `edit.json`, `multiedit.json` | `write`, `edit`, `multiedit` | |
| `fetch.json` | `fetch` | |
| `mcp.json` | an MCP tool | the server name `files` is made up |
| `todos.json` | `todos` | ungoverned; its item keys are a guess |
| `agent.json` | `agent` (the subagent tool) | `prompt` from its `*Params`; `access` left out |

The ids other than the documented `313909e` are made up.
