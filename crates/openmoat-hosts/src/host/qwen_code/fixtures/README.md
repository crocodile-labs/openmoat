# Qwen Code fixtures

Not captured from a running `qwen`: every payload here is built from Qwen Code's
documentation and source, read 2026-11-14 (npm's latest release was 0.27.3), with the
project at `/p` and the home directory at `/Users/me`. The weekly `latest agents` job
installs the latest release, but drives no model turn through it yet, so none of these
has been compared with a real payload.

| Source | What it gives |
|---|---|
| <https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/> | the `PreToolUse` fields, the decision format, exit codes, matchers |
| `packages/core/src/hooks/hookEventHandler.ts` (`firePreToolUseEvent`), `QwenLM/qwen-code` `main` | `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`, `permission_mode`, `tool_name` (the runtime name, unchanged), `tool_input`, `tool_use_id` |
| `packages/core/src/tools/tool-names.ts` | the tool names |
| `packages/core/src/tools/shell.ts`, `read-file.ts`, `write-file.ts`, `edit.ts`, `grep.ts`, `web-fetch.ts` | the argument keys of each tool |
| `packages/core/src/tools/mcp-tool.ts` | `mcp__<server>__<tool>` |

| Fixture | Tool | Notes |
|---|---|---|
| `run_shell_command.json` | `run_shell_command` | the weekly job's golden shell payload |
| `read_file.json` | `read_file` | a secret file |
| `read_file-malformed.json` | `read_file` | `absolute_path` (Gemini CLI's older key) in place of `file_path`: refused |
| `write_file.json`, `edit.json` | `write_file`, `edit` | |
| `grep_search.json` | `grep_search` | |
| `web_fetch.json` | `web_fetch` | |
| `mcp.json` | an MCP tool | the server name `files` is made up |
| `todo_write.json` | `todo_write` | ungoverned; `permission_mode` `yolo` |
| `agent.json` | `agent` (the subagent tool) | its argument keys were not read and are a guess (`description`, `prompt`, `subagent_type`, as Claude Code's `Task`) |

The timestamps and ids are made up.
