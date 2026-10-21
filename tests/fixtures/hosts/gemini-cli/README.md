# Gemini CLI hook payloads

None of these fixtures is captured from a running Gemini CLI: a tool call needs a
model answer, and capturing one means signing in. Each is built from the hooks
reference (<https://geminicli.com/docs/hooks/reference/>) and from the source of
`@google/gemini-cli` 0.65.0, read from the npm package on 2026-10-20, so a guess is
never mistaken for a capture.

| Field | Source |
|---|---|
| `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp` | `createBaseInput` in `packages/core/src/hooks/hookEventHandler.ts`; the reference's "Base input schema". |
| `tool_name`, `tool_input`, `original_request_name` | `fireBeforeToolEvent`; the reference's `BeforeTool`. |
| `mcp_context` | `extractMcpContext` in `packages/core/src/core/coreToolHookTriggers.ts`: `server_name`, `tool_name` (the server's own name for the tool), `command`, `args`, `cwd`, `url`, `tcp`; sent only for an MCP tool. |

## Tool arguments (Gemini CLI 0.65.0)

From <https://geminicli.com/docs/reference/tools/> ("Tool argument keys") and the
tool schemas in `packages/core/src/tools/definitions`:

- `run_shell_command`: `command`, `description`, `dir_path`, `is_background`.
- `read_file`: `file_path`, `start_line`, `end_line`. `write_file`: `file_path`, `content`.
  `replace`: `file_path`, `old_string`, `new_string`, `instruction`, `allow_multiple`.
- `list_directory`: `dir_path`. `glob`: `pattern`, `dir_path`. `grep_search` (legacy
  name `search_file_content`): `pattern` (a regular expression), `dir_path`, `include_pattern`.
- `read_many_files`: `include` (paths or globs), `exclude`.
- `web_fetch`: `prompt`, a request holding up to 20 URLs (`parsePrompt` takes each
  whitespace-separated word with `://`). `google_web_search`: `query`.
- `read_mcp_resource`: `uri`.
- MCP tools are named `mcp_<server>_<tool>` (<https://geminicli.com/docs/tools/mcp-server/>,
  "Tool naming and namespaces").

`read_file-malformed.json` carries `absolute_path`, the key older Gemini CLI releases
used, in place of `file_path`: a missing key is an adapter error, so a deny.

Replace these with captured payloads once someone signed in runs Gemini CLI with a
hook that copies its stdin (`"command": "tee /tmp/payload.json"` under
`hooks.BeforeTool` in a scratch `GEMINI_CLI_HOME`).
