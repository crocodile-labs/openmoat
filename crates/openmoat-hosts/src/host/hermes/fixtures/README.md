# Hermes Agent hook payloads

None of these fixtures is captured from a running Hermes Agent: a tool call needs a
model answer, and capturing one means signing in to a model provider. Each is built
from the source of `NousResearch/hermes-agent` v0.22.5 (tag of 2026-10-23), read on
2026-10-25, so a guess is never mistaken for a capture.

| Field | Source |
|---|---|
| `hook_event_name`, `tool_name`, `tool_input`, `session_id`, `cwd`, `profile`, `extra` | `_serialize_payload` and `_payload_fields` in `agent/shell_hooks.py`: the keys in that order; `cwd` is `Path.cwd()` of the Hermes process; `session_id` falls back to `parent_session_id`, then `""`; `profile` is `get_active_profile_name()` (`default`, a profile's name, or `custom`). |
| `extra` | every other keyword `_get_pre_tool_call_directive_details` in `hermes_cli/plugins.py` passes: `task_id`, `tool_call_id`, `turn_id`, `api_request_id`, `middleware_trace`. |
| the reply | `_parse_pre_tool_call` and `_evaluate_result` in `agent/shell_hooks.py`: `block` (as `action` or `decision`), `modify`, `action: approve` with `message` and `rule_key`; exit 2 blocks. |

## Tool arguments (v0.22.5)

From each tool's schema:

- `terminal` (`tools/terminal_tool.py`): `command`, `background`, `timeout`, `workdir`
  (absolute), `pty`, `notify`, `heartbeat`, `persist_on_release`.
- `read_file`: `path`, `offset`, `limit`. `write_file`: `path`, `content`. `patch`:
  `path`, `old_string`, `new_string`, `replace_all`, or `mode: patch` with a V4A
  `patch`. `search_files`: `pattern`, `target` (`content` or `files`), `path` (default
  `.`), `file_glob`, `limit`, `offset`, `order`, `output_mode`, `context`
  (`tools/file_tools.py`).
- `web_search`: `query`, `limit`. `web_extract`: `urls` (at most 5), `char_limit`
  (`tools/web_tools.py`). `browser_navigate`: `url`; `browser_click`: `ref`
  (`tools/browser_tool.py`).
- `execute_code`: `code`, `reset` (`tools/code_execution_tool.py`).
- `memory`: `action`, `target`, `content`, `old_text`, `new_text` (`tools/memory_tool.py`).
- `process_manage`: `action`, `session_id`, `data`, … (`tools/process_registry.py`).
- `cronjob_manage`: `action`, `schedule`, `prompt`, `script`, … (`tools/cronjob_tools.py`).
- `skill_manage`: `operations`, each with `name` and `action` (`tools/skill_manager_tool.py`).
- `todo_list` (`tools/todo_tool.py`).
- MCP tools are `mcp__<server>__<tool>`, each part with every character but ASCII
  letters, digits and `_` as `_`, a name over 64 characters cut and hashed
  (`mcp_prefixed_tool_name` in `tools/mcp_tool_schema.py`). The documentation still
  says `mcp_<server>_<tool>`; the source is what Hermes sends.
- `tool_call` is the Tool Search bridge, `{"calls": [{"name", "arguments"}]}`
  (`tools/tool_search_validation.py`). Hermes unwraps a single call before the hook
  (`_unwrap_tool_search_call` in `agent/tool_executor.py`), so the hook sees the real
  tool; it keeps the wrapper only for a batch of connector calls, whose entries fire
  the hook one by one, and for a call it cannot read.

`read_file-malformed.json` carries `file_path` in place of `path`: a missing key is an
adapter error, so a deny. `read_file-relative.json` names a path relative to the
session's directory, which the payload does not send.

Replace these with captured payloads once someone signed in runs Hermes with a hook
that copies its stdin (`command: "tee /tmp/payload.json"` under `hooks.pre_tool_call`
in a scratch `HERMES_HOME`, approved in its `shell-hooks-allowlist.json`), or with
`hermes hooks test pre_tool_call --for-tool terminal`.
