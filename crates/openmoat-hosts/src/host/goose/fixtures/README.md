# goose hook payloads

None of these fixtures is captured from a running goose: a tool call needs a model
answer, and capturing one means signing in to a model provider. Each is built from the
source of `aaif-goose/goose` v1.57.0 (release of 2026-10-28; the repository moved from
`block/goose`), read on 2026-11-03, so a guess is never mistaken for a capture.

| Field | Source |
|---|---|
| `event`, `session_id`, `matcher_context`, `tool_call_id`, `tool_name`, `tool_input`, `working_dir` | `HookContext` in `crates/goose/src/hooks/mod.rs` (serialised in that order, `None` fields left out) and `run_pre_tool_hooks` in `crates/goose/src/agents/state_machine/ops_toolcalling.rs`, which fills `with_tool` (name and arguments), `with_tool_call_id` and `with_working_dir` (the session's directory). `tool_input` is absent for a call without arguments (`list_functions.json`). |
| the reply | `classify_output` and `apply_verdict` in `hooks/mod.rs`: exit 2 blocks with stderr as the reason; `{"decision": "block", "reason"}` on stdout blocks whatever the exit code; exit 0 with nothing on stdout or `{"decision": "allow"}` allows; anything else is a hook failure, which `on_failure: block` turns into a block. |
| the hook file | `load_hooks_file` in `hooks/mod.rs` and `documentation/docs/guides/context-engineering/hooks.md`: `hooks/hooks.json` in a plugin directory found by `plugins/discovery.rs` (`~/.agents/plugins/<name>/`, `<project>/.agents/plugins/<name>/`). |

## Tool arguments (v1.57.0)

From each tool's schema:

- `shell`: `command`, `timeout_secs` (`agents/platform_extensions/developer/shell.rs`).
- `write`: `path`, `content`; `edit`: `path`, `before`, `after` (`developer/edit.rs`;
  a relative path is joined to the session's working directory, `resolve_path`).
- `tree`: `path`, `depth` (`developer/tree.rs`); `read_image`: `source` (a path or an
  http(s) URL), `crop` (`developer/image.rs`).
- `analyze`: `path`, `focus`, `max_depth`, … (`platform_extensions/analyze/mod.rs`).
- `delegate`: `instructions`, `source`, `working_dir`, …; `load`: `source`
  (`platform_extensions/summon.rs`).
- `execute_javascript`: `code` (`platform_extensions/code_execution.rs`, Code Mode, off by
  default); the tools a script calls are dispatched without the hook.
- An extension's tool is `<key>__<tool>` (`agents/extension_manager/mod.rs`, `name_to_key`
  in `config/extensions.rs`): `mcp.json` (`github__create_issue`), `todo.json`.

## Files

| File | What it shows |
|---|---|
| `shell.json` | a shell command that sends a key away |
| `shell-malformed.json` | an empty `command`: an adapter error, so a deny |
| `tool_input-not-object.json` | arguments that are not an object: an adapter error |
| `write.json`, `edit.json` | file writes; `edit` with a relative path |
| `tree.json`, `analyze.json` | directory reads |
| `read_image.json`, `read_image-url.json` | a local image and a downloaded one |
| `execute_javascript.json` | a Code Mode script, which needs review |
| `delegate.json` | a subagent started in another directory |
| `list_functions.json` | an ungoverned call with no arguments |
| `mcp.json`, `todo.json` | extension tools |
