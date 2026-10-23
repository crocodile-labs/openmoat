# Gemini CLI (`gemini-cli`)

Gemini CLI (`gemini`, npm `@google/gemini-cli`), through its `BeforeTool` command hook,
checked against the source of 0.65.0. Since 2026-06-18 Gemini CLI signs individual
accounts in only with an API key or Vertex AI; Google's own sign-in for them moved to the
Antigravity CLI, which OpenMoat does not support yet. Every fact here comes from
[`gemini_cli.rs`](../gemini_cli.rs) and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout |
|---|---|---|
| `BeforeTool` | `*` | 600 s |

Input is `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`,
`tool_name`, `tool_input` and, for an MCP tool, `mcp_context`. `{"decision": "deny"}` or
exit 2 blocks; no output, or `"allow"`, leaves the call to Gemini CLI's own policy.

## Tools OpenMoat sees

- `run_shell_command` (`Shell`; `ForeignShell` on Windows).
- `read_file`, `list_directory` (`FsRead`); `write_file`, `replace` (`FsWrite`).
- `glob`, `grep_search` (`FsRead`, `ReadFiles`; `Unchecked` when no `dir_path`);
  `read_many_files` (`Unchecked`).
- `web_fetch` (`Fetch`), `google_web_search` (`WebSearch`).
- `read_mcp_resource` (`FsRead` for a `file:` URI; `UnknownTool`); MCP tools
  `mcp_<server>_<tool>` (`McpTool` as `mcp__<server>__<tool>` from `mcp_context`;
  `UnknownTool` without it).
- Any other tool (a custom or browser subagent's, a discovered tool): `UnknownTool`.
- Ungoverned: `write_todos`, `ask_user`, `tracker_*`, `update_topic`, plan-mode,
  `complete_task`, `activate_skill`, `get_internal_docs`, `list_mcp_resources`,
  `invoke_agent` and the built-in subagents.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

`"ask"` makes Gemini CLI confirm the call with the person even where its own policy would
not (YOLO and auto-edit included).

## Configuration and MCP files

- `GEMINI_CLI_HOME` replaces the home directory that holds `.gemini`; hooks in
  `.gemini/settings.json`.
- MCP servers: `mcpServers` in the user `settings.json` and a project's
  `.gemini/settings.json`; tools are named `mcp_<server>_<tool>`.
- Project settings: a trusted folder's `.gemini/settings.json` is merged over the user's;
  its `hooksConfig.disabled` lists are joined and its `BeforeTool` hooks run beside
  OpenMoat's and may rewrite a call's arguments. There is no local file.

## When the hook fails

Gemini CLI has no fail-closed setting. It runs the call when the hook times out, is killed
by a signal or exits 1; it blocks it when the hook exits 2, or exits with any other code
and prints something, as a missing `openmoat` does.

## Known gaps

No OS sandbox from OpenMoat; in a folder Gemini CLI does not trust it runs no settings
hooks at all and asks the person before every tool instead; a project's
`.gemini/settings.json` can turn hooks off or add a hook that rewrites a call's arguments
(`openmoat status` and `doctor` warn about one); extension hooks run beside OpenMoat's; a
hook that times out lets the call run.

## Sandbox

None: hook only.
