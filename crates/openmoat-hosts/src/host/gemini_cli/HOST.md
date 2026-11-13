# Gemini CLI (`gemini-cli`)

Gemini CLI (`gemini`, npm `@google/gemini-cli`), through its `BeforeTool` command hook
(and `AfterTool` for what a call returned), checked against the source of 0.65.0. Since 2026-06-18 Gemini CLI signs individual
accounts in only with an API key or Vertex AI; Google's own sign-in for them moved to the
Antigravity CLI ([its own host](../antigravity_cli/HOST.md)). Every fact here comes from
[`gemini_cli.rs`](../gemini_cli.rs) and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout |
|---|---|---|
| `BeforeTool` | `*` | 600 s |
| `AfterTool` | `run_shell_command\|web_fetch\|google_web_search\|mcp_.*` | 60 s |

Input is `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`,
`tool_name`, `tool_input` and, for an MCP tool, `mcp_context`. `{"decision": "deny"}` or
exit 2 blocks; no output, or `"allow"`, leaves the call to Gemini CLI's own policy.

`AfterTool` adds `tool_response` (`llmContent`, `returnDisplay` and, for a failed tool,
`error`), what the call returned: the weekly latest-agents run 42853181916 (2026-11-10)
recorded `llmContent` and `returnDisplay` as strings for a shell call from a real Gemini
CLI, and the [hooks reference](https://geminicli.com/docs/hooks/reference/) names all
three. The reference says its answer can hide or add to the result; whether Gemini CLI
waits for the hook was not observed in that run. OpenMoat answers it with nothing; only a failure of
`openmoat guard` (a broken lock, an audit log it cannot write) exits 2, and then Gemini
CLI gives the model OpenMoat's reason in place of the call's output. The call itself is
not undone.

## Tools OpenMoat sees

- `run_shell_command` (`Shell`; `ForeignShell` on Windows).
- `read_file`, `list_directory` (`FsRead`); `write_file`, `replace` (`FsWrite`).
- `glob`, `grep_search` (`FsRead`, `ReadFiles`) and `read_many_files` (`ReadFiles`).
  Without a `dir_path` Gemini CLI searches every workspace directory: the working
  directory and those `context.includeDirectories` adds in the user's
  `settings.json` and the project's `.gemini/settings.json`, which `openmoat guard`
  reads and checks as read too. A settings file it cannot parse leaves the search
  needing review (`Unchecked`). Directories added with `--include-directories` or
  `/directory add` are not in any file and are not checked.
- `web_fetch` (`Fetch`), `google_web_search` (`WebSearch`).
- `read_mcp_resource` (`FsRead` for a `file:` URI; `UnknownTool`); MCP tools
  `mcp_<server>_<tool>` (`McpTool` as `mcp__<server>__<tool>` from `mcp_context`;
  `UnknownTool` without it).
- Any other tool (a custom or browser subagent's, a discovered tool): `UnknownTool`.
- Ungoverned: `write_todos`, `ask_user`, `tracker_*`, `update_topic`, plan-mode,
  `complete_task`, `activate_skill`, `get_internal_docs`, `list_mcp_resources`,
  `invoke_agent` and the built-in subagents.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Reviews

A `review`, sent as `"ask"`, makes Gemini CLI confirm the call with the person even where its own policy would
not (YOLO and auto-edit included).

## Configuration and MCP files

- `GEMINI_CLI_HOME` replaces the home directory that holds `.gemini`; hooks in
  `.gemini/settings.json`.
- MCP servers: `mcpServers` in the user `settings.json` and a project's
  `.gemini/settings.json`; tools are named `mcp_<server>_<tool>`.
- Project settings: a trusted folder's `.gemini/settings.json` is merged over the user's;
  its `hooksConfig.disabled` lists are joined and its `BeforeTool` hooks run beside
  OpenMoat's and may rewrite a call's arguments. There is no local file.

Credentials: `oauth_creds.json` (the Google sign-in), `mcp-oauth-tokens.json`,
`a2a-oauth-tokens.json` (also in `~/.cache/.gemini`, where they go under the macOS
Seatbelt sandbox) and `gemini-credentials.json` (the keychain's fallback file, whose key
the agent could derive) are `agent-credentials`': the agent's own tools may neither
read nor write them, under `GEMINI_CLI_HOME` too; its `.env` is `secrets-paths`'. The
keychain entries (`gemini-cli-oauth`, `gemini-cli-api-key`) are read by `security
find-generic-password -w` or `secret-tool lookup`, which `secrets-paths` denies.
`gemini mcp add`, `gemini mcp enable` and `gemini extensions install`/`link` need review
(`runs-later`). `openmoat status` and `openmoat doctor` warn when the `gemini` on the
search path is a version with a published advisory (`advisories.rs`).

## When the hook fails

Gemini CLI has no fail-closed setting. It runs the call when the hook times out, is killed
by a signal or exits 1; it blocks it when the hook exits 2, or exits with any other code
and prints something, as a missing `openmoat` does.

## Known gaps

Injected input (ADR-057, ADR-063): OpenMoat's `AfterTool` entry reads what a shell
command, a fetch, a search or an MCP tool returned, so a host, path or command untrusted
output named makes a later call that uses it need review (`injected-input`). A folder
Gemini CLI does not trust runs neither entry, and an install from before the entry links
nothing until `openmoat init` runs once; only session taint applies there. On Windows
Gemini CLI runs shell commands in PowerShell, which OpenMoat does not parse
(`ForeignShell`), so a later shell command there is not linked to what a call returned.

No OS sandbox from OpenMoat; in a folder Gemini CLI does not trust it runs no settings
hooks at all and asks the person before every tool instead; a project's
`.gemini/settings.json` can turn hooks off or add a hook that rewrites a call's arguments
(`openmoat status` and `doctor` warn about one); extension hooks run beside OpenMoat's; a
search without a `dir_path` is checked over the working directory and the
`context.includeDirectories` of the user and project settings, not over directories added
with `--include-directories` or `/directory add`; a hook that times out lets the call run.

## Sandbox

None: hook only. `openmoat status` names the command that gives it one:
`openmoat run --write ~/.gemini -- gemini`; its login must then be an API key, not the
keychain (ADR-076).
