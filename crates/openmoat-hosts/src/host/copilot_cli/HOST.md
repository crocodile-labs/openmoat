# GitHub Copilot CLI (`copilot-cli`)

GitHub Copilot CLI (`copilot`, npm `@github/copilot`), through its `preToolUse` command
hook in the camelCase format, checked against `@github/copilot` 1.0.101. Every fact here
comes from [`copilot_cli.rs`](../copilot_cli.rs) and [`doc.rs`](doc.rs); if they disagree,
the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout |
|---|---|---|
| `preToolUse` | none: every tool (the payload does not mark MCP tools) | 600 s (`timeoutSec`) |

Input is `sessionId`, `timestamp`, `cwd`, `toolName` and `toolArgs` (a JSON string).
Empty output leaves the call to Copilot's own permission flow (`defer`).

## Tools OpenMoat sees

- `bash`, `local_shell` (`Shell`); `write_bash` (`Unchecked`); `powershell`
  (`ForeignShell`); `write_powershell` (`Unchecked`).
- `view` (`FsRead`); `create`, `edit`, `str_replace` (`FsWrite`); `str_replace_editor`
  (`FsRead` or `FsWrite`); `apply_patch` (`Patch`).
- `grep`, `rg`, `glob` (`FsRead`, `ReadFiles`); `web_fetch` (`Fetch`); `web_search`
  (`WebSearch`).
- Any other tool, MCP tools included (`<server>-<tool>`): `McpTool`.
- Ungoverned: `ask_user`, `report_intent`, `task`, `think`, `update_todo`,
  `read_bash`/`stop_bash`/`list_bash` and their PowerShell forms.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

`ask` prompts in an interactive session; autopilot and the cloud agent turn it into a deny.

## Configuration and MCP files

- Configuration directory: `COPILOT_HOME`, else `~/.copilot`. Copilot loads every `*.json`
  in its `hooks/`, so OpenMoat's entry is a file of its own, `hooks/openmoat.json`.
- MCP servers: `mcp-config.json` in the configuration directory, and a project's `.mcp.json`
  and `.github/mcp.json` (servers may be listed bare); tools are named `<server>-<tool>`.
- Project settings: `.github/copilot/settings.json` and `settings.local.json`, merged over
  the user's `settings.json`; `disableAllHooks: true` in either turns the hook off. A
  repository's `.github/hooks/*.json` load once the folder is trusted.

## When the hook fails

Copilot blocks the call when the hook cannot start, crashes or exits non-zero; it runs it
when the hook times out (`timeoutSec`, 600 s as `openmoat init` writes it) or its file is
gone.

## Known gaps

A hook that times out lets the call run; `disableAllHooks` in Copilot's user or a
repository's `settings.json` turns the hook off (`openmoat status` and `doctor` report it);
MCP tools are told apart from built-in ones only by name, so a changed server is traced by
its `<server>-` prefix; asks become denies in autopilot; no OS sandbox is configured.

## Sandbox

None: hook only.
