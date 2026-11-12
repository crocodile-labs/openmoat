# GitHub Copilot CLI (`copilot-cli`)

GitHub Copilot CLI (`copilot`, npm `@github/copilot`), through its `preToolUse` command
hook in the camelCase format (and `postToolUse` for what a call returned), checked against `@github/copilot` 1.0.101. Every fact here
comes from [`copilot_cli.rs`](../copilot_cli.rs) and [`doc.rs`](doc.rs); if they disagree,
the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout |
|---|---|---|
| `preToolUse` | none: every tool (the payload does not mark MCP tools) | 600 s (`timeoutSec`) |
| `postToolUse` | none: every tool, for the same reason | 60 s (`timeoutSec`) |

Input is `sessionId`, `timestamp`, `cwd`, `toolName` and `toolArgs` (a JSON string).
Empty output leaves the call to Copilot's own permission flow (`defer`).

`postToolUse` adds `toolCallId` and `toolResult` (`resultType`, `textResultForLlm`: what
the model gets), with `toolArgs` as an object: the weekly latest-agents run 42853181916
(2026-11-10) recorded these fields from a real Copilot CLI, and the
[CLI hooks reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference)
lists `toolResult` for `postToolUse` only. Neither payload names its event, so a
`toolResult` is what makes it an after-call report; a `toolResult` without its text is an
error (exit 2), and a payload without one is decided as a call. Copilot waits for the
hook before its next model request (the same run). OpenMoat answers it with nothing; a
non-zero exit or a timeout is logged and the run goes on. It fires only after a call that
succeeded: `postToolUseFailure`, for a failed one, is not installed.

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

## Reviews

A `review`, sent as `"ask"`, prompts in an interactive session; autopilot and the cloud agent turn it into a deny.

## Configuration and MCP files

- Configuration directory: `COPILOT_HOME`, else `~/.copilot`. Copilot loads every `*.json`
  in its `hooks/`, so OpenMoat's entry is a file of its own, `hooks/openmoat.json`.
- MCP servers: `mcp-config.json` in the configuration directory, and a project's `.mcp.json`
  and `.github/mcp.json` (servers may be listed bare); tools are named `<server>-<tool>`.
- Project settings: `.github/copilot/settings.json` and `settings.local.json`, merged over
  the user's `settings.json`; `disableAllHooks: true` in either turns the hook off. A
  repository's `.github/hooks/*.json` load once the folder is trusted.

Credentials: `config.json` (where the login goes when there is no keychain),
`mcp-oauth-config/` and `mcp-secrets/` in `COPILOT_HOME` are `agent-credentials`': the
agent's own tools may not read them (`kernel-self` already denies writing
`config.json`). The keychain entry `copilot-cli` is read by `security
find-generic-password -w` or `secret-tool lookup`, which `secrets-paths` denies.
`copilot mcp add` and `copilot mcp enable` need review (`runs-later`). `openmoat status` and
`openmoat doctor` warn when the `copilot` on the search path is a version with a
published advisory (`advisories.rs`).

## When the hook fails

Copilot blocks the call when the hook cannot start, crashes or exits non-zero; it runs it
when the hook times out (`timeoutSec`, 600 s as `openmoat init` writes it) or its file is
gone.

## Known gaps

Injected input (ADR-057, ADR-063): OpenMoat's `postToolUse` entry reads what a call
returned, so a host, path or command untrusted output named makes a later call that uses
it need review (`injected-input`). The output of a call that failed (`postToolUseFailure`)
is not read, and an install from before the entry links nothing until `openmoat init`
runs once; only session taint applies there.

A hook that times out lets the call run; `disableAllHooks` in Copilot's user or a
repository's `settings.json` turns the hook off (`openmoat status` and `doctor` report it);
MCP tools are told apart from built-in ones only by name, so a changed server is traced by
its `<server>-` prefix; reviews become denies in autopilot; no OS sandbox is configured.

## Sandbox

None: hook only. `openmoat status` names the command that gives it one:
`openmoat run --write ~/.copilot --write ~/Library/Caches/copilot -- copilot`
(`~/.cache/copilot` on Linux); its login must then be a key, not the keychain (ADR-076).
