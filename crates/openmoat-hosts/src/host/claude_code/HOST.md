# Claude Code (`claude-code`)

Anthropic's Claude Code. Its `PreToolUse` format is also what the Continue CLI sends
([continue_cli](../continue_cli/HOST.md)). Every fact here comes from
[`claude_code.rs`](../claude_code.rs) and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout | Notes |
|---|---|---|---|
| `PreToolUse` | `Bash\|Monitor\|PowerShell\|Edit\|Write\|MultiEdit\|NotebookEdit\|Read\|Glob\|Grep\|LSP\|SendFile\|WebFetch\|WebSearch\|ReadMcpResourceTool\|EnterWorktree\|Skill\|Artifact\|ArtifactData\|mcp__.*` | 600 s | sets `onFailure: "block"` |
| `ConfigChange` | `user_settings\|project_settings\|local_settings` | 60 s | the settings-change veto |
| `SessionStart` | `startup\|resume\|clear\|compact` | 60 s | with `sandbox.proxy_port`, issues the session its `openmoat proxy` credential in `CLAUDE_ENV_FILE` (ADR-044); prints nothing, a failure exits 2 |

## Tools OpenMoat sees

- `Bash` (`Shell`), `Monitor` (`Shell` or `Net`), `PowerShell` (`ForeignShell`).
- `Read`, `LSP` (`FsRead`); `Glob`, `Grep` (`FsRead`, `ReadFiles`); `SendFile` (`ReadFiles`).
- `Edit`, `Write`, `MultiEdit`, `NotebookEdit` (`FsWrite`).
- `WebFetch` (`Fetch`), `WebSearch` (`WebSearch`).
- `Artifact`, `ArtifactData` (`ReadFiles`, `Patch`, `Fetch`; `FsRead`).
- `ReadMcpResourceTool` (`McpTool` `mcp__<server>__read_resource`), `mcp__<server>__<tool>` (`McpTool`).
- `EnterWorktree` with a `path` (`FsRead`).
- Ungoverned: `Task`, `Skill`, `EnterWorktree` without a `path`, and any other tool.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

Claude Code asks the person on `PreToolUse`, except in a permission mode that asks no one
(`bypassPermissions`, `dontAsk`). `claude --continue` resumes a session.

## Configuration and MCP files

- Configuration directory: `CLAUDE_CONFIG_DIR`, else `~/.claude`; hooks in `settings.json`
  (nested layout).
- MCP servers: `~/.claude.json` (beside the default directory) and a project's `.mcp.json`;
  tools are named `mcp__<server>__<tool>`.
- Project settings merged over the user's `settings.json`: `.claude/settings.json` and
  `.claude/settings.local.json`.

Credentials: the login Claude Code keeps in a file (`.credentials.json` in its
configuration directory on Linux and Windows, and on macOS when the Keychain refuses
it) and the Anthropic profiles in `~/.config/anthropic` are `agent-credentials`': the
agent's own tools may neither read nor write them, under `CLAUDE_CONFIG_DIR` too. The
macOS Keychain entry is read by `security find-generic-password -w`, which
`secrets-paths` denies. `claude setup-token`, which prints a new long-lived token, asks
(`agent-token`); `claude mcp add`, `add-json`, `login` and `claude plugin install` ask
(`runs-later`). `openmoat status` and `openmoat doctor` warn when the `claude` on the
search path is a version with a published advisory (`advisories.rs`).

## When the hook fails

Before 2.1.295 Claude Code runs the call when the hook is missing, cannot start, exits
non-zero other than 2, or times out (default 600 s); from 2.1.295 it blocks it
(`openmoat init` sets `onFailure: "block"`).

## Known gaps

File tools, WebFetch and MCP servers run outside the OS sandbox; before Claude Code 2.1.295
calls run unchecked if the hook binary is missing or crashes.

## Sandbox

OpenMoat writes Claude Code's `sandbox` block and permission rules into `settings.json`
(macOS, Linux, WSL2). Not on native Windows: the hook still applies the policy there (use
WSL2 for OS confinement).
