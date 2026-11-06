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
| `PostToolUse` | `Bash\|WebFetch\|WebSearch\|ReadMcpResourceTool\|mcp__.*` | 60 s | what the call returned (`tool_response`): when it is untrusted output, keeps keyed fingerprints of its hosts, paths and code-span commands for `injected-input` (ADR-057); prints nothing, writes no audit row, a failure exits 2, which Claude Code shows the model; new after 0.15.0, so an older install reports "run `openmoat init`" |

## Tools OpenMoat sees

- `Bash` (`Shell`), `Monitor` (`Shell` or `Net`), `PowerShell` (`ForeignShell`).
- `Read`, `LSP` (`FsRead`); `Glob`, `Grep` (`FsRead`, `ReadFiles`); `SendFile` (`ReadFiles`).
- `Edit`, `Write`, `MultiEdit`, `NotebookEdit` (`FsWrite`).
- `WebFetch` (`Fetch`), `WebSearch` (`WebSearch`).
- `Artifact`, `ArtifactData` (`ReadFiles`, `Patch`, `Fetch`; `FsRead`).
- `ReadMcpResourceTool` (`McpTool` `mcp__<server>__read_resource`), `mcp__<server>__<tool>` (`McpTool`).
- The editor tools of VS Code and JetBrains ([`ide_tools.rs`](ide_tools.rs)):
  `mcp__ide__getDiagnostics` and `mcp__claude-vscode__getDiagnostics` (`McpTool` reading the
  file its `uri` names, else the working directory), `mcp__ide__executeCode` (`Unchecked`
  `McpTool`: at least `review`).
- `EnterWorktree` with a `path` (`FsRead`).
- Ungoverned: `Task`, `Skill`, `EnterWorktree` without a `path`, and any other tool.
- A payload Cursor sends to this hook (it carries `cursor_version`) is read as Cursor's
  `preToolUse` ([`from_cursor.rs`](from_cursor.rs), below).

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Reviews

OpenMoat's `review` is sent as Claude Code's `"ask"`, which Claude Code puts to the person on
`PreToolUse`, except in a permission mode that prompts no one (`bypassPermissions`, `dontAsk`). `claude --continue` resumes a session.

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
agent's own tools may neither read nor write them, under `CLAUDE_CONFIG_DIR` too, and
Claude Code's sandbox denies them (and every other agent's login) to the commands it
runs, while Claude Code itself signs in outside it (ADR-054). The
macOS Keychain entry is read by `security find-generic-password -w`, which
`secrets-paths` denies. `claude setup-token`, which prints a new long-lived token, needs review
(`agent-token`); `claude mcp add`, `add-json`, `login` and `claude plugin install` need review
(`runs-later`). `openmoat status` and `openmoat doctor` warn when the `claude` on the
search path is a version with a published advisory (`advisories.rs`).

## When the hook fails

Before 2.1.295 Claude Code runs the call when the hook is missing, cannot start, exits
non-zero other than 2, or times out (default 600 s); from 2.1.295 it blocks it
(`openmoat init` sets `onFailure: "block"`). On Windows without Git for Windows or Git
Bash, before 2.1.310 a hook's block, its exit 2 included, can still let the call through
(changelog 2.1.299, 2.1.309, 2.1.310); `openmoat status` and `openmoat doctor` warn about
such a version as an advisory.

`openmoat init` writes `onFailure` only when every Claude Code it finds reads it (2.1.295
or later), since a key an older version rejects can stop every hook in the file: the
`claude` on the search path and each copy an editor extension bundles. The VS Code
extension bundles its own Claude Code and puts no `claude` on the search path; OpenMoat
reads its version, which is the extension's, from `extensions.json` in the extensions
folder of VS Code, VS Code Insiders, VS Code Server, Cursor, Windsurf and VSCodium
(`BUNDLED` in [`claude_code.rs`](../claude_code.rs)), without running it. `status` and
`doctor` name each copy, and warn about one older than 2.1.295. A person who runs Claude
Code only from the desktop app, with no `claude` on the search path and no extension,
gets entries without the key, so a hook that fails runs the call; `doctor` warns about
that ("runs a tool call when its hook fails to start, crashes or times out"). Once
written, the key stays on a later `init`.

## In VS Code and JetBrains

The same hook protects Claude Code in the VS Code extension and the JetBrains plugin:
both read `~/.claude/settings.json` ([IDE.md](../../../../../docs/IDE.md) has the steps).

- **JetBrains** bundles no Claude Code: the plugin runs the `claude` on the search path,
  or the command its settings name, which OpenMoat does not read. Name the same `claude`
  in both, or `init` cannot see its version.
- **Editor tools**: `getDiagnostics` returns errors and warnings that quote the file's
  lines, so a secret's are denied as a `Read` of it is; `executeCode` runs Python in the
  VS Code notebook's kernel and needs review, before the editor's own Execute or Cancel
  question. The argument names (`uri`, `code`) are the tools' schema as Claude Code shows
  it to the model; the docs do not list them.
- **The editors' own files**: `.vscode/`, `.idea/`, `*.code-workspace` and `*.run.xml`
  are `runs-later`, so an agent's write there needs review (ADR-060).
- **Not covered**: the editor selection and open-file context Claude Code adds to each
  prompt is no tool call, so no hook sees it (Claude Code's own `Read` deny rules keep a
  file's selection out); `claudeCode.claudeProcessWrapper` runs another program as
  Claude Code.

A project's `.claude/settings.json` can set `disableAllHooks`, which turns OpenMoat's
user-level hook off for that project; `openmoat status` and `openmoat doctor` report it
([`project_settings.rs`](project_settings.rs)) whichever front end runs the session.
Hooks in managed settings are the one tier a project cannot turn off; put OpenMoat's
entries there for a machine a repository must not be able to unhook.

## Run by Cursor

Cursor loads Claude Code's hooks by default ("Include Third-Party Plugins, Skills, and
Other Configs"), maps `PreToolUse` to `preToolUse`, runs every matching hook and lets its
own hooks win a conflict; it fails open on any exit but 0 and 2 for them and does not read
`onFailure` (<https://cursor.com/docs/reference/third-party-hooks>). A payload with
`cursor_version` is read as Cursor's `preToolUse`, its `Shell` as the command, and
answered as a call that cannot prompt: a `review` is a deny, a `defer` no answer. A Cursor
`sessionStart` decides nothing. This hook is not Cursor's protection: the Cursor hooks
`openmoat init` installs are. With both set up, a call is recorded twice, once by each.

## Known gaps

File tools, WebFetch and MCP servers run outside the OS sandbox; before Claude Code 2.1.295
calls run unchecked if the hook binary is missing or crashes.

Injected input (ADR-057) reads only the tools of the `PostToolUse` matcher: the output of
`PowerShell`, `Monitor`, `Read` and every ungoverned tool is not looked at. A tool response
larger than the guard's payload limit is not read; the hook reports the error and keeps
nothing for that call.

## Sandbox

OpenMoat writes Claude Code's `sandbox` block and permission rules into `settings.json`
(macOS, Linux, WSL2). Not on native Windows: the hook still applies the policy there (use
WSL2 for OS confinement).

With `sandbox.proxy_port`, each session's sandboxed commands send `openmoat proxy` the
credential the `SessionStart` hook issued (ADR-044), so the proxy records them under that
session and applies its taint and connection share; `openmoat status` and `openmoat
doctor` report this under "proxy sessions".
