# Cursor (`cursor`)

Cursor, through five of its hooks. Every fact here comes from [`cursor.rs`](../cursor.rs)
and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Timeout |
|---|---|
| `beforeShellExecution` | 600 s |
| `beforeMCPExecution` | 600 s |
| `beforeReadFile` | 600 s |
| `preToolUse` | 600 s |
| `beforeTabFileRead` | 600 s |

Each entry sets `failClosed`. Output is `{"permission", "user_message", "agent_message"}`;
exit 2 also denies. An entry's `command` is one shell string Cursor's shell expands, so on
macOS and Linux the binary path is written in single quotes (`'/opt/My Tools/openmoat'
guard --host cursor`): a `$`, backtick or `\` in it is never run as shell. Windows keeps
double quotes, which a Windows path cannot hold.

## Tools OpenMoat sees

- `beforeShellExecution` (`Shell`), `beforeReadFile` (`FsRead`), `beforeMCPExecution`
  (`McpTool` `mcp__<server>__<tool>`).
- `beforeTabFileRead` (`FsRead`, recorded as `TabRead`): Tab, the inline completion, reads
  a file it sends to Cursor's model. Its output is `permission` alone, and a response that
  does not match that schema blocks the read, so OpenMoat answers only
  `{"permission":"allow"|"deny"}` ([`tab.rs`](tab.rs)): `allow` for `allow` and `defer`,
  `deny` for the rest. Tab has no question to ask, and holding every file outside the
  project would only stop completions there.
- `preToolUse`: `Read` (`FsRead`); `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete`
  (`FsWrite`); `Grep`, `Glob` and the listing and search tools that name a path
  (`FsRead`, `ReadFiles`); any other tool that names a path (`FsWrite`, `Patch`);
  `WebFetch` (`Fetch`); `WebSearch` (`WebSearch`); any other tool that names no path
  (`UnknownTool`).
- Ungoverned: `TodoWrite`, `TodoRead`, `todo_write`, and `preToolUse` `Shell`, `Task`,
  `MCP:<tool>` (the shell and MCP events decide those; a `Task` subagent's own calls are
  hooked). Cursor's hooks have no "no decision", so an ungoverned call is allowed.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Reviews

Only the shell and MCP events prompt on `"ask"`; on the others a review is sent as a deny
("Cursor does not prompt for this hook").

Cursor's hooks have no "no decision", so a call no rule decides (`defer`) is sent as
`"ask"` on the shell event. A command whose payload says `sandbox: true` is the exception
while OpenMoat's `sandbox.json` is installed and pinned: Cursor would run it in that
sandbox without asking, so the `defer` is sent as `"allow"`. A `review` or `deny` of such
a command is sent as before, and a command Cursor runs outside its sandbox
(`sandbox: false`) still gets `"ask"`.

## Working directory

The payload's `cwd` is where the command or tool runs, which the model chooses; the
session's directories are `workspace_roots`. A `cwd` inside a workspace root is decided as
before. One outside every root is decided from the first root, with the command run after
a `cd` to the `cwd` and relative paths taken from it, so a write from
`~/Library/LaunchAgents` is checked as that path, never as one inside the project.

## Configuration and MCP files

- Configuration directory: `CURSOR_CONFIG_DIR`, else `~/.cursor`; hooks in `hooks.json`.
- MCP servers: `mcp.json` beside the hook file and a project's `.cursor/mcp.json`; tools
  are named `mcp__<server>__<tool>`.
- Project settings: a project's `.cursor/hooks.json` runs its hooks beside the user's.

## When the hook fails

Cursor runs the call when the hook is missing, crashes or times out, unless the hook entry
sets `failClosed: true`; then it blocks the call. `openmoat status` and `openmoat doctor`
report an entry of OpenMoat's without it as "not protected", and `openmoat init` puts it
back.

## Claude Code's hooks in Cursor

Cursor loads `~/.claude/settings.json` and a project's `.claude/settings*.json` hooks by
default and runs them beside its own, ranking its own above them
(<https://cursor.com/docs/reference/third-party-hooks>). So OpenMoat's Claude Code hook
runs in Cursor too, fail-open. It reads such a payload as Cursor's `preToolUse`
([claude_code HOST.md](../claude_code/HOST.md#run-by-cursor)); the Cursor hooks here remain
Cursor's protection. With both set up, a call is recorded twice.

## Cloud agents and tools without a hook name

Cursor's cloud agents do not load `~/.cursor/hooks.json`, so OpenMoat checks none of
their calls; a project's `.cursor/hooks.json` runs there, but it is the repository's.
`beforeTabFileRead` and `beforeMCPExecution` do not run in cloud agents at all
(<https://cursor.com/docs/agent/hooks>, checked 2026-11-06).

The hook docs name no browser, web or memory tool among `preToolUse`'s tools (`Shell`,
`Read`, `Write`, `Grep`, `Delete`, `Task`, `MCP:<tool>`). A tool that reaches `preToolUse` is decided (an unnamed one as
`tool.unknown`, with every path and URL it names checked); whether the browser tools reach
it is not documented and not confirmed by a capture, so THREAT_MODEL §5 lists them as not
confirmed hooked.

## Known gaps

Injected input (ADR-057): OpenMoat installs none of Cursor's after-call hooks
(`afterShellExecution`, `afterMCPExecution`), so it never sees what a call returned. A host,
path or command untrusted output named is not linked to the later call that uses it; only
session taint applies.

Commands Cursor runs outside its sandbox (a rerun or call its Auto-review classifier
approves, Run Everything mode, the CLI without `--sandbox enabled`) are not confined;
file-tool reviews become denies; Task and tools that name no path are not hooked; a failed
hook blocks the call.

## Sandbox

OpenMoat writes Cursor's `sandbox.json`, which the lock pins whole (macOS and Linux).
Cursor's sandbox does not run on Windows; the hook still applies the policy there.
`sandbox.json` has no proxy setting, so sandboxed commands never reach `openmoat proxy`
and carry no session (ADR-044); `openmoat status` and `openmoat doctor` say so under
"proxy sessions".
