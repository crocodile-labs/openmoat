# Cursor (`cursor`)

Cursor, through four of its hooks. Every fact here comes from [`cursor.rs`](../cursor.rs)
and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Timeout |
|---|---|
| `beforeShellExecution` | 600 s |
| `beforeMCPExecution` | 600 s |
| `beforeReadFile` | 600 s |
| `preToolUse` | 600 s |

Each entry sets `failClosed`. Output is `{"permission", "user_message", "agent_message"}`;
exit 2 also denies.

## Tools OpenMoat sees

- `beforeShellExecution` (`Shell`), `beforeReadFile` (`FsRead`), `beforeMCPExecution`
  (`McpTool` `mcp__<server>__<tool>`).
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

## Known gaps

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
