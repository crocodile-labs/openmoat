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

## Asks

Only the shell and MCP events prompt on `ask`; on the others an ask is sent as a deny
("Cursor does not prompt for this hook").

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
file-tool asks become denies; Task and tools that name no path are not hooked; a failed
hook blocks the call.

## Sandbox

OpenMoat writes Cursor's `sandbox.json`, which the lock pins whole (macOS and Linux).
Cursor's sandbox does not run on Windows; the hook still applies the policy there.
