# pi (`pi`)

pi, the coding agent, through its `tool_call` extension event, checked against pi 1.3.0.
pi has no command hook: OpenMoat's extension ([`integration/openmoat.js`](integration/openmoat.js))
runs `moat guard --host pi`. Every fact here comes from [`pi.rs`](../pi.rs) and
[`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Timeout |
|---|---|
| `tool_call` (through the extension) | 45 s |

The extension sends pi's `toolName`, `input`, `toolCallId` and `parentToolCallId`, and
adds `sessionId`, `cwd`, `hasUI` and `platform`. It returns nothing for `allow`, asks with
`ctx.ui.confirm` for `ask` and blocks for `deny`; anything it cannot read blocks the call.

## Tools OpenMoat sees

- `bash` (`Shell`), `powershell` (`ForeignShell`).
- `read` (`FsRead`); `write`, `edit` (`FsWrite`); `grep`, `ls` (`FsRead`); `find`
  (`FsRead`, `ReadFiles`).
- `mcp__<server>__<tool>` and `read_mcp_resource` (`McpTool`).
- Any other tool (an extension's): `UnknownTool`.
- Ungoverned: `codemode`, `tool_search`, `list_mcp_resources`,
  `list_mcp_resource_templates`.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

pi asks through the extension's dialog where it has a screen (`ctx.hasUI`: the terminal UI
and RPC mode); print and JSON modes have none. pi has no approval step of its own, so a
call OpenMoat defers runs.

## Configuration and MCP files

- Agent directory: `PI_CODING_AGENT_DIR`, else `~/.pi/agent`. The hook file is OpenMoat's
  extension itself, `extensions/openmoat.js`; pi loads every `.js` and `.ts` there on
  start.
- MCP servers: `mcp.json` in the agent directory and a trusted project's `.pi/mcp.json`;
  tools are named `mcp__<server>__<tool>` with every character but letters, digits and `_`
  as `_`.
- Project settings: a trusted project's `.pi/settings.json` can turn the user's extensions
  off and add packages, and its `.pi/extensions/` (`.js`, `.ts`) load with the agent's
  rights; the user's `settings.json` can turn OpenMoat's extension off.

Credentials: `auth.json` (provider keys and OAuth tokens), `models.json` (which may
hold API keys) and `mcp-auth.json` (MCP sign-ins) in `PI_CODING_AGENT_DIR` are
`agent-credentials`': the agent's own tools may neither read nor write them, and `pi
auth print-api-key` and `pi auth print-bearer-token`, which print a stored key, are
denied. `pi mcp add` and `pi mcp login` ask (`runs-later`). `openmoat status` and
`openmoat doctor` warn when the `pi` on the search path is a version with a published
advisory (`advisories.rs`), such as the `auth.json` write race before 0.78.1.

## When the hook fails

pi blocks the call when OpenMoat's extension throws (`tool_call` fails closed), and the
extension blocks when `openmoat` is missing, crashes or does not answer within 45 s; the
call runs unchecked when pi does not load the extension (`--no-extensions`, or an
`extensions` entry in pi's or a trusted project's settings that turns it off).

## Known gaps

No OS sandbox from OpenMoat; a call OpenMoat defers runs; an input change by an extension
pi loads after OpenMoat's (a package's) and an extension that replaces a built-in tool are
not checked; a trusted project's `.pi` settings and extensions load with the agent's
rights; calls run unchecked if pi does not load the extension (`openmoat status` and
`doctor` report a settings entry that turns it off, not `--no-extensions`); a failed or
slow hook blocks the call.

## Sandbox

None: hook only.
