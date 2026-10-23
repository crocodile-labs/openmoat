# pi hook payloads

None of these fixtures is captured from pi as a person runs it. Each is built from
pi's documented `tool_call` extension event and from the tool schemas in the
`@earendil-works/pi-coding-agent` 1.3.0 npm package (`dist/core/extensions/types.d.ts`,
`dist/core/tools/*.d.ts`), so a guess is never mistaken for a capture. The envelope
was checked against what the extension sent from a pi 1.3.0 SDK session
(`createAgentSession` with pi-ai's faux model provider, so no model was called): the
same fields, a UUID `sessionId`, and `hasUI: false`, since the SDK has no screen.

pi has no command hook. OpenMoat's extension
(`crates/openmoat-hosts/src/host/pi/integration/openmoat.js`) builds the JSON that
`moat guard --host pi` reads, so the envelope is OpenMoat's own:

| Field | Source |
|---|---|
| `hook_event_name` | Always `tool_call`, set by the extension. |
| `toolName`, `input`, `toolCallId`, `parentToolCallId` | The event (`ToolCallEvent` in `types.d.ts`). `parentToolCallId` is set when another tool, such as `codemode`, made the call; its id is then `<parent id>/<n>`. |
| `sessionId` | Added by the extension: `ctx.sessionManager.getSessionId()`. |
| `cwd` | Added by the extension: `ctx.cwd`, where pi's tools resolve relative paths. |
| `hasUI` | Added by the extension: `ctx.hasUI`, true in the terminal UI and RPC mode, false in print and JSON mode. |
| `platform` | Added by the extension: Node's `process.platform`. |

## Tool inputs (pi 1.3.0)

- `bash`, `powershell`: `command`, `timeout`.
- `read`: `path`, `offset`, `limit`. `write`: `path`, `content`. `edit`: `path`, `edits` (`oldText`, `newText`).
- `grep`: `pattern`, `path`, `glob`, `ignoreCase`, `literal`, `context`, `limit`.
- `find`: `pattern`, `path`, `limit`. `ls`: `path`, `limit`.
- MCP tools: `mcp__<server>__<tool>` (`docs/mcp.md`); `read_mcp_resource`: `server`, `uri`.
- A path may start with `@`, which pi drops, and `~`, which pi expands (`dist/utils/paths.js`).

Replace these with captured payloads once OpenMoat's extension has run under a
real pi in its terminal UI (`cat` the stdin of `openmoat guard` from a scratch
`PI_CODING_AGENT_DIR`).
