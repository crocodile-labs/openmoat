# OpenClaw (`openclaw`)

OpenClaw has no command hook. OpenMoat's plugin (`integrations/openclaw/openmoat.mjs` in
the CLI crate) handles OpenClaw's `before_tool_call` plugin hook and runs
`moat guard --host openclaw`. Every fact here comes from [`openclaw.rs`](../openclaw.rs)
and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Timeout |
|---|---|
| `before_tool_call` (through the plugin) | 60 s |

The plugin sends OpenClaw's `toolName`, `params`, `toolCallId`, `runId`, `toolKind`,
`sessionId`, `sessionKey` and `agentId`, and adds `cwd`, `configPath`, `stateDir` and
`platform`. It returns no decision for `allow`, `requireApproval` for `ask` and `block`
for `deny`; anything it cannot read blocks the call.

## Tools OpenMoat sees

- `exec` (`Shell`; `ForeignShell` on Windows); Code Mode `exec` and `process` input
  actions (`ForeignShell`, `unparseable`).
- `read` (`FsRead`, `ReadFiles`); `write`, `edit` (`FsWrite`, `Patch`); `apply_patch`
  (`Patch`); `view_image` (`FsRead`, `ReadFiles`, or `Fetch`).
- `web_fetch` (`Fetch`); `web_search`, `x_search` (`WebSearch`); `browser` (`Net`,
  `ReadFiles`, `UnknownTool`).
- `gateway`, `plugins`, `cron`, `nodes`: by action (`plugins` and `cron` writes are
  `FsWrite`, which `kernel-self` denies).
- MCP tools `<server>__<tool>` (`McpTool` as `mcp__<server>__<tool>`); any other tool
  (`message`, `sessions_*`, a plugin's tool): `UnknownTool`.
- Ungoverned: `ask_user`, `session_status`, `agents_list`, `agents_wait`, the goal tools,
  `progress_card`, `theme`, `screen`, `wait`, `tool_search`, `tool_describe`,
  `heartbeat_respond`, and the read-only actions of `process`, `gateway`, `plugins`,
  `cron`, `nodes`.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

OpenClaw puts an `ask` to the person itself (`requireApproval`) and blocks when no one can
answer.

## Configuration and MCP files

- State directory: `OPENCLAW_STATE_DIR`, else `~/.openclaw`; it holds `openclaw.json`
  unless `OPENCLAW_CONFIG_PATH` puts it elsewhere ([`location.rs`](location.rs)).
- OpenMoat's plugin, `openmoat/openmoat.mjs` in that directory, loaded from
  `plugins.load.paths`; the lock pins it with `openclaw.json`.
- MCP servers: `mcp.servers` in `openclaw.json`; no project file.
- No project settings are read.

## When the hook fails

OpenClaw blocks the call when OpenMoat's plugin throws or times out (`before_tool_call`
fails closed), and the plugin blocks when `openmoat` is missing, crashes or does not
answer; the call runs unchecked when the Gateway does not load the plugin.

## Known gaps

No OS sandbox from OpenMoat; a parameter rewrite by another plugin and OpenClaw's process
input are not checked; calls run unchecked if the Gateway does not load the plugin; a
failed or slow hook blocks the call.

## Sandbox

None: hook only.
