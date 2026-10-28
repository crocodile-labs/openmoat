# OpenClaw (`openclaw`)

OpenClaw has no command hook. OpenMoat's plugin ([`integration/openmoat.mjs`](integration/openmoat.mjs))
handles OpenClaw's `before_tool_call` plugin hook and runs
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

### Order among plugins

OpenClaw runs the `before_tool_call` handlers one after another, highest `priority`
first (any number; equal ones in the order they registered). Each handler gets its own
copy of the call as it came, never another handler's change, and the `params` of the
last handler that returns some are what runs, laid key by key over the call's own; a
`block` is final and stops the run, and once a handler asks for approval its
parameters are kept whatever later handlers return (`runBeforeToolCall` in
`src/plugins/hooks.ts`, the caller in `src/agents/agent-tools.before-tool-call.policy.ts`,
read at openclaw/openclaw `bd6a4e4`). So the plugin registers two handlers
([ADR-041](../../../../../docs/adr/ADR-041-openclaw-decides-first-and-last.md)):

- at the highest priority (`Number.MAX_SAFE_INTEGER`) it runs `moat guard` on the call
  as it came; a deny blocks before any other plugin runs, and after its ask no later
  plugin can change what the person approves;
- at the lowest (`Number.MIN_SAFE_INTEGER`) it returns the parameters it decided on,
  so a change another plugin returned in between is undone and the call that runs is
  the one OpenMoat checked. A change another plugin meant (a rewritten path, an added
  flag) is undone too: OpenMoat decides only on what it has seen.

When OpenClaw loads the plugin to run (`registrationMode` `full`, not for listing the
CLI's commands), it runs `moat guard --heartbeat --host openclaw`
([ADR-042](../../../../../docs/adr/ADR-042-plugins-report-loading.md)).

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
- MCP servers: `mcp.servers` in `openclaw.json`; no project file. The lock pins
  `openclaw.json` without them (its `pinned_form`, recorded per file as `pinned_forms`)
  and each server by itself.
- No project settings are read.

Credentials: the model sign-in databases (`agents/<id>/agent/openclaw-agent.sqlite`,
`state/openclaw.sqlite`, which also holds the MCP OAuth sessions), `credentials/`,
`secrets.json`, the older `auth-profiles.json`, `auth-state.json`, a per-agent
`auth.json`, `codex-home/` and `mcp-oauth/` in the state directory are
`agent-credentials`': the agent's own tools may neither read nor write them, under
`OPENCLAW_STATE_DIR` too. `openclaw mcp add`, `set`, `configure` and `login` ask
(`runs-later`). `openmoat status` and `openmoat doctor` warn when the `openclaw` on the
search path is a version with a published advisory (`advisories.rs`).

## When the hook fails

OpenClaw blocks the call when OpenMoat's plugin throws or times out (`before_tool_call`
fails closed), and the plugin blocks when `openmoat` is missing, crashes or does not
answer; the call runs unchecked when the Gateway does not load the plugin (a plugin
OpenClaw must load or refuse to run is tracked upstream in
[openclaw/openclaw#147129](https://github.com/openclaw/openclaw/issues/147129)).

A plugin that fails to load at Gateway start is recorded with `status: "error"` and the
Gateway keeps running (`src/plugins/loader-records.ts`; only a reload throws,
`throwOnLoadError` in `src/gateway/server-plugins.ts`); with no `before_tool_call`
handler left, OpenClaw runs every call (`policy.ts`, "no hooks"). `openmoat status` and
`openmoat doctor` therefore say whether the plugin has reported loading since OpenMoat
wrote it or the `openclaw` on the search path changed: "plugin loaded" with the time of
its last report or of a call the guard decided, or "plugin not loaded yet", a note, while
the Gateway has not been restarted. OpenClaw keeps its sessions in a database that
sign-in commands write too, so OpenMoat cannot tell a Gateway that ran without the plugin
from one that has not run: the note stays a note. `openclaw plugins inspect openmoat
--runtime` shows OpenClaw's own error.

## Known gaps

No OS sandbox from OpenMoat; a parameter change by another plugin is undone, except by a
plugin that also asks for approval (OpenClaw keeps the parameters of the first approval
request, so a person approving that plugin's request runs its change, unchecked) or one
that registers at the same lowest priority after OpenMoat, or at a lower one
(`-Infinity`), and so runs last; OpenClaw's
process input is not checked; calls run unchecked if the Gateway does not load the
plugin (`openmoat status` says when it has not reported loading); a failed or slow hook
blocks the call.

## Sandbox

None: hook only.
