# OpenClaw hook payloads

None of these fixtures is captured from a running OpenClaw. Each is built from
OpenClaw's documented `before_tool_call` event and context and from the tool
schemas in the OpenClaw 2026.10.5 npm package, so a guess is never mistaken for
a capture.

OpenClaw has no command hook. OpenMoat's plugin
(`crates/openmoat-cli/integrations/openclaw/openmoat.mjs`) builds the JSON that
`moat guard --host openclaw` reads, so the envelope is OpenMoat's own:

| Field | Source |
|---|---|
| `hook_event_name` | Always `before_tool_call`, set by the plugin. |
| `toolName`, `params`, `toolCallId`, `runId`, `toolKind` | The hook's `event` (<https://docs.openclaw.ai/plugins/hooks/tool-policy>, `PluginHookBeforeToolCallEvent` in the package's `dist/*.d.ts`). |
| `sessionId`, `sessionKey`, `agentId` | The hook's `ctx` (`PluginHookToolContext`). |
| `cwd` | Added by the plugin: the agent's workspace from `api.runtime.agent.resolveAgentWorkspaceDir`, where OpenClaw's file tools resolve relative paths. The context has no working directory. |
| `configPath` | Added by the plugin: `OPENCLAW_CONFIG_PATH`, else `openclaw.json` in the state directory (<https://docs.openclaw.ai/help/environment>). |
| `stateDir` | Added by the plugin: `OPENCLAW_STATE_DIR`, else `.openclaw` in `OPENCLAW_HOME` or the home directory. Fixtures without it are from a plugin that predates it. |
| `platform` | Added by the plugin: Node's `process.platform`; `exec` runs PowerShell on Windows. |

## Tool parameters (OpenClaw 2026.10.5)

- `exec`: `command`, `workdir`, `env` (<https://docs.openclaw.ai/tools/exec>).
- `process`: `action` (`list`, `poll`, `log`, `kill`, `clear`, `remove`, `send-keys`, `submit`, `paste`, …).
- `read`, `write`, `edit`: `path` (the package's tool schemas; its renderers also read `file_path`), `write` `content`, `edit` `edits`.
- `apply_patch`: `input`, the `*** Begin Patch` text (<https://docs.openclaw.ai/tools/apply-patch>).
- `web_fetch`: `url`. `web_search`: `query` (assumed, the same key as Claude Code's).
- `browser`: `action`; `url` or `targetUrl` for `open` and `navigate`; `paths` for `upload` (the package's browser tool schema).
- `gateway`: `action` (`config.get`, `config.schema.lookup`, `update.run`). `plugins`: `action` (`list`, `inspect`, `search`, `install`, `enable`, `disable`, `uninstall`, `reload`, `reloadAndResume`).
- MCP tools: `<server>__<tool>` (the package's `agent-bundle-mcp-names` module; <https://docs.openclaw.ai/plugins/bundles>, "Tool naming").
- `cron`: `action` (`status`, `list`, `get`, `add`, `update`, `remove`, `run`, `runs`, `next_check`, `wake`), `job` for `add` (<https://github.com/openclaw/openclaw/blob/main/src/agents/tools/cron-tool.ts>; the `job` shape in `cron-add.json` is assumed).
- `nodes`: `action` (`status`, `describe`, `pending`, `approve`, `reject`, `notify`, `camera_*`, `photos_latest`, `screen_*`, `location_get`, `notifications_*`, `device_*`, `which`, `invoke`), `node`, `invokeCommand`, `invokeParamsJson`, `outPath` (<https://github.com/openclaw/openclaw/blob/main/src/agents/tools/nodes-tool.ts>).
- `view_image`: `path` or `paths` (a local image or a permitted URL), `maxImages` (<https://docs.openclaw.ai/tools>).

Replace these with captured payloads once OpenMoat's plugin has run under a real
OpenClaw Gateway (`cat` the stdin of `moat guard` from a scratch
`OPENCLAW_STATE_DIR`).
