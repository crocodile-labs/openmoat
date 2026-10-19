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
| `configPath` | Added by the plugin: `OPENCLAW_CONFIG_PATH`, else `openclaw.json` in `OPENCLAW_STATE_DIR` or `~/.openclaw` (<https://docs.openclaw.ai/help/environment>). |
| `platform` | Added by the plugin: Node's `process.platform`; `exec` runs PowerShell on Windows. |

## Tool parameters (OpenClaw 2026.10.5)

- `exec`: `command`, `workdir`, `env` (<https://docs.openclaw.ai/tools/exec>).
- `process`: `action` (`list`, `poll`, `log`, `kill`, `clear`, `remove`, `send-keys`, `submit`, `paste`, …).
- `read`, `write`, `edit`: `path` (the package's tool schemas; its renderers also read `file_path`), `write` `content`, `edit` `edits`.
- `apply_patch`: `input`, the `*** Begin Patch` text (<https://docs.openclaw.ai/tools/apply-patch>).
- `web_fetch`: `url`. `web_search`: `query` (assumed, the same key as Claude Code's).
- `browser`: `action`; `url` or `targetUrl` for `open` and `navigate`; `paths` for `upload` (the package's browser tool schema).
- `gateway`: `action` (`config.get`, `config.schema.lookup`, `update.run`). `plugins`: `action` (`list`, `inspect`, `search`, `install`, `enable`, `disable`, `uninstall`, `reload`, `reloadAndResume`).
- MCP tools: `<server>__<tool>` (the package's `agent-bundle-mcp-names` module).

Replace these with captured payloads once OpenMoat's plugin has run under a real
OpenClaw Gateway (`cat` the stdin of `moat guard` from a scratch
`OPENCLAW_STATE_DIR`).
