# OpenCode hook payloads

OpenCode 1's are the files without a prefix; OpenCode 2's start with `v2-` (below).

None of these fixtures is captured from OpenCode as a person runs it. Each is built from
the source of OpenCode 1.19.4 (`anomalyco/opencode`, tag `v1.19.4`): the
`tool.execute.before` hook as `packages/plugin/src/index.ts` declares it and
`packages/opencode/src/session/tools.ts` calls it, and each tool's parameters in
`packages/opencode/src/tool/*.ts`. So a guess is never mistaken for a capture. Where the
documentation and the source differ, the source was followed.

OpenCode has no command hook. OpenMoat's plugin
(`crates/openmoat-hosts/src/host/opencode/integration/openmoat.js`) builds the JSON that
`openmoat guard --host opencode` reads, so the envelope is OpenMoat's own:

| Field | Source |
|---|---|
| `hook_event_name` | Always `tool.execute.before`, set by the plugin. |
| `tool`, `sessionID`, `callID` | The hook's first argument (`{ tool, sessionID, callID }`). A subagent's calls carry the subagent's own session id. |
| `args` | The hook's second argument, `output.args`: the arguments the tool will receive. |
| `directory`, `worktree` | Added by the plugin: the `PluginInput` of the OpenCode instance that loaded it. Tools resolve relative paths against `directory`. |
| `mcpServers` | Added by the plugin: the keys of `mcp` in the merged configuration its `config` hook receives. |
| `platform` | Added by the plugin: `process.platform`. |

## Tool arguments (OpenCode 1.19.4)

- `bash` (the id stays `bash` whatever the shell is): `command`, `timeout` (ms), `workdir`.
- `read`: `filePath`, `offset`, `limit`. `write`: `filePath`, `content`. `edit`: `filePath`,
  `oldString`, `newString`, `replaceAll`. `apply_patch` (offered to GPT models in place of
  `edit` and `write`): `patchText`.
- `glob`: `pattern`, `path`. `grep`: `pattern` (a regular expression), `path`, `include`.
- `webfetch`: `url`, `format`, `timeout` (s). `websearch`: `query` (the tool is shown only
  for some providers; its source was not read, the argument name is the documented one).
- `lsp` (experimental): `operation`, `filePath`, `line`, `character`, `query`.
- `task`: `description`, `prompt`, `subagent_type`, `task_id`, `command`, `background`.
- MCP tools: `<server>_<tool>`, each with every character but letters, digits, `_` and `-`
  as `_` (`mcp/catalog.ts`). `read_mcp_resource`: `server`, `uri`.
- Paths are taken as written: OpenCode joins a relative one to `directory` and expands no
  `~`.

`mcp-ambiguous.json` names two servers, `files` and `files_read`, whose spellings both
begin `files_read_file`; `plugin-tool.json` is a tool no server's name begins, as a
plugin's or a custom tool's is.

## OpenCode 2 (`v2-*.json`)

Built, not captured, from the source of OpenCode 2.2.0 (`anomalyco/opencode`, tag
`v2.2.0`): the `execute.before` event as `packages/plugin/src/promise/tool.ts` declares
it and `packages/core/src/tool.ts` builds it (`{ tool, sessionID, agent, messageID, id,
input }`), and each tool's `Input` schema in `packages/core/src/tool/plugin/*.ts`. The
envelope is again OpenMoat's own:

| Field | Source |
|---|---|
| `hook_event_name` | Always `execute.before`, set by the plugin. |
| `tool`, `sessionID`, `agent`, `messageID` | The event's fields. |
| `callID` | The event's `id` (the tool call's id). |
| `input` | The event's `input`, after OpenCode's own `opencode.tool.input.repair`, cloned and frozen by the plugin: what the tool runs with. |
| `directory`, `worktree` | Added by the plugin: `ctx.location.directory` and `ctx.location.project.directory`. |
| `mcpServers`, `platform` | Added by the plugin: the server names its `mcp` transform sees, and `process.platform`. |

Tool arguments (OpenCode 2.2.0): `shell` `command`, `workdir`, `timeout`, `background`;
`read` `path`, `offset`, `limit`; `write` `path`, `content`; `edit` `path`, `oldString`,
`newString`, `replaceAll`; `patch` `patchText`; `glob` `pattern`, `path` (the text
`undefined` or `null` is none), `hidden`, `limit`; `grep` `pattern`, `path`, `include`,
`literal`, `caseSensitive`, `limit`; `webfetch` `url`, `format`, `timeout`; `websearch`
`query`; `subagent` `agent`, `prompt`, …; `read_mcp_resource` `server`, `uri`;
`opencode_worktree_remove` `directory`. A leading `~` or `~/` is the home directory
(`core/src/file-access.ts`, `resolvePath`), unlike OpenCode 1. `v2-read-malformed.json`
names OpenCode 1's `filePath`, which OpenCode 2's `read` does not take.

Replace these with captured payloads once OpenMoat's plugin has run under a real
OpenCode 1 and 2 (`cat` the stdin of `openmoat guard` from a scratch `XDG_CONFIG_HOME`).
