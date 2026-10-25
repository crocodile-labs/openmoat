# OpenCode hook payloads

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

Replace these with captured payloads once OpenMoat's plugin has run under a real
OpenCode 1 (`cat` the stdin of `openmoat guard` from a scratch `XDG_CONFIG_HOME`).
