# Cline hook payloads

None of these fixtures is captured from a running Cline: a tool call needs a model
answer, and capturing one means signing in to a model provider. Each is built from the
source of `cline/cline` at tag `cli-v3.0.74` (2026-10-26; the SDK files named here are
the same at the extension's `v4.1.26`), read on 2026-11-03, so a guess is never
mistaken for a capture. Paths are placeholders: `/p` for the project, `/Users/me` for
the home directory.

| Field | Source |
|---|---|
| `clineVersion`, `timestamp`, `taskId`, `sessionContext.rootSessionId`, `workspaceRoots`, `userId`, `agent_id`, `parent_agent_id` | `createPayloadBase` in `sdk/packages/core/src/hooks/hook-file-hooks.ts` |
| `hookName` (`tool_call`), `iteration`, `tool_call` (`id`, `name`, `input`), `preToolUse` (`toolName`, `parameters`: each argument as a string, others as JSON) | `runToolCallStart` and `mapParams` in the same file; `PreToolUse` → `tool_call` in `HOOK_CONFIG_FILE_EVENT_MAP` (`hook-file-config.ts`) |
| `input` | the model's arguments, with JSON-looking strings parsed as the tool's schema expects (`sdk/packages/agents/src/agent-runtime.ts`, before the `beforeTool` hooks) and not yet put in one shape by the tool's lenient schema |
| the reply | `parseHookControl` and `beforeToolResultFromControl` in `hook-file-hooks.ts`: `cancel: true` with `errorMessage` stops the call and the run; `review` is ignored for a tool call; stdout that is not JSON, a hook that cannot start and a timeout (120 s) are logged and the call runs; the exit code is never read |

The documented example in `sdk/examples/hooks/README.md` ("Hook Input/Output Format")
shows an older `read_files` input, `{"filePath": …}`; the source's schema is followed
here.

## Tool arguments (`sdk/packages/core/src/extensions/tools/schemas.ts`)

- `run_commands`: `commands`, a list of shell lines or `{command, args}` run without a
  shell; also accepted as one line, one entry, a list, `{command}` or `{cmd}`
  (`RunCommandsInputUnionSchema`, `collectRunCommands` in `helpers.ts`).
- `read_files`: `files`, a list of `{path, start_line, end_line}`; also a path, a list
  of paths, `file_path`/`filePath` for `path`, `file_paths` or `paths`
  (`ReadFilesInputUnionSchema`).
- `editor`: `path`, `old_text`, `new_text`, `insert_line`. `apply_patch`: `input`,
  the patch. `search_codebase`: `queries`. `fetch_web_content`: `requests`, each
  `{url, prompt}`. `skills`: `skill`, `args`. `ask_question`: `question`, `options`.
- An MCP server's tool is `<server>__<tool>` (`defaultMcpToolNameTransform` in
  `extensions/mcp/name-transform.ts`).

## Files

| Fixture | What it is |
|---|---|
| `run_commands.json` | a shell line sending a private key |
| `run_commands-benign.json` | `git status` |
| `run_commands-structured.json` | `{command, args}`, run without a shell |
| `run_commands-many.json` | two lines, run one after the other |
| `run_commands-split-quote.json` | two lines that read as one quoted string when put together |
| `read_files.json`, `read_files-several.json` | one and two file requests |
| `read_files-malformed.json` | a file request without a path |
| `editor.json`, `apply_patch.json` | an edit and a patch adding a file |
| `search_codebase.json`, `fetch_web_content.json` | a search and a fetch |
| `mcp.json` | `internal-tools__run` with a path argument |
| `ask_question.json` | a question to the person (ungoverned) |
| `skills.json` | a skill, checked as an unknown tool |
| `tool_result.json` | the `PostToolUse` event, which OpenMoat does not handle |
