# GitHub Copilot CLI hook payloads

None of these fixtures is captured from a running Copilot CLI; capturing one
needs a signed-in session. Each is built from the documented camelCase
`preToolUse` payload and from the tool argument shapes in the
`@github/copilot` 1.0.101 npm package, so a guess is never mistaken for a
capture.

| Field | Source |
|---|---|
| `sessionId`, `timestamp`, `cwd`, `toolName`, `toolArgs` | <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference> ("Payload fields": camelCase `preToolUse`). `timestamp` is Unix epoch milliseconds. |
| `toolArgs` as a JSON string | The examples in <https://awesome-copilot.github.com/instruction/hooks/> parse it a second time; the SDK types it `unknown`. The adapter reads an object too. |
| `apply_patch.json` `toolArgs` as the patch text | The CLI reads an `apply_patch` call's arguments as the text itself, or its `input` or `patch` (`Svr` in the package's `cli-main.js`). |

## Tool arguments (`@github/copilot` 1.0.101, `cli-main.js`)

- `bash`, `powershell`: `command`, `description`, `timeout`, `shellId`, `async`.
- `write_bash`, `write_powershell`: `shellId`, `input` (keys typed into a running shell).
- `view`: `path`, `view_range`. `create`: `path`, `file_text`. `edit` and `str_replace`: `path`, `old_str`, `new_str`.
- `str_replace_editor` (older builds): `command` (`view`, `create`, `str_replace`, `insert`), `path`.
- `grep`, `rg`: `pattern`, `paths` (a path or a list), `glob`, `output_mode`. `glob`: `pattern`, `paths`.
- `web_fetch`: `url` (assumed from the tool's name and the docs' "fetches web pages").
- MCP tools: the hook payload carries only the model-facing name; `filesystem-read_file` in `mcp.json` assumes `<server>-<tool>`.

## How to capture real ones

In a throwaway `COPILOT_HOME`, put a hook file in `$COPILOT_HOME/hooks/` whose
`preToolUse` entry runs `cat > /tmp/payload-$$.json`, start `copilot` in a scratch
project, and ask for one call of each tool. Replace the paths and ids before
committing a payload.
