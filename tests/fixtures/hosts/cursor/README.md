# Cursor hook payloads

What each fixture is based on, so a guess is never mistaken for a capture.

| Fixture | Source |
|---|---|
| `preToolUse-shell-3.13.json` | Shape of a real Cursor 3.13.25 `preToolUse` payload posted in <https://forum.cursor.com/t/inconsistent-hook-payload/166997> (values replaced): top-level `cwd` may be empty, `tool_input` carries `cwd`, not the documented `working_directory`. A Cursor staff reply in that thread confirms `cwd` is the right key. |
| `preToolUse-grep-file-path.json` | Shape of a live cursor-agent `2026.09.26-dd393fe` `preToolUse` `Grep` payload (captured 2026-09-27, values replaced), published as a third-party fixture in <https://github.com/noamsto/dispatcher/pull/529>: the target is `tool_input.file_path`, with `pattern`; no `path`, `glob` or `output_mode`. The same capture shows `Read` sends `tool_input.file_path`. |
| `preToolUse-*.json`, `before*.json` | Field names from <https://cursor.com/docs/hooks> (common fields, `beforeReadFile` `file_path`, `beforeMCPExecution` `tool_input` as a JSON string, `preToolUse` `tool_name`/`tool_input`/`tool_use_id`/`cwd`). |

## What the docs settle (checked 2026-10-06)

- <https://cursor.com/docs/hooks>: `preToolUse` matcher values include `Shell`, `Read`,
  `Write`, `Grep`, `Delete`, `Task` and `MCP:<tool_name>`. The only `tool_input` shown
  is `Shell`'s.
- <https://cursor.com/docs/reference/third-party-hooks>: Claude Code `Edit` maps to
  Cursor `Write`, `WebFetch` and `WebSearch` keep their names, and `Glob` has no
  Cursor equivalent.

## Not verified (#138)

- No official source gives the `tool_input` keys of `Read`, `Write`, `Grep` or
  `Delete`. `file_path` for `Read` and `Grep` comes from the third-party capture above;
  `file_path` for `Write` and `Delete` is assumed, and so is `query` for `WebSearch`
  (Claude Code's key). A missing key is an adapter error,
  so a deny.
- `preToolUse-grep.json` (Grep with `path`) and `preToolUse-write.json` are not
  captures. The adapter reads every path key a search carries (`path`, `file_path`,
  `target_file`, `target_directory`, `target_directories`), else `cwd`, else the first
  workspace root.
- `Glob`, `Edit`, `MultiEdit` and `StrReplace` are not Cursor hook tool names in the
  docs. The adapter maps them in case a build sends them.
- Any other tool that names a path under one of those keys is read as reading it,
  or as writing it when its name is write-shaped (`Delete`, `Rename`, `Move`, …).
  `preToolUse-delete-directory.json` is not a capture: it stands for such a tool.
- A tool that names no path under those keys is `tool.unknown`, which asks.
  `preToolUse-unknown.json` (`RunNotebookCell`) is not a capture: it stands for such
  a tool. `url` for `WebFetch` is assumed (Claude Code's key).

Replace these fixtures with a captured Cursor IDE payload once one is available.
