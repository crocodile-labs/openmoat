# Cline CLI (`cline`)

The Cline CLI (`cline`, npm `@cline/cli`, <https://github.com/cline/cline>), through its
`PreToolUse` file hook, checked against the source of tag `cli-v3.0.74` (2026-10-26);
the SDK files it runs hooks with are the same in the VS Code extension's `v4.1.26`.
Every fact here comes from [`cline.rs`](../cline.rs) and the files beside this one; if
they disagree, the code wins.

The Cline VS Code extension is not covered: it runs its own hook layer, which reads
hooks only from `~/Documents/Cline/Hooks` and a workspace's `.clinerules/hooks`, sends
another payload (`hookName: "PreToolUse"`, `preToolUse.parameters` as strings) and
needs an executable file (`apps/vscode/src/core/hooks/hook-factory.ts`). OpenMoat's
adapter answers that payload with a deny, so its script copied there would block every
call rather than check it.

## Hooks OpenMoat installs

| Event | File | Timeout | Fail closed |
|---|---|---|---|
| `PreToolUse` (`tool_call`) | `~/.cline/hooks/PreToolUse` | 120 s (Cline's, fixed) | by OpenMoat's script; Cline has no setting |

Cline has no hook entries in a settings file: every file named after an event in a
hooks directory is that event's hook (`hook-file-config.ts`). The directories are
`~/Documents/Cline/Hooks`, `$CLINE_DIR/hooks` (`~/.cline` unless `CLINE_DIR` moves it),
and a workspace's `.clinerules/hooks` and `.cline/hooks`; Cline runs every
`PreToolUse` file it finds there, with the interpreter its `#!` line names.

`openmoat init` writes OpenMoat's script, the binary's path filled in, to
`<CLINE_DIR>/hooks/PreToolUse` ([`integration/PreToolUse.sh`](integration/PreToolUse.sh)).
The file is OpenMoat's whole: the lock pins it, a person's file of that name is backed
up first and given back by `openmoat uninstall`, which deletes OpenMoat's. The script
runs `openmoat guard --host cline` with the call on stdin and prints its reply; when
`openmoat` is missing, crashes or exits without the reply it owes, the script prints
`{"cancel": true, …}` itself, since Cline runs the call when a hook fails.

Input is `hookName` (`tool_call`), `clineVersion`, `timestamp`, `taskId`,
`sessionContext.rootSessionId` (the session, used as the session id), `workspaceRoots`
(the first is the working directory), `userId`, `agent_id`, `parent_agent_id`,
`iteration`, `tool_call` (`id`, `name`, `input`) and `preToolUse` (`toolName`,
`parameters`).

| Verdict | Reply (stdout) |
|---|---|
| `allow` | `{}` |
| `defer` | nothing |
| `review` | as `deny`, with how to approve it: Cline's hooks cannot prompt |
| `deny`, and every adapter error | `{"cancel": true, "errorMessage"}` |

Cline reads stdout only, never the exit code. It has no "allow" that skips its own
approval, so `allow` and `defer` both leave the call to it. A `cancel` stops the call
before it runs and ends Cline's run with `errorMessage` as the reason
(`applyStopControl` in `sdk/packages/agents/src/agent-runtime.ts`).

## Tools OpenMoat sees

- `run_commands` (`Shell`): each command runs on its own, in the workspace; a
  `{command, args}` entry runs without a shell and is checked as its quoted words.
  Several commands are decided together, each in a subshell of its own; a command that
  cannot be read alone (an open quote, a trailing `\`) could hide the next one when put
  together, so then the call needs review (`Unchecked`). On Windows Cline runs them in
  PowerShell (`ForeignShell`).
- `read_files` (`FsRead`, `ReadFiles`), `editor` (`FsWrite`), `apply_patch` (`Patch`),
  `search_codebase` (`FsRead` of the workspace).
- `fetch_web_content` (`Fetch` for one URL, `UnknownTool` for several).
- MCP tools, `<server>__<tool>`: recorded as `mcp__<server>__<tool>` and decided as
  that MCP tool. A browser server's call that only opens a page (`browser_navigate`)
  is that page's open, as on every other host (ADR-047); any other is checked for every
  path, URL and command its arguments name, since a plugin's tool may be named the same
  way.
- Any other tool (`skills`, subagent and team tools, a plugin's): `UnknownTool`.
- Ungoverned: `ask_question`, `submit_and_exit`.
- Not hooked: the provider's own `web_search`, which the model provider runs.

The hook sees the arguments as the model gave them, before Cline's lenient schemas put
them in one shape, so every shape those schemas accept is read and any other is
malformed (a deny). The full table is in
[ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Configuration and MCP files

- `~/.cline` (`CLINE_DIR`): `hooks/`, `plugins/`, `data/settings/providers.json`
  (provider keys), `data/settings/cline_mcp_settings.json` (MCP servers,
  `{"mcpServers": {…}}`, which `openmoat init` pins), `data/db/connectors.db`.
- `CLINE_DATA_DIR` and `CLINE_MCP_SETTINGS_PATH` move the data and the MCP file;
  OpenMoat reads them only at their default place.

## When the hook fails

| Failure | Cline |
|---|---|
| `openmoat` missing, crashing, or exiting without a reply | blocked by OpenMoat's script |
| the script cannot start (no `sh`, as on native Windows) | runs the call |
| the script prints something that is not JSON | runs the call |
| the script is killed after 120 s | runs the call |
| `--yolo` | runs no hooks at all |

## Known gaps

- No OS sandbox from OpenMoat (`openmoat run` sandboxes the whole agent).
- `--yolo` runs no hooks; `--config`, `--hooks-dir` or a moved `CLINE_DIR` that OpenMoat
  did not install into skip OpenMoat's script.
- Reviews become denies, and a deny ends Cline's run; the person approves with
  `openmoat allow --last` and continues the session.
- Cline approves calls on its own by default (`--auto-approve`, default `true`), so a
  call OpenMoat defers usually runs.
- Another `PreToolUse` file or a plugin can rewrite a call's input (`overrideInput`)
  after OpenMoat checked it. `openmoat status` and `doctor` name every other
  `PreToolUse` file in `~/Documents/Cline/Hooks`, `<CLINE_DIR>/hooks` and the current
  workspace's hook folders, and every entry of `<CLINE_DIR>/plugins`, and print Cline's
  limits (`--yolo`, hooks that rewrite input, a script that cannot start or times out) on
  a line of their own. `--yolo` is a flag of one run, which they cannot see. A workspace's `.cline/hooks` and `.clinerules/hooks` run
  with the agent's rights; writing them (or renaming a folder onto `.clinerules`,
  `.cline` or their `hooks`) needs review (`runs-later`), and session taint protects
  every `.cline` and `.clinerules` file.
- The VS Code extension, and native Windows, are not covered.
