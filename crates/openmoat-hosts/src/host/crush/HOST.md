# Crush (`crush`)

Charm's terminal coding agent (`crush`), through its `PreToolUse` command hook.
**Preview:** every fact here comes from Crush's documentation and source at
`charmbracelet/crush` `main`, read 2026-11-14, when the latest release was v0.101.0; no
real `crush` has run OpenMoat's hook yet, and the weekly job does not install Crush.

Sources: `docs/hooks/README.md` and `docs/config/README.md`;
`internal/hooks/config.go`, `input.go`, `runner.go`; `internal/agent/hooked_tool.go`;
`internal/agent/tools/*.go` (each tool's `*Params`, `mcp-tools.go`);
`internal/config/config.go`, `load.go`, `hooks.go`, `config_unix.go`;
`internal/home/home.go`. Hooks came with v0.63.0; `openmoat init` does not set up an
older `crush`.
Implementation: [`crush.rs`](../crush.rs) and [`doc.rs`](doc.rs); if they disagree, the
code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout | File |
|---|---|---|---|
| `PreToolUse` | none (every tool) | 600 s | `~/.config/crush/crush.json` (`$XDG_CONFIG_HOME/crush/`, or `CRUSH_GLOBAL_CONFIG`) |

Crush's layout is flat: `{"hooks": {"PreToolUse": [{"name": "openmoat", "command": …,
"timeout": 600}]}}`, one entry per hook, not Claude Code's nested groups. Crush runs the
`command` in its embedded POSIX shell (since v0.67.0), so the binary is quoted for
`sh`. Crush's documentation calls JSON configuration deprecated in favour of `crushrc`
Bash files, but still loads and merges it; OpenMoat writes JSON and reads no `crushrc`.

Input is Claude Code's `PreToolUse` document without `transcript_path` or
`permission_mode`: `event`, `hook_event_name`, `session_id`, `cwd`, `tool_name`,
`tool_input`, `tool_use_id`. `tool_name` is Crush's own name. Crush also sets
`CRUSH_*` variables and `CLAUDE_PROJECT_DIR` for the hook.

## Answers

Claude Code's `hookSpecificOutput.permissionDecision`: `deny` blocks (and OpenMoat exits
2, whose stderr Crush gives the model); `allow` approves the call and skips Crush's own
prompt. Crush reads `ask` as no decision and has no answer that asks the person, so a
`review` reaches it as a deny that says how to approve it (`openmoat allow --last`).
Nothing on stdout leaves the call to Crush's permission flow, which `--yolo` skips: a
call OpenMoat defers then runs unasked. A deny from any hook wins over an allow.

## Tools OpenMoat sees

- `bash` (`Shell`; `command` after a `cd` to `working_dir`). On Windows it is left to
  Crush (`ForeignShell`): what its shell is there was not checked.
- `view`, `lsp_diagnostics`, `lsp_symbols` (`FsRead`); `write`, `edit`, `multiedit`,
  `lsp_replace_symbol` (`FsWrite`, with what they leave in the file).
- `ls`, `glob`, `grep` (`FsRead`, `ReadFiles`), as Claude Code's `Glob` and `Grep`.
- `fetch`, `web_fetch` (`Fetch`); `web_search`, `sourcegraph` (`WebSearch`).
- `read_mcp_resource`; MCP tools `mcp_<server>_<tool>` (`McpTool` of that name, told
  apart by the server prefix).
- `agent` and `agentic_fetch`: subagents, whose own tool calls fire no hook. Starting
  one is an `UnknownTool` that needs review, a deny in Crush.
- Ungoverned: `todos`, `question`, `job_output`, `job_kill`, `crush_logs`, `crush_info`,
  `list_mcp_resources`, `agent_status`.
- Every other tool (`download`, `lsp_rename`, `lsp_references`, `lsp_definition`,
  `agent_dispatch`, `agent_send`, `agent_stop`, a tool added later): `UnknownTool`,
  whose arguments' paths, URLs and commands are checked.

## Configuration and MCP files

Crush merges, lowest first: `/etc/crush/crush.json`, the global `crush.json` and the
`crushrc` beside it, the data directory's `crush.json` (`~/.local/share/crush/`, or
`CRUSH_GLOBAL_DATA`), a project's files found from the working directory up to its git
root (`.crushrc`, `crushrc`, `.crush.json`, `crush.json`), and the workspace's
`.crush/crush.json` last. Objects merge and lists are appended, so every file's hooks run
and none can remove another's; identical commands run once.

- `mcp` in each `crush.json` holds MCP servers (`type`, `command`, `args`, `url`, …),
  pinned as for every host; a project's are held until accepted.
- `openmoat status` and `doctor` warn about a project's `crush.json`, `.crush.json` or
  `.crush/crush.json` that adds hooks, servers or `permissions.allowed_tools`.
- `kernel-self` covers the global `crush.json` and `crushrc` and the data directory's
  `crush.json`, which `agent-credentials` also covers, since a `crush.json` can hold a
  provider's `api_key`; a project's configuration files and `crushrc` scripts are in the
  taint list and `runs-later`; `/etc/crush/` is `managed-settings`.

## When the hook fails

Crush runs the call. A hook that times out is "no opinion"; one that cannot start, or
exits with a code other than 0, 2 and 49 without a decision on stdout, is a logged,
non-blocking error; output it cannot parse is no decision. Crush has no fail-closed
setting. Every error `openmoat guard` can catch itself is a deny with exit 2.

## Known gaps

- Preview: no real `crush` has run the hook; the fixtures are built from the source; the
  weekly job does not install Crush yet.
- A failed or timed-out hook lets the call run.
- Subagents' tool calls fire no hook.
- A project's `.crushrc` (or `crushrc`) is a Bash script Crush runs when it starts, from
  the repository, with no trust prompt. OpenMoat cannot read what it does; writing one
  needs review, and `openmoat run` denies commands writing one.
- A project's or another hook can rewrite a call's arguments (`updated_input`) after
  OpenMoat checked it.
- The argument keys of `agent_dispatch`, `agent_send`, `agent_status`, `agent_stop` and
  `crush_info` were not read.

## Sandbox

None from OpenMoat, and Crush has none of its own: `hook only`. Which directories
`crush` writes was not checked, so `openmoat run` has no profile for it.

## Plugin channel

None: Crush has no plugin system. Agent Skills are its only extensions, and a skill
carries no hook.
