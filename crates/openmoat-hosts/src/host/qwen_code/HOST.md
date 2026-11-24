# Qwen Code (`qwen-code`)

Alibaba's terminal coding agent (`qwen`, npm `@qwen-code/qwen-code`), a fork of Gemini
CLI, through its `PreToolUse` command hook. **Preview:** every fact here comes from
Qwen Code's documentation and source, read 2026-11-14, when npm's latest release was
0.27.3; no real `qwen` has run OpenMoat's hook yet.

Sources:
[hooks](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/) (updated
2026-11-11),
[settings](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/),
[sandbox](https://qwenlm.github.io/qwen-code-docs/en/users/features/sandbox/),
[extensions](https://qwenlm.github.io/qwen-code-docs/en/users/extension/introduction/),
and `QwenLM/qwen-code` `main`: `packages/core/src/hooks/hookRunner.ts`,
`hookEventHandler.ts`, `hook-matcher.ts`, `hookRegistry.ts`, `types.ts`,
`core/toolHookTriggers.ts`, `tools/tool-names.ts`, the tools' `*Params`, and
`config/storage.ts`. `PreToolUse` came with 0.13.0
([#2203](https://github.com/QwenLM/qwen-code/pull/2203)); `openmoat init` does not set up
an older `qwen`.
Implementation: [`qwen_code.rs`](../qwen_code.rs) and [`doc.rs`](doc.rs); if they
disagree, the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout | File |
|---|---|---|---|
| `PreToolUse` | `*` | 600 s | `~/.qwen/settings.json` (`QWEN_HOME` moves the directory) |

The entry is Claude Code's nested layout with one command hook named `openmoat`; its
`command` is a shell string, the binary quoted for `sh`. On Windows the entry sets
`shell: powershell` and ends with `if (-not $?) { exit 2 }`, so a guard that cannot start
still blocks; this was not tried. `*` matches every tool: a regular expression would not
reach the Claude Code names (`Bash`, `Write|Edit`) Qwen Code also accepts. A timeout of
1000 or more would be read as milliseconds.

Input is Claude Code's `PreToolUse` document: `session_id`, `transcript_path`, `cwd`,
`hook_event_name`, `timestamp`, `permission_mode` (`default`, `plan`, `auto_edit`,
`auto`, `yolo`), `tool_name`, `tool_input`, `tool_use_id`, and `agent_id` when the call
is a subagent's. `tool_name` is Qwen Code's runtime name, not Claude Code's.

## Answers

Claude Code's: `hookSpecificOutput.permissionDecision` `allow`, `deny` or `ask`, with
`permissionDecisionReason`; nothing on stdout for a `defer`, which leaves the call to Qwen
Code's own permission flow. A deny also exits 2, whose stderr Qwen Code gives the model.
`ask` pauses for the person in the terminal, and the hooks page says no permission rule,
approval mode (YOLO included) or `PermissionRequest` hook answers it instead; in a
headless run, a background subagent or an ACP session Qwen Code turns it into a deny.
Whether `allow` skips Qwen Code's own prompts was not verified.

## Tools OpenMoat sees

- `run_shell_command` (`Shell`; `command` after a `cd` to `directory`). `ForeignShell` on
  Windows, where Qwen Code is taken to run PowerShell as Gemini CLI does (not verified).
- `read_file`, `list_directory` (`FsRead`); `write_file`, `edit` (`FsWrite`, with what
  they leave in the file).
- `glob`, `grep_search` (`FsRead`, `ReadFiles`), as Claude Code's `Glob` and `Grep`.
- `web_fetch` (`Fetch`), `web_search` (`WebSearch` of `query`, a key not verified).
- `read_mcp_resource`; MCP tools `mcp__<server>__<tool>` (`McpTool`).
- Ungoverned: `todo_write`, `ask_user_question`, `enter_plan_mode`, `exit_plan_mode`,
  `tool_search`.
- Every other tool (`agent`, `skill`, `exec`, `notebook_edit`, `save_memory`, `monitor`,
  `enter_worktree`, the cron, task and team tools, a discovered tool): `UnknownTool`,
  whose arguments' paths, URLs and commands are checked. A subagent's own calls fire
  `PreToolUse` too (they carry `agent_id`).

## Configuration and MCP files

- `~/.qwen/settings.json` holds OpenMoat's hook and `mcpServers`; a project's
  `.qwen/settings.json` is merged over it. A project's hooks run only once the person
  approves that exact configuration or trusts the folder; `openmoat status` and `doctor`
  warn about a project file that adds hooks or servers or sets `disableAllHooks`, and a
  write that would set it is denied.
- System settings (`/etc/qwen-code/settings.json`, `/Library/Application
  Support/QwenCode/settings.json`, `C:/ProgramData/qwen-code/settings.json`, moved by
  `QWEN_CODE_SYSTEM_SETTINGS_PATH`) outrank both; OpenMoat protects them and does not
  write them.
- `kernel-self` covers `~/.qwen` and a project's `.qwen`; `agent-credentials` covers
  `~/.qwen/oauth_creds.json`, the name Gemini CLI uses for its sign-in (not verified for
  Qwen Code); `QWEN.md` and `.qwen/` are in the taint list; `~/.qwen/extensions/` and a
  project's `.qwen/` are `runs-later`.

## When the hook fails

Qwen Code runs the call. A hook that times out (SIGTERM, then SIGKILL after 2 s), cannot
start, is killed, exits non-zero other than 2 without JSON on stdout, or prints JSON it
cannot parse is a non-blocking error, and `toolHookTriggers.ts` lets the call go ahead
("Hook errors should not block tool execution"). Qwen Code has no fail-closed setting.
Every error `openmoat guard` can catch itself is a deny with exit 2. OpenMoat's hook command ends in a tail that turns any exit but the guard's own 0 or 2 (a
missing `openmoat` exits 127, a killed one 128 and the signal) into exit 2 with a reason
on stderr (ADR-109), so those block the call. A slow hook never reaches the timeout: the
guard answers deny on its own at its 30 s deadline, before the 600 s `openmoat init`
writes (ADR-120). A timeout still runs the call when the guard cannot answer at all before
it (stopped, or killed together with the hook command). `disableAllHooks`,
`--safe-mode` and `--bare` load no hook at all.

## Known gaps

- Preview: no real `qwen` has run the hook; the fixtures are built from the source. The
  weekly job installs the latest release and checks the hook file and replies only.
- A hook that cannot answer at all before its time limit (its process stopped) lets the
  call run.
- Whether a project's `disableAllHooks` turns the person's hooks off was not verified;
  OpenMoat assumes it does, so `openmoat run` refuses a project that sets it.
- A project or extension hook can rewrite a call's arguments (`updatedInput`) after
  OpenMoat checked it; hooks run in parallel by default and the order of their answers is
  Qwen Code's.
- Qwen Code rewrites `settings.json` itself for a person's choices (a model, a theme);
  which keys it writes was not checked, so any change is drift until `openmoat init` or
  `openmoat doctor --accept`.
- The argument keys of `web_search`, `agent`, `skill`, `notebook_edit` and `exec` were not
  read.
- The shell Qwen Code runs `run_shell_command` and hooks with on Windows was not
  verified.

## Sandbox

None from OpenMoat: `hook only`. Qwen Code has its own (`--sandbox`, `QWEN_SANDBOX`,
`tools.sandbox`: macOS Seatbelt profiles, Docker or Podman, off by default; `--yolo` does
not turn it on), which OpenMoat does not write. Which directories `qwen` writes was not
checked, so `openmoat run` has no profile for it.

## Plugin channel

None: Qwen Code's extensions (`qwen extensions install`, `qwen-extension.json`, which
also converts Claude Code plugins) can carry hooks, but which manifest field holds them
was not verified. `openmoat init` is the way in.
