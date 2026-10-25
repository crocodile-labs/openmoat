# Hermes Agent (`hermes`)

Hermes Agent (`hermes`, Nous Research, <https://github.com/NousResearch/hermes-agent>),
through its `pre_tool_call` shell hook, checked against the source of v0.22.5
(2026-10-23). Hermes releases several times a week; its hook protocol follows Claude
Code's and Cursor's (`decision`/`reason`, exit 2, `fail_closed`), and its own `approve`
reply and the payload's `extra` keys are newer. Every fact here comes from
[`hermes.rs`](../hermes.rs) and the files beside this one; if they disagree, the code
wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout | Fail closed |
|---|---|---|---|
| `pre_tool_call` | none (every tool) | 60 s | `fail_closed: true` |

`openmoat init` adds one entry to `hooks.pre_tool_call` in `config.yaml` and approves its
exact command in `shell-hooks-allowlist.json` beside it: Hermes runs a shell hook only
once that `(event, command)` pair is there, and its gateway, cron, ACP and `mcp-serve`
sessions skip one that is not without asking. `openmoat status` and `openmoat doctor`
report a hook the allowlist does not approve; `openmoat init` approves it again.

`config.yaml` is the person's and Hermes rewrites it itself, comments kept, so OpenMoat
edits it as text: only its own entry's lines are added or taken out, and the result is
checked to parse to the document it must. A `hooks:` written on one line (flow style), a
quoted `"hooks"` key, a repeated key, a merge key (`<<`) or an unknown tag is refused, and
`openmoat init` prints the entry to add by hand. `openmoat uninstall` takes the lines out
again, gives back the backup's bytes when nothing else changed, and takes OpenMoat's
command out of the allowlist (deleting it when `init` created it).

Input is `hook_event_name`, `tool_name`, `tool_input`, `session_id` (may be empty), `cwd`,
`profile` and `extra` (`task_id`, `tool_call_id`, `turn_id`, `api_request_id`,
`middleware_trace`). The `cwd` is the Hermes process's working directory, not the
session's.

| Verdict | Reply | Exit |
|---|---|---|
| `allow` | `{}` | 0 |
| `defer` | nothing | 0 |
| `ask` | `{"action": "approve", "message", "rule_key": "openmoat:<hash>"}` | 0 |
| `deny`, and every adapter error | `{"decision": "block", "reason"}` | 2 |

Hermes has no "allow" that skips its own checks, so `allow` and `defer` both leave the
call to them.

## Tools OpenMoat sees

- `terminal` (`Shell`, with `workdir` as a `cd` before the command; `Unchecked` for a
  relative `workdir` or a command that leaves the session's shell where OpenMoat cannot
  know).
- `read_file` (`FsRead`); `write_file`, `patch` (`FsWrite`; `Patch` for a V4A
  `mode: patch`); `search_files` (`FsRead`, `ReadFiles`). A relative path asks
  (`Unchecked`): Hermes resolves it against the session's directory, which the payload
  does not send.
- `web_search` (`WebSearch`), `web_extract` (`Fetch` for one URL, `UnknownTool` for
  several), `browser_navigate` (`Net`).
- `execute_code` (`ForeignShell`, `unparseable`): the script is not read; each tool it
  calls through `hermes_tools` fires the hook on its own.
- `process_manage` `write`/`submit` (`Unchecked` `Shell`); `cronjob_manage` other than
  `list` (`Unchecked` `UnknownTool`, its `script` read as a command).
- MCP tools `mcp__<server>__<tool>` (`McpTool`).
- Any other tool (`memory`, `skill_manage`, `skill_view`, the other `browser_*` tools,
  `vision_analyze`, `computer_use`, the messaging tools, connectors, a plugin's tool):
  `UnknownTool`.
- Ungoverned: `todo_list`, `clarify`, `session_search`, `skills_list`, `delegate_task`
  (its subagents' calls fire the hook), `read_terminal`, `close_terminal`, and
  `process_manage` `list`, `poll`, `log`, `wait`, `kill`, `close`, `handoff`.

The Tool Search bridge's `tool_call` is unwrapped by Hermes before the hook, so the hook
sees the tool that runs. The full table is in
[ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

An ask goes to Hermes's own approval prompt (the terminal, or the gateway's buttons on
Telegram, Slack and the others), which blocks the call on a denial, a timeout or when no
one can answer. Its `rule_key` is a hash of OpenMoat's reason, so Hermes's "always"
approves that ask again, never the whole tool.

Hermes approves an ask without a person seeing it in YOLO mode and with
`approvals.mode: off` (the Desktop's "Approvals: off"), and in cron, `hermes chat -q` and
webhook sessions whose `approvals.cron_mode`, `single_query_mode` or `unattended_mode` is
`approve`. Where OpenMoat can see that, the ask is a deny that says how to approve it
(`openmoat`, or `openmoat allow --last`): `HERMES_YOLO_MODE` in the hook's environment
(`--yolo` sets it), or one of those settings in the `config.yaml` `openmoat init` set up
or the one `HERMES_HOME` names for the hook. It cannot see the in-session `/yolo` toggle
or a `hermes -z` one-shot run, which approve asks unseen.

## Configuration and MCP files

- The Hermes home: `HERMES_HOME`, else `~/.hermes` (`%LOCALAPPDATA%\hermes` on Windows;
  `HERMES_DATA_DIR_SUFFIX` is added to the name). The hook goes in its `config.yaml`, the
  approval in its `shell-hooks-allowlist.json`; the lock pins both: `config.yaml` without
  `mcp_servers` and without what Hermes rewrites for a person's choice (`model`,
  `display`, `_config_version`), the allowlist whole. Any other change, a hook, plugin,
  approval mode, terminal backend or another hook approved in Hermes's own prompt, denies
  every call until a person runs `openmoat init` or `openmoat doctor --accept`.
- Profiles: `~/.hermes/profiles/<name>/` is a home of its own, chosen with `hermes -p`,
  the sticky `active_profile` file or `HERMES_HOME`. `openmoat init` sets up the one home
  this environment names; to protect a profile, run it with `HERMES_HOME` naming that
  profile. Any other profile runs without OpenMoat's hook.
- MCP servers: `mcp_servers` in `config.yaml`, pinned one by one; tools are named
  `mcp__<server>__<tool>`, each part with every character but ASCII letters, digits and
  `_` as `_`, a name longer than 64 characters cut and hashed. Hermes reads no project
  file of servers. `openmoat mcp wrap` does not rewrite YAML; it prints the `command` and
  `args` to set by hand.
- No project settings file: a project's `AGENTS.md`, `.hermes.md` and `SOUL.md` are prompt
  text, and its `.hermes/plugins/` load only with `HERMES_ENABLE_PROJECT_PLUGINS`.

## Self-protection

The default policy's `kernel-self` rule denies the agent's writes to the Hermes home
itself, its `config.yaml`, `shell-hooks-allowlist.json`, `.env`, `active_profile`,
`plugins/`, `hooks/`, `agent-hooks/` and the `profiles` folder; setting
`HERMES_SAFE_MODE`; and `hermes config set hooks…`, `approvals…`, `plugins…` or
`HERMES_SAFE_MODE`,
`hermes hooks revoke` and `hermes profile use`. `runs-later` asks before writes to
`cron/`, `skills/`, another profile's configuration, allowlist, `.env`, plugins, hooks,
skills and cron jobs, and a project's `.hermes/plugins/`. Once a session has read
untrusted content, writes to `memories/`, `SOUL.md`, a project's `.hermes.md` and
`.hermes/` ask too (`session-taint`).

## When the hook fails

With `fail_closed: true`, which `openmoat init` sets, Hermes blocks the call when the hook
cannot start, times out (60 s, or `plugins.hook_callback_timeout`, 30 s by default),
exits other than 0 without a decision or prints something that is not a JSON object. It
runs every call unchecked when the hook is not registered: missing from `config.yaml`, not
approved in `shell-hooks-allowlist.json` in a gateway, cron or ACP session, in another
profile, or under `HERMES_SAFE_MODE=1`. An exception inside Hermes's own hook dispatcher
lets the call run (`model_tools.py`, `agent/tool_executor.py`); that takes a Hermes bug,
not a failing hook.

## Known gaps

- No OS sandbox from OpenMoat: `openmoat run hermes` is the OS layer.
- What an `execute_code` script does itself (Python file, process and network calls) is
  not checked; the tools it calls are.
- An enabled plugin, a gateway hook, another shell hook's `modify` reply or Hermes's tool
  middleware runs in Hermes's process and can rewrite a call's arguments after
  OpenMoat's check; the lock pins the hooks and plugins Hermes loads.
- Terminal commands on a remote backend (`terminal.backend` docker, ssh, modal, daytona,
  singularity, vercel) are checked as if they ran locally.
- Relative paths of terminal commands are checked against the Hermes process's directory,
  which differs from the session's after a `cd` in an earlier call, and in Desktop, TUI
  and ACP sessions, which register a workspace of their own; relative file-tool paths ask.
- The in-session `/yolo` toggle and `hermes -z` approve an ask unseen.
- A changed `config.yaml` is caught on the next tool call (Hermes has no
  settings-change hook); a gateway drops a hook removed from it within about 30 s.
- `HERMES_SAFE_MODE=1`, another profile, or Hermes's private safe-worker mode runs no
  shell hook.
- Hermes's hook API moves fast; the fixtures are built from v0.22.5's source, not
  captured from a running agent.

## Sandbox

None: hook only. Under `openmoat run`, Hermes cannot write the files `kernel-self`
protects, its own `config.yaml` included.
