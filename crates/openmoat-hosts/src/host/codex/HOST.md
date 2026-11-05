# Codex (`codex`)

The Codex CLI. It sends `PreToolUse` in Claude Code's format. Every fact here comes from
[`codex.rs`](../codex.rs) and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout |
|---|---|---|
| `PreToolUse` | `Bash\|apply_patch\|read_mcp_resource\|view_image\|mcp__.*` | 600 s |

Supported hook schema: Codex 0.160.1 through 0.166.0, checked at both endpoints.
Codex ignores `args`: OpenMoat writes one POSIX shell-quoted `command`, plus
`commandWindows` and `statusMessage: "OpenMoat"`. Both versions execute the string
through `$SHELL -lc` (fallback `/bin/sh`), or `%COMSPEC% /C` (fallback `cmd.exe`).
The Windows override invokes Windows PowerShell with a UTF-16 encoded command, so
spaces, apostrophes, percent signs and other shell characters in paths survive cmd's
expansion; PowerShell propagates the guard's exit code. Custom command shells must
support the corresponding invocation.

Codex runs a new or changed user hook only once the person trusts it: after
`openmoat init`, open Codex, run `/hooks` and trust the OpenMoat hook.
`openmoat init`, `openmoat policy upgrade` and `openmoat sandbox sync` replace legacy
args-style entries and re-pin the lock; repeat the trust step after the replacement.
`status` and `doctor` fail for legacy entries. They only warn about an installed but
not trusted hook, leaving their exit code successful: the check mirrors Codex's
internal hash and must never block a call, installation or upgrade. The Codex host
module reads the parsed `[hooks.state]` from `config.toml`, checking the entry's
source/index, enabled flag and normalised declaration hash; it never grants trust.
Project or managed configuration overrides can still change the state Codex loads.

Source: Codex [0.166 schema](https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/protocol/src/hooks.rs#L140),
[0.160.1 schema](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/config/src/hook_config.rs#L161),
[execution](https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/hooks/src/engine/command_runner.rs#L417),
[older execution](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/hooks/src/engine/command_runner.rs#L359)
and [trust discovery](https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/hooks/src/engine/discovery.rs).

## Tools OpenMoat sees

- `Bash` (`Shell`), `apply_patch` (`Patch`), `mcp__<server>__<tool>` (`McpTool`),
  `read_mcp_resource` (`McpTool` `read_resource`, a `file:` URI read as its file) and
  `view_image` (`FsRead`, `Fetch` for an `http(s)` URL).
- `write_stdin` runs no hook: Codex types into a command an earlier call started. A
  `Bash` call that starts a program reading its commands from its input (a shell, a
  REPL, an editor, `ssh host`, `sqlite3 db`, `tmux`, `docker run -i` … with no script
  or command of its own, and whose input is not a pipe, file or here-document) needs
  review (`Unchecked`); the deny tells the model to pass the commands instead
  (`bash x.sh`, `bash -c …`, `python3 x.py`, `ssh host cmd` are decided as before).
- Ungoverned: `update_plan`, `list_mcp_resources` and any other tool; code mode's
  `exec`/`wait` and `request_permissions` are not hooked.

## Working directory

Codex sends a call's own working directory as `cwd` (a shell call's `workdir`, which the
model chooses) and starts every hook in the session's directory. When the `cwd` lies
outside the session's project, `openmoat guard` decides the call from the session's
directory, with the command run after a `cd` to the `cwd` and relative paths taken from
it: a write from `~/Library/LaunchAgents` is checked as that path. A session started
outside any project (the home directory) keeps a `cwd` inside a git work tree as its
project.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Reviews

Codex hooks cannot prompt: Codex rejects `permissionDecision: "ask"` and then runs the call,
so a review is sent as a deny that the person approves with `openmoat allow --last`.

## Configuration and MCP files

- Configuration directory: `CODEX_HOME`, else `~/.codex`; hooks in `hooks.json` (nested
  layout).
- MCP servers: `config.toml` beside the hook file and a project's `.codex/config.toml`;
  tools are named `mcp__<server>__<tool>`.
- Project settings: a trusted project's `.codex/config.toml` and `.codex/hooks.json`, whose
  hooks run beside OpenMoat's; `[features] hooks = false` there or in the user's
  `config.toml` turns every hook off.

Credentials: `auth.json` (the ChatGPT tokens or API key, the default store) and
`.credentials.json` (MCP OAuth tokens without a keyring) in `CODEX_HOME` are
`agent-credentials`': the agent's own tools may not read them (`kernel-self` already
denies every write there). The keyring entries (`Codex Auth`, `Codex MCP Credentials`)
are read by `security find-generic-password -w` or `secret-tool lookup`, which
`secrets-paths` denies. `codex mcp add` and `codex mcp login` need review (`runs-later`);
`codex mcp add --url` starts the server's OAuth sign-in at once. `openmoat status` and
`openmoat doctor` warn when the `codex` on the search path is a version with a
published advisory (`advisories.rs`).

## When the hook fails

Codex runs the call when the hook is missing, cannot start, exits non-zero other than 2
(or 2 with nothing on stderr), or times out (default 600 s).

## Known gaps

Web search, hosted tools, code mode's `exec`/`wait` and `request_permissions` are not
hooked; what `write_stdin` types into a running command is not hooked, so a command that
starts a shell, REPL, editor or login without its own commands needs review; reviews
become denies; Codex skips a new or changed hook until the person trusts it in `/hooks`,
and `[features] hooks = false` turns hooks off (`openmoat status` and `doctor` report
that); calls run unchecked if the hook binary is missing or crashes.

## Sandbox

OpenMoat writes its permissions profile into Codex's `config.toml`; the lock pins the part
OpenMoat owns. Codex's Linux sandbox does not refuse `TIOCSTI`, so only the kernel stops a
command typing into the terminal there (`openmoat doctor` warns).

With `sandbox.proxy_port`, Codex's own proxy hands its traffic on to `openmoat proxy`
with no session credential, and no Codex hook can add one (ADR-044). `openmoat proxy`
refuses that traffic (`407`, a `proxy-session` row) unless the policy sets
`sandbox.proxy_serve_without_credential: true`, which serves it without a session and
without session taint; `openmoat run -- codex` gives each run a credential of its own.
`openmoat status` and `openmoat doctor` report this under "proxy sessions" as a warning.
