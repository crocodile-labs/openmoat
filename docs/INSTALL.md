# Install and set up OpenMoat

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you install or upgrade OpenMoat on macOS, Linux or Windows, run `openmoat init`, want to know what each agent's hook covers, or use other config directories.

**On this page:** [Install](#install) · [Set up with openmoat init](#set-up-with-openmoat-init) · [Undo with openmoat uninstall](#undo-with-openmoat-uninstall) · [Upgrading](#upgrading) · [Keep openmoat proxy running as a user service](#keep-openmoat-proxy-running-as-a-user-service) · [Teams: managed settings](#teams-managed-settings) · [Non-default config directories](#non-default-config-directories)

In short: install the binary, run `openmoat init` in your own terminal, and start a new
agent session. `openmoat init` writes the default policy, asks before it hooks each agent
it finds, and backs up every file it changes; `openmoat uninstall` puts them back. The
sections below follow that order, then cover upgrades, the proxy service, team setups
and agents that keep their configuration somewhere other than the default.

## Install

Release builds cover macOS (arm64, x64), Linux (x64, arm64; glibc and static musl)
and Windows (x64). The installer URLs below always fetch the latest release; every
release is listed on [Releases](https://github.com/crocodile-labs/openmoat/releases).

```bash
# Homebrew (macOS, Linux)
brew install crocodile-labs/tap/openmoat

# macOS and Linux: installs openmoat into ~/.cargo/bin
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/crocodile-labs/openmoat/releases/latest/download/openmoat-installer.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/crocodile-labs/openmoat/releases/latest/download/openmoat-installer.ps1 | iex"

# From crates.io (Rust 1.95)
cargo install openmoat --locked
```

Then run `openmoat init` ([below](#set-up-with-openmoat-init)).

> [!NOTE]
> **Windows.** On Windows, OpenMoat applies the policy through the agents' hooks. It
> sets up no OS sandbox for Claude Code or Cursor (Codex's own sandbox settings are
> written as on other systems), `openmoat run` refuses to start, `openmoat proxy` cannot be
> installed as a service, and OpenMoat sets no file permissions on its own files: it
> relies on the access rules of the user profile. For OS confinement, run the agent
> and `openmoat` inside WSL2 ([details below](#set-up-with-openmoat-init)).

> [!NOTE]
> **The `moat` name.** The command is `openmoat`. Releases up to 0.7.0 called it
> `moat`, and every install still puts a `moat` beside `openmoat` that runs it, so
> hooks and scripts that call `moat` keep working; `openmoat init` switches the hooks
> to `openmoat`. The `moat` name will be removed in a later release, and an unrelated
> project, `majorcontext/moat`, also installs a command named `moat`: use `openmoat`.
> OpenMoat's Homebrew formula is `crocodile-labs/tap/openmoat` (it was
> `crocodile-labs/tap/moat`) and its crate is `openmoat`. `openmoat --version` prints
> `(OpenMoat)` after the version number. OpenMoat's state stays where it was
> (`~/.moat`, a project's `.moat`).

> [!IMPORTANT]
> **macOS version.** `openmoat run` needs macOS 13 or later. Its Seatbelt profile names
> `(ioctl-command TIOCSTI)` (CVE-2017-5226 class), an identifier `sandbox-exec`
> only recognises from macOS 13 onwards, so on macOS 12 and earlier `openmoat run`
> refuses (exit 64) without starting the agent and says so, and `openmoat doctor`
> warns. CI tests macOS 14 and 15 (`macos-14` and `macos-15-intel`); GitHub
> Actions no longer offers a `macos-13` runner, so macOS 13 is not tested. The
> hooks, `openmoat init`, `openmoat status` and `openmoat doctor` work on earlier macOS and
> still apply the policy to each tool call; only `openmoat run` has this floor.
>
> Homebrew itself no longer supports macOS 12 and earlier: `brew install` or
> `brew upgrade` may stop and ask for a newer Xcode or Command Line Tools than the
> system can run. Install with the shell installer or `cargo install` above
> instead; both put `openmoat` in `~/.cargo/bin`. Keep only one install (see
> [Upgrading](#upgrading)): after `brew uninstall openmoat`, run `openmoat init`
> once so the hooks point to the new binary.

To build from a clone instead (Rust 1.95, pinned by `rust-toolchain.toml`):

```bash
git clone https://github.com/crocodile-labs/openmoat && cd openmoat
cargo install --locked --path crates/openmoat-cli    # installs the `openmoat` binary
```

Each release carries `sha256.sum`, and every release file (archives, installers,
`sha256.sum`) has a GitHub build attestation. To check a file before you use it:

```bash
gh release download --repo crocodile-labs/openmoat --pattern openmoat-installer.sh
gh attestation verify openmoat-installer.sh --repo crocodile-labs/openmoat
```

## Set up with `openmoat init`

```bash
openmoat init      # policy, lock, audit log; asks before hooking each agent it finds
openmoat status    # policy, lock, hooks and protection level per agent, recent decisions
```

`openmoat init` writes `~/.moat/policy.yaml` (the default policy), pins it and the hook
files in `~/.moat/policy.lock` and creates the audit log. Then it lists each agent
whose configuration directory exists, with the files it would change, and asks once
per agent. Before each question it sums up every file that agent would get: new or
edited, lines added and removed, and the top-level settings it sets. Answer `d` to see
the full diff, then answer again (the line counts below are an example; yours depend on
your settings and home directory):

```
Found these agents:
  Claude Code  /Users/you/.claude (changes settings.json)
  Codex        /Users/you/.codex (changes hooks.json, config.toml)
  /Users/you/.claude/settings.json: edited, +310 -0 lines; sets env, hooks, permissions, sandbox
Protect Claude Code (/Users/you/.claude)? [Y/n/d]
  /Users/you/.codex/hooks.json: new file, +23 -0 lines; sets hooks
  /Users/you/.codex/config.toml: edited, +12 -0 lines; sets sandbox_workspace_write
Protect Codex (/Users/you/.codex)? [Y/n/d]
```

Only the agents you accept get the hook and sandbox settings. The last lines name the
backups and how to undo: `Undo anytime: openmoat uninstall`. `init` never overwrites an
existing policy, never duplicates a hook and backs up a host file before editing it
(`<file>.moat-backup` for hooks, `<file>.moat-sandbox-backup` for sandbox settings), so
it is safe to run again. The backups it creates are listed in `~/.moat/hosts.json`;
a file of yours that already has one of those names is left alone, and
`openmoat uninstall` never deletes it.

To choose without questions, name the agents: `openmoat init --hosts claude-code` (or
`codex`, `cursor`, `openclaw`, `copilot-cli`, `pi`, `gemini-cli`, `opencode`, `hermes`; comma-separated). `openmoat init --yes` sets up every agent found, for
scripts. Without a terminal and without `--yes` or `--hosts`, `init` changes no agent's
files and says how to go on. `openmoat init --dry-run` prints what would change first.
`openmoat init --mcp-proxy` also runs every stdio MCP server in the agents' user
configuration through `openmoat mcp proxy`, which pins each tool's description, schemas and annotations
(`openmoat mcp wrap` in [USAGE.md](USAGE.md#commands)).

`init` also pins every MCP server definition the agents load; the tool calls of a server
that changes later, or of a new one, are refused until you run `openmoat mcp accept`.

Hooks run the `openmoat` you ran `openmoat init` with, by its stable path (ADR-016). After
moving or reinstalling the binary somewhere else, run `openmoat init` again; `openmoat doctor`
names a hook whose binary is missing or is a different `openmoat`.

On native Windows, `init` does not turn on Claude Code's sandbox: it runs on macOS,
Linux and WSL2 only, and Claude Code would not start with it required. The hook still
applies the policy to Claude Code's tool calls, and `init`, `doctor` and `status` say so. For OS
confinement, run Claude Code and `openmoat` inside WSL2. Codex's sandbox is set up as on
other systems; Cursor's `sandbox.json` is not written, because Cursor documents its
sandbox for macOS and Linux only.

| Agent | What is hooked | Hook file |
|---|---|---|
| Claude Code | `PreToolUse`: `Bash`, `Monitor`, `PowerShell` (never parsed: `unparseable`), `Read`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, `LSP`, `SendFile`, `Artifact` and `ArtifactData` (the local files they upload or save), `WebFetch` (as `fetch`), `WebSearch` (as `web.search`), MCP tools. `ConfigChange`: user, project and local settings | `~/.claude/settings.json` |
| Codex | `PreToolUse`: shell commands, `apply_patch` (every file the patch names), MCP tools. Codex hooks cannot ask (`PermissionRequest` runs only when Codex itself prompts), so an `ask` blocks the call until you run `openmoat` or `openmoat allow --last`, for `apply_patch` too. Codex does not hook web search or hosted tools. Codex skips a new or changed user hook until you review and trust it in `/hooks` ([hooks docs](https://learn.chatgpt.com/docs/hooks)): after `openmoat init` (and after an upgrade that rewrites the entry), open `/hooks` in Codex and trust OpenMoat's (`openmoat init` and `openmoat doctor` remind you). `[features] hooks = false` in `config.toml` turns every hook off: `openmoat status` and `openmoat doctor` report Codex as not protected while yours sets it, and warn about a trusted project's `.codex/config.toml` or `.codex/hooks.json` that turns hooks off, adds hooks or starts programs | `~/.codex/hooks.json` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` (`Read`, `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete`, `Grep`, `Glob`, `WebSearch`, `WebFetch`, and any other tool: one that names a path is checked against it, one that does not asks as `tool.unknown`); installed with `failClosed`. Cursor prompts on `ask` only for shell and MCP calls, so an `ask` on `preToolUse` or `beforeReadFile` is sent as a deny until you run `openmoat` or `openmoat allow --last`. `openmoat init` also writes Cursor's own sandbox settings (`sandbox.json`) on macOS and Linux; Cursor still runs a command outside that sandbox when its Auto-review classifier approves it, in Run Everything mode, and in the CLI without `--sandbox enabled` ([SANDBOX.md](SANDBOX.md#cursors-sandbox)) | `~/.cursor/hooks.json`, `~/.cursor/sandbox.json` |
| OpenClaw | Every tool, through OpenMoat's plugin and OpenClaw's `before_tool_call` hook: `exec` (PowerShell on Windows: `unparseable`), `read`, `write`, `edit`, `apply_patch`, `web_fetch`, `web_search`, `browser` `open`/`navigate`/`upload`, MCP tools (`<server>__<tool>`; each server in `mcp.servers` pinned), `gateway config.get`, `plugins` changes (as a write to `openclaw.json`), `cron` jobs added or updated (ask, `runs-later`), `view_image` (a file read, or a fetch of one URL), `nodes` `invoke` (`unparseable`); `process` input is `unparseable`; any other tool is `tool.unknown`, checked for the paths, URLs and commands its arguments name. `exec`'s `workdir` is where the command runs, never the project. An `ask` becomes OpenClaw's own approval request; a hook that throws or takes over 60 s blocks the call. `openclaw.json` is read as JSON5 and written back as plain JSON (values kept, formatting not); `openmoat init` refuses a file with comments, which that would drop: move them out of the file first. `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR` and `OPENCLAW_CONFIG_PATH` are followed when `openmoat init` runs and recorded; run `init` again after changing them. An `$include` that may bring MCP servers holds back every OpenClaw MCP call. Restart the Gateway after `openmoat init` | `~/.openclaw/openclaw.json` (or `OPENCLAW_CONFIG_PATH`), `<state dir>/openmoat/openmoat.mjs` |
| GitHub Copilot CLI | `preToolUse` for every tool, in a hook file of OpenMoat's own (Copilot loads every `*.json` in its hooks directory): `bash` (a command that leaves Copilot's shell, which later calls reuse, in a directory OpenMoat cannot know asks), `write_bash` and `write_powershell` (input typed into a running shell: checked on its own and asks), `powershell` (`unparseable`), `view`, `create`, `edit`, `str_replace_editor`, `apply_patch` (every file the patch names), `grep`, `glob`, `web_fetch` (as `fetch`), `web_search`; any other tool, MCP tools included, is checked by the paths and URLs its arguments name and by the shell commands under a command key. An `ask` is Copilot's own prompt; in autopilot Copilot turns it into a deny. Copilot denies a call whose hook crashes or exits non-zero, but runs one whose hook times out; `openmoat init` sets `timeoutSec` to 600, far above the guard's own 30 s deadline. `disableAllHooks` in `~/.copilot/settings.json` or a repository's `.github/copilot/settings*.json` turns every hook off; agents are denied writing them, and `openmoat doctor` and `openmoat status` report Copilot as not protected while your `settings.json` sets it and warn about a repository that sets it or carries `.github/hooks/*.json`. The MCP servers in `~/.copilot/mcp-config.json` and a project's `.mcp.json` and `.github/mcp.json` are pinned; a call is traced to its server by the `<server>-` prefix of its tool name | `~/.copilot/hooks/openmoat.json` (or `$COPILOT_HOME/hooks/`) |
| pi | Every tool, through OpenMoat's extension and pi's `tool_call` event, calls a `codemode` script makes included: `bash`, `powershell` (`unparseable`), `read`, `write`, `edit`, `grep`, `find`, `ls` (each `path` read as pi reads it: a leading `@` dropped, `~` the home), MCP tools (`mcp__<server>__<tool>`), `read_mcp_resource`; `codemode` and `tool_search` themselves touch nothing; any other tool (an extension's) is `tool.unknown`, checked for the paths, URLs and commands its input names, so one naming a secret is denied. An `ask` is a pi dialog; in print and JSON mode, which have no screen, it blocks the call until you run `openmoat` or `openmoat allow --last`. pi has no approval step of its own, so a deferred call runs. An extension that throws, or a guard that takes over 45 s, blocks the call. pi loads every file in `extensions/` on start: restart pi after `openmoat init`. `pi --no-extensions`, or an `extensions` entry in pi's or a trusted project's settings that turns OpenMoat's extension off, leaves calls unchecked: `openmoat status` and `openmoat doctor` report such an entry (not the flag) and warn about a project's `.pi/settings.json` and `.pi/extensions/`. The MCP servers in `~/.pi/agent/mcp.json` and a project's `.pi/mcp.json` are pinned | `~/.pi/agent/extensions/openmoat.js` (OpenMoat's own file) |
| Gemini CLI | `BeforeTool` for every tool (matcher `*`): `run_shell_command` (in its `dir_path`, which never decides the project; PowerShell on Windows: `unparseable`), `read_file`, `write_file`, `replace`, `list_directory`, `glob` and `grep_search` (the directory searched, and where a `glob` pattern or a `grep_search` `include_pattern` climbs to; without `dir_path` Gemini CLI searches every workspace directory, which the hook does not name, so the call asks), `read_many_files` (each `include` up to its first wildcard; it reads every workspace directory, so it asks), `web_fetch` (the one URL in its prompt, as `fetch`; a prompt with several is refused, so fetch each in its own call), `google_web_search` (as `web.search`), `read_mcp_resource` (a `file:` URI as a read), MCP tools (`mcp_<server>_<tool>`, named `mcp__<server>__<tool>`; each server in `mcpServers` pinned); its to-do, tracker, plan-mode, skill and subagent tools are not governed (a subagent's own tool calls are), and any other tool is `tool.unknown`, checked for the paths, URLs and commands its arguments name. An `ask` is Gemini CLI's own confirmation, even in YOLO mode; an `allow` skips none of Gemini CLI's own confirmations. Gemini CLI has no fail-closed setting: a hook that times out (600 s), is killed by a signal or exits 1 lets the call run, while a missing `openmoat` (the shell exits 127) blocks it. In a folder Gemini CLI does not trust it runs no settings hooks and asks before every tool. `openmoat status` and `openmoat doctor` warn about a project's `.gemini/settings.json` that turns hooks off, adds hooks, sets a tool discovery command or starts MCP servers, and report Gemini CLI as not protected while your own `settings.json` turns OpenMoat's hook off (`hooksConfig.enabled: false`, or `openmoat` in `hooksConfig.disabled`). `openmoat init` refuses a `settings.json` with comments, which Gemini CLI allows: move them out first. When Gemini CLI saves its own `settings.json` for `/model`, `/theme`, a sign-in choice or a display toggle, `openmoat doctor` reports the change and calls are still checked ([POLICY.md](POLICY.md#8-the-policy-lock)); any other change to that file denies every call until you run `openmoat doctor --accept`. `GEMINI_CLI_HOME` moves the home directory `.gemini` is in | `~/.gemini/settings.json` |
| OpenCode | OpenCode 1 (`opencode-ai`, 1.3.4 and later) and OpenCode 2 (`@opencode/cli`), through one plugin of OpenMoat's (ADR-039) on OpenCode 1's `tool.execute.before` and OpenCode 2's `execute.before` hook; `openmoat status` and `openmoat doctor` name the one the `opencode` on your search path runs, and an upgrade from 1 to 2 needs no new `openmoat init`. Every tool, subagents' calls included: `bash` (OpenCode 1) and `shell` (OpenCode 2), in their `workdir`, which never decides the project (on Windows, where they may run Git Bash, PowerShell or `cmd`: `unparseable`), `read`, `write`, `edit`, `apply_patch` (1) and `patch` (2) (every file the patch names), `glob` and `grep` (the directory searched, and where a pattern climbs to), `lsp` (1), `webfetch` (as `fetch`), `websearch` (as `web.search`), `opencode_worktree_remove` (2, a write of the worktree), MCP tools (`<server>_<tool>`, named `mcp__<server>__<tool>` from the server names in OpenCode's configuration; each server under `mcp` or `mcp.servers` pinned), `read_mcp_resource`; `task` (1), `subagent` (2), `todowrite`, `skill`, `question` and Code Mode's `execute` are not governed (a subagent's and Code Mode's own calls are); any other tool (a plugin's or custom tool's) is checked for the paths, URLs and commands its arguments name. Paths are read as OpenCode opens them: a relative one in the project; OpenCode 2 expands a leading `~`, OpenCode 1 does not. On OpenCode 2 an `ask` is OpenCode's own permission prompt (the action `openmoat`, with OpenMoat's reason; `--auto` approves it as it approves OpenCode's own); OpenCode 1 has no way for a plugin to ask, so there an `ask` blocks the call until you run `openmoat` or `openmoat allow --last`. A deferred call is left to OpenCode's own permission rules. A plugin that throws, or a guard that takes over 45 s, blocks the call; so does another plugin that changes a call after OpenMoat checked it. OpenCode loads every file in `plugins/` on start: restart OpenCode (on OpenCode 2, its background service: `opencode service restart`) after `openmoat init`. OpenCode 1's `--pure` and `OPENCODE_PURE=1`, OpenCode 2's `-openmoat` (or `-*`) in a configuration's `plugins` or a `policies` entry denying OpenMoat's plugin, or an error loading the plugin leaves calls unchecked: agents are denied starting OpenCode that way or writing your own configuration, writing a project's asks, `openmoat status` and `openmoat doctor` report OpenCode as not protected while your `opencode.json[c]` removes the plugin and warn about a project that does, about a project's `.opencode/plugins/` and what its `opencode.json` sets. OpenCode before 1.3.4 loads no plugin of this kind: `openmoat init` does not set it up, and `openmoat status` and `openmoat doctor` report it as not protected (told by `opencode --version`). `XDG_CONFIG_HOME` and `OPENCODE_CONFIG_DIR` are followed when `openmoat init` runs and recorded | `~/.config/opencode/plugins/openmoat.js` (OpenMoat's own file; in `OPENCODE_CONFIG_DIR` when that is set) |
| Hermes Agent | `pre_tool_call` for every tool (no matcher), `fail_closed: true`, 60 s: `terminal` (in its `workdir`, which never decides the project; a command that leaves the session's shell where OpenMoat cannot know asks), `read_file`, `write_file`, `patch` (every file a V4A patch names), `search_files` (the directory searched, and where a file-search `pattern` climbs to), `web_search` (as `web.search`), `web_extract` (one URL as `fetch`, several as an unknown tool), `browser_navigate` (as `net`), `execute_code` (`unparseable`; each tool the script calls fires the hook on its own), `process_manage` input to a running process and `cronjob_manage` changes (both ask), MCP tools (`mcp__<server>__<tool>`; each server in `mcp_servers` pinned); its to-do, clarify, session-search, skill-list, subagent and terminal-reading tools are not governed, and any other tool (`memory`, `skill_manage`, the other browser tools) is `tool.unknown`, checked for the paths, URLs and commands its arguments name. The payload's `cwd` is the Hermes process's, not the session's, so a file tool's relative path asks. `openmoat init` also approves the hook's exact command in `shell-hooks-allowlist.json`, without which Hermes's gateway, cron and ACP sessions skip it; `openmoat status` and `openmoat doctor` report a hook it does not approve. It edits `config.yaml` as text, keeping your comments, and refuses a `hooks:` written on one line or a quoted key, printing the entry to add by hand. An `ask` is Hermes's own approval prompt; where Hermes would approve it unseen (`HERMES_YOLO_MODE`, which `--yolo` sets, `approvals.mode: off`, or a cron, single-query or unattended mode set to `approve`) it is a deny you approve with `openmoat allow --last`; the in-session `/yolo` and `hermes -z` are not visible. A change to `config.yaml` other than `model`, `display`, `_config_version` or `mcp_servers` (pinned server by server), and any change to the allowlist, denies every call until you run `openmoat doctor --accept`. `HERMES_HOME` moves the home (default `~/.hermes`, `%LOCALAPPDATA%\hermes` on Windows); a profile (`~/.hermes/profiles/<name>`) is protected only when `openmoat init` runs with `HERMES_HOME` naming it | `~/.hermes/config.yaml` |
| Continue CLI (`cn`) | Runs the Claude Code hook, recorded as host `continue`. `cn` ignores an `ask`, so an `ask` blocks the call until you run `openmoat allow --last`. The released `cn` does not run hooks, so nothing is checked until it does; use `openmoat run` (`openmoat doctor` warns) | Claude Code's |

## Undo with `openmoat uninstall`

```bash
openmoat uninstall                    # every agent; --hosts codex for one
openmoat uninstall --purge            # also delete ~/.moat (policy, lock, audit log)
```

`openmoat uninstall` removes OpenMoat's hooks and sandbox settings from each agent and
prints what it did per file. When the file is otherwise unchanged since `openmoat init`,
the backup `init` took is written back byte for byte; a file `init` created is
deleted; a file you changed since keeps your changes and only loses OpenMoat's
entries (its backup stays next to it). The lock stops pinning those files, the proxy
service is removed if you installed it, and wrapped MCP servers are pointed back at their
own commands. `~/.moat`
stays unless you pass `--purge`. Like `openmoat allow`, it runs only from a terminal, and
the default policy denies it to agents (`kernel-self`).

## Upgrading

Upgrade the binary the way you installed it:

```bash
brew update && brew upgrade openmoat                              # Homebrew: update the tap first
cargo install openmoat --locked --force                       # crates.io
```

The Homebrew formula was renamed from `moat` to `openmoat`; `brew upgrade` follows the
rename. With the installers, run the installer again: its URL always fetches the latest release.
From a clone, pull and run `cargo install --locked --path crates/openmoat-cli` again.

Keep one OpenMoat installed. If an older binary is left elsewhere (a Homebrew install
beside a `cargo install`), point every agent at the new one with `openmoat init`, run by
that binary's full path, and restart the agents: an agent keeps the hook command it read
when it started, and an older binary denies every call over a lock written by a newer
release (from 0.9.0 the lock also records state files that do not exist yet, which an
older binary reads as files gone missing).

From a release before 0.9.0, run `openmoat init` once and restart your agents. The
[CHANGELOG](../CHANGELOG.md) lists what 0.9.0 breaks: MCP tools are held once, session
grants need approving again, repository policies and packs must be signed again in their
new namespaces, and a host allowed without a port is reached on 443 and 80 only.

Then, in a terminal of your own:

1. **`openmoat doctor`.** After an upgrade in the same place the hooks keep working, because
   they run `openmoat` by its stable path (ADR-016), and nothing has to be re-pinned. Doctor
   names what is left, if anything:
   - `hook entry for … is out of date (written by an older OpenMoat); run openmoat init`: the new
     release writes its hook entry differently (more tools, another timeout, a new event).
     Run `openmoat init`. It keeps your policy, backs up the agent's file before it changes
     OpenMoat's own entry, and re-pins.
   - `hook runs …, which does not exist`, `a different OpenMoat binary than this one`, or
     `lock expects …, running …`: `openmoat` now lives at another path (another
     install method, another Cargo `--root`). Run `openmoat init` with the `openmoat` the hooks
     should use, and `openmoat proxy install` again if the proxy runs as a service
     ([Upgrade note](#upgrade-note)).
   - a sandbox line ending `run openmoat sandbox sync`: the new release writes the agents'
     sandbox settings differently. Run `openmoat sandbox sync`.
   - `policy update  N changes from the OpenMoat … default`: see step 2.

   Re-run `openmoat init` only when doctor asks for it.
2. **`openmoat policy upgrade`.** `openmoat init` and an upgrade keep your `policy.yaml` as it
   is, so rules the new default policy gained, security fixes among them, reach you only
   this way. It shows the diff and asks; `--dry-run` only shows it, `--undo` puts the
   previous policy back ([USAGE.md](USAGE.md#after-upgrading-openmoat)). `openmoat` alone
   offers the same at a terminal.

### What can change between 0.x minor releases

Before 1.0 a minor release (0.5 → 0.6) may change things a patch release does not.
Read the [CHANGELOG](../CHANGELOG.md) entries since your version first; so far these
kinds of change have happened:

- **The audit log schema moves forward** (version 3 in 0.5.0, version 4 in 0.6.0). The
  new `openmoat` updates the log when it first opens it; an older `openmoat` then refuses to
  open it (`schema too new`), and its hook denies every call. Going back to an older
  release is not supported.
- **The default policy changes.** In 0.5.0, calls no rule names moved from `ask` to
  `defer` (the agent's own prompt decides, ADR-025). Your policy keeps its own rules
  until you run `openmoat policy upgrade`.
- **Hook entries change.** `openmoat doctor` then says the hook is out of date, and
  `openmoat init` rewrites it (step 1).
- **The library crates' API** (`openmoat-core`, `openmoat-hosts`, `openmoat-audit`,
  `openmoat-proxy`) breaks in minor releases, marked **Breaking** in the CHANGELOG. This
  matters only to Rust code that depends on them; the `openmoat` command is not affected.
- **The minimum Rust version** for `cargo install` is raised only in a minor release.

The policy format and the commands may still change before 1.0
([README](../README.md#status)); every such change has a CHANGELOG line.

## Keep `openmoat proxy` running as a user service

The egress proxy records every connection and injects brokered secrets. The
host sandboxes `openmoat init` configures send their commands' traffic through
it when the policy sets `sandbox.proxy_port`, so a stopped proxy leaves
sandboxed `npm install`, `cargo build` and `git fetch` without network. To
keep it up without opening a terminal every time, install it as a per-user
service (#272):

```bash
openmoat proxy install     # macOS: launchd user agent at ~/Library/LaunchAgents/dev.openmoat.proxy.plist
                       # Linux: systemd user unit at ~/.config/systemd/user/moat-proxy.service
openmoat proxy status      # not installed | stopped | running | drift-blocked | crashlooping
openmoat proxy uninstall   # stop and remove the service
```

The service restarts on failure (`KeepAlive = {SuccessfulExit=false}` on
macOS; `Restart=on-failure` on Linux). A policy-lock drift is a clean exit
(code 64), not a crash, so the service deliberately stops instead of
loop-restarting into the same error; `openmoat doctor` names the problem and
the fix. `openmoat sandbox sync` restarts the service after re-pinning the
lock so the proxy picks up the new policy (which it reads once at
start-up). `openmoat uninstall` removes the service alongside the hooks, so
a stale service never keeps listening with a reference to a gone binary.

Windows has no user service yet (#272): `openmoat proxy install` and `openmoat proxy
status` refuse with exit 64 and say to run `openmoat proxy` in a terminal.

The plist/unit holds only `MOAT_HOME` (a path, never a secret) and the
pinned `openmoat` binary. On Linux the file is written owner-only (`0o600`);
on macOS the `LaunchAgents` directory already restricts access to the
user. Token values the policy brokers are read from the user's
environment at run time by the proxy itself; they never touch the service
file.

### Upgrade note

The service names the pinned `openmoat` by its stable path (ADR-016), so an
upgrade through Homebrew or a cargo-install swap keeps working as long as
the stable path still resolves to the new binary. After a reinstall at a
different path (a Cargo change of `--root`, say), run `openmoat proxy install`
again so the service file names the new path.

## Teams: managed settings

`openmoat init` writes OpenMoat's Claude Code hooks to the user `settings.json`. A
repository's `.claude/settings.json` can turn every user-level hook off with
`"disableAllHooks": true`, and Claude Code loads it when a session starts, before any
hook runs. OpenMoat blocks such a change mid-session and `openmoat doctor` and `openmoat status`
warn about it, but cannot stop it at start (THREAT_MODEL §5). Only Claude Code's
[managed settings](https://code.claude.com/docs/en/managed-settings), which an
administrator deploys and the user cannot edit, make the hooks immune: a `disableAllHooks`
outside them cannot turn off a hook set in them. For teams:

1. Copy the `PreToolUse` and `ConfigChange` entries `openmoat init` wrote to
   `~/.claude/settings.json` (they run `openmoat` by its stable path, ADR-016) into the
   managed settings file, and keep them in the user file too, which `openmoat doctor`
   checks.
2. Add `"allowManagedHooksOnly": true` there to also block user, project, local and
   plugin hooks (except plugins the managed settings force on) and to take `statusLine`
   and file suggestion commands only from managed settings.

OpenMoat does not write or pin managed settings; whoever deploys them keeps them in step
with `openmoat init` after an upgrade that changes the hook entries.

## Non-default config directories

`openmoat` finds each agent's configuration the way the agent does: the variable in the
table replaces the agent's directory, and `MOAT_HOME` replaces `~/.moat`. OpenClaw also
follows `OPENCLAW_HOME` and `OPENCLAW_CONFIG_PATH` (see the hosts table above). pi's
hook file is OpenMoat's extension itself, in the `extensions/` of pi's agent directory.
`GEMINI_CLI_HOME` names the directory Gemini CLI uses as the home, so its settings are
in `$GEMINI_CLI_HOME/.gemini`. OpenCode's directory is `opencode` in `XDG_CONFIG_HOME`
when that is set (as for every program that follows the XDG layout), else
`~/.config/opencode`. When `OPENCODE_CONFIG_DIR` is set, OpenCode 2 reads it in place of
that directory and OpenCode 1 reads it as well, so `openmoat init` puts OpenMoat's plugin
there and both load it. Hermes Agent's home is
`%LOCALAPPDATA%\hermes` on Windows unless `HERMES_HOME` names another, and
`HERMES_DATA_DIR_SUFFIX` is added to the default's name; a Hermes profile is a home of
its own (`HERMES_HOME=~/.hermes/profiles/<name>`). The
table is generated from each agent's `HostSpec` (`OPENMOAT_TEST_UPDATE_DOCS=1 cargo test
-p openmoat-hosts --test docs`); do not edit it.

<!-- generated:hosts-install -->
| Agent | Directory | Moved by | Hook file | Entries `openmoat init` writes |
|---|---|---|---|---|
| Claude Code | `~/.claude` | `CLAUDE_CONFIG_DIR` | `settings.json` | `PreToolUse` (600 s), `ConfigChange` (60 s) |
| Codex | `~/.codex` | `CODEX_HOME` | `hooks.json` | `PreToolUse` (600 s) |
| Cursor | `~/.cursor` | `CURSOR_CONFIG_DIR` | `hooks.json` | `beforeShellExecution` (600 s), `beforeMCPExecution` (600 s), `beforeReadFile` (600 s), `preToolUse` (600 s) |
| OpenClaw | `~/.openclaw` | `OPENCLAW_STATE_DIR` | `openclaw.json` | `before_tool_call` (60 s) |
| GitHub Copilot CLI | `~/.copilot` | `COPILOT_HOME` | `hooks/openmoat.json` | `preToolUse` (600 s) |
| pi | `~/.pi/agent` | `PI_CODING_AGENT_DIR` | `extensions/openmoat.js` | `tool_call` (45 s) |
| Gemini CLI | `~/.gemini` | `GEMINI_CLI_HOME` | `settings.json` | `BeforeTool` (600 s) |
| OpenCode | `~/.config/opencode` | `XDG_CONFIG_HOME` | `plugins/openmoat.js` | `tool.execute.before` (45 s), `execute.before` (45 s) |
| Hermes Agent | `~/.hermes` | `HERMES_HOME` | `config.yaml` | `pre_tool_call` (60 s) |
<!-- /generated -->

If you start Claude Code with `CLAUDE_CONFIG_DIR`
set, run `openmoat init` once with the same value. `init` records the directory of each
agent it sets up in `~/.moat/hosts.json` (pinned by the lock), and every later command
(`status`, `doctor`, `allow`, `sandbox sync`, `uninstall`) uses the recorded directory,
so you do not export the variables again. When a variable in your shell names another
directory than the record, `openmoat doctor` reports it instead of following it; run
`openmoat init` with the variable set to move OpenMoat to that directory. `MOAT_HOME` is
not recorded: it says where the record is.

Next: [USAGE.md](USAGE.md) for daily use, [SANDBOX.md](SANDBOX.md) for the OS sandboxes.
