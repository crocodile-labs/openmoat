# Install and set up OpenMoat

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you install or upgrade OpenMoat on macOS, Linux or Windows, run `openmoat init`, want to know what each agent's hook covers, or use other config directories.

**On this page:** [Install](#install) · [Set up with openmoat init](#set-up-with-openmoat-init) · [Install from an agent's plugin channel (preview)](#install-from-an-agents-plugin-channel-preview) · [Undo with openmoat uninstall](#undo-with-openmoat-uninstall) · [Upgrading](#upgrading) · [Keep openmoat proxy running as a user service](#keep-openmoat-proxy-running-as-a-user-service) · [Teams: managed settings](#teams-managed-settings) · [Non-default config directories](#non-default-config-directories)

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

# From crates.io (Rust 1.99)
cargo install openmoat --locked
```

Then run `openmoat init` ([below](#set-up-with-openmoat-init)).

> [!NOTE]
> **Windows.** On Windows, OpenMoat applies the policy through the agents' hooks. It
> sets up no OS sandbox for Claude Code or Cursor (Codex's own sandbox settings are
> written as on other systems), `openmoat run` starts a preview tier that refuses writes
> outside the project and ends the agent's processes, and holds reads and the network too
> once `openmoat agent-account setup` has run (a preview; [SANDBOX.md](SANDBOX.md#openmoat-run-on-windows-preview)), and `openmoat proxy` cannot
> be installed as a service. `openmoat init` gives the state directory an access list of
> your account and `SYSTEM` only (on an NTFS drive; it refuses a folder another account
> owns), which keeps other accounts out but not the agent, which runs as you: the hook's
> rules keep the agent out of it. The hook denies commands and
> paths that cross into WSL (`wsl`, `\\wsl$`), where no Windows path rule reaches. For
> full OS confinement, run the agent and `openmoat` inside WSL2 ([details below](#set-up-with-openmoat-init)).

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
> warns. CI tests macOS 15 on Apple silicon (`macos-15`); Intel Macs are not tested.
> GitHub Actions no longer offers `macos-13` or `macos-14` runners, so macOS 13 and 14
> are not tested. The
> hooks, `openmoat init`, `openmoat status` and `openmoat doctor` work on earlier macOS and
> still apply the policy to each tool call; only `openmoat run` has this floor.
>
> Homebrew itself no longer supports macOS 12 and earlier: `brew install` or
> `brew upgrade` may stop and ask for a newer Xcode or Command Line Tools than the
> system can run. Install with the shell installer or `cargo install` above
> instead; both put `openmoat` in `~/.cargo/bin`. Keep only one install (see
> [Upgrading](#upgrading)): after `brew uninstall openmoat`, run `openmoat init`
> once so the hooks point to the new binary.

To build from a clone instead (Rust 1.99, pinned by `rust-toolchain.toml`):

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
files in `~/.moat/policy.lock` and creates the audit log. Then it shows one line per
agent whose configuration directory exists, with what it would add there, and asks once
per agent. Answer `d` to see the full diff, then answer again. An agent whose files
already have everything is not asked: a yes would change nothing. It ends with each
agent's protection, the steps left to you (only the ones this run needs) and how to
undo:

```
OpenMoat 0.15.0 · protecting the agents on this machine

  Each file is backed up first · d shows the full diff · openmoat uninstall undoes it

  Claude Code  ~/.claude    adds hook + sandbox settings  Protect? [Y/n/d] y
  Codex        ~/.codex     adds hook + sandbox settings  Protect? [Y/n/d] y
  OpenClaw     ~/.openclaw  already set up                ✔

✔ 3 agents protected

  Agent        Protection
  Claude Code  ✔ hook + OS sandbox
  Codex        ✔ hook + OS sandbox
  OpenClaw     ✔ hook only

Next steps
  1. Codex: open Codex and trust OpenMoat's hooks in /hooks; Codex runs a changed hook only then
  2. Restart your agents (a new session reads the new settings)
  3. Try it: openmoat policy check "cat ~/.ssh/id_rsa"

Backups saved · undo everything: openmoat uninstall · check any time: openmoat status · details: openmoat init --verbose
```

`openmoat init --verbose` also prints, before each question, every file the agent would
get (new or edited, lines added and removed, the top-level settings it sets), and after
it each hook entry written, the backups and the files the lock pins.

Only the agents you accept get the hook and sandbox settings. `init` never overwrites an
existing policy, never duplicates a hook and backs up a host file before editing it
(`<file>.moat-backup` for hooks, `<file>.moat-sandbox-backup` for sandbox settings), so
it is safe to run again. The backups it creates are listed in `~/.moat/hosts.json`;
a file of yours that already has one of those names is left alone, and
`openmoat uninstall` never deletes it.

To choose without questions, name the agents: `openmoat init --hosts claude-code`, or
several comma-separated (each agent's id is in [FEATURES.md](FEATURES.md#each-agent) and
the README's agent table). `openmoat init --yes` sets up every agent found, for
scripts. Without a terminal and without `--yes` or `--hosts`, `init` changes no agent's
files and says how to go on. `openmoat init --dry-run` prints what would change first.
For provisioning scripts, `openmoat init --hooks-only --hosts <ids> --format json` writes
and pins only those agents' hooks, asks nothing and prints one JSON document
([USAGE.md](USAGE.md#init-for-scripts-hooks-only-and-json)).
At a terminal, `openmoat init` lists the stdio MCP servers in the agents' user
configuration, shows what would change (`d`) and asks before it runs them through OpenMoat;
`--no-mcp-proxy` skips the question, `n` is remembered for that definition, and `--yes` or
no terminal changes none of them. `openmoat init --mcp-proxy` runs every stdio MCP server in the agents' user
configuration through `openmoat mcp proxy`, which starts a server only from a definition a
person accepted, in `openmoat run`'s sandbox where it can sandbox (`--mcp-no-sandbox` opts
out), and pins each tool's description, schemas and annotations
(`openmoat mcp wrap` in [USAGE.md](USAGE.md#commands)).

`init` also pins every MCP server definition the agents load; the tool calls of a server
that changes later, or of a new one, are refused until you run `openmoat mcp accept`.

### Two choices `init` offers: decoy keys and sandboxed start

After the agents, `openmoat init` at a terminal asks two more questions. Both default to
no (Enter), `d` shows every file the yes would write, and `openmoat uninstall` takes them
back. `--yes`, `--dry-run`, `--hooks-only`, `--format json` and a run without a terminal
never ask and change nothing here (ADR-106).

```
  Decoy keys       plant 3 fake key file(s) (~/.aws/credentials.bak, ~/.git-credentials.bak, ~/.npmrc.bak) so that any attempt to read or send them is caught? No real file is touched  [y/N/d] y
✔ decoy keys       3 planted: ~/.aws/credentials.bak, ~/.git-credentials.bak, ~/.npmrc.bak; reading or sending one is denied (rule canary)
  Sandboxed start  make typing gemini, opencode start it in `openmoat run`'s sandbox? It writes 2 shim(s) to ~/.moat/bin and 2 lines to ~/.zshrc  [y/N/d] y
✔ sandboxed start  gemini, opencode: shims in ~/.moat/bin; ~/.zshrc puts it first on PATH (backup ~/.zshrc.moat-backup); open a new shell to use it
```

- **Decoy keys.** Fake keys at names no program loads, beside the files a key hunter
  looks for: `~/.aws/credentials.bak` (only when `~/.aws` exists), `~/.git-credentials.bak`
  and `~/.npmrc.bak`. Each is created only where nothing is at that name, readable by your account alone; no
  real file is read, changed or replaced. The keys look like real ones to a scanner and
  carry `OpenMoatDecoy`, so you can tell them apart. No real work touches them: a call
  that reads or changes one, or carries one of their values in a command, a URL, a file it
  writes or a request through `openmoat proxy`, is denied with rule `canary`, and
  `openmoat status`, `openmoat doctor` and `openmoat report` flag it. Which files are
  decoys is recorded in `~/.moat/canaries.json`, which agents may not read.
- **Sandboxed start.** Offered where `openmoat run` works (macOS 13 and later, Linux) for
  each hook-only agent it can start (Gemini CLI, OpenCode, Hermes Agent, …; the agents
  with an OS sandbox of their own already have one). It writes a shim per agent in
  `~/.moat/bin` that runs `openmoat run` around the real program, both by absolute path,
  and, on the same yes, two lines at the end of your shell's start-up file (`~/.zshrc`;
  `~/.bash_profile` on macOS or `~/.bashrc` for bash) that put `~/.moat/bin` first on
  `PATH`, after backing the file up. For another shell it prints the line to add. Nothing
  changes how an agent starts until a new shell reads that line. `openmoat status` and
  `openmoat doctor` say whether typing each agent's command starts it sandboxed in the
  current shell. Outside a project `openmoat run` refuses to start, as always; the shim
  names the real program if you need it there.

Hooks run the `openmoat` you ran `openmoat init` with, by its stable path (ADR-016). After
moving or reinstalling the binary somewhere else, run `openmoat init` again; `openmoat doctor`
names a hook whose binary is missing or is a different `openmoat`.

An agent can stop running the hook without a word: an update, a setting that turns hooks
off, or a session started before `init`. When Claude Code, Codex, the Cursor CLI, GitHub
Copilot CLI, Gemini CLI or Qwen Code wrote sessions since its hook, settings or program
last changed and none of its calls reached OpenMoat, `openmoat status` and `openmoat
doctor` warn and say what to do; restart the agent first
([USAGE.md](USAGE.md#does-the-agent-still-run-openmoats-hook)).

On native Windows, `init` does not turn on Claude Code's sandbox: it runs on macOS,
Linux and WSL2 only, and Claude Code would not start with it required. The hook still
applies the policy to Claude Code's tool calls, and `init`, `doctor` and `status` say so. For OS
confinement, run Claude Code and `openmoat` inside WSL2. Codex's sandbox is set up as on
other systems; Cursor's `sandbox.json` is not written, because Cursor documents its
sandbox for macOS and Linux only.

On Linux, the sandboxes `init` turns on need what each agent documents: Claude Code
needs bubblewrap and socat (`sudo apt-get install bubblewrap socat` on Debian and
Ubuntu, `sudo dnf install bubblewrap socat` on Fedora), and Claude Code, Codex and
Cursor all need to create user namespaces as you, which Ubuntu 23.10 and later restrict
through AppArmor by default (`kernel.apparmor_restrict_unprivileged_userns=1`). Each
agent's documentation gives a different AppArmor fix, and Claude Code's sandbox fails
under the `bwrap-userns-restrict` profile Codex's suggests, so follow the one `openmoat
doctor` names for each agent. If an
agent's commands all fail after `openmoat init`, run `openmoat doctor`: it says which
agent's sandbox cannot start commands here and why, with the fixes
([SANDBOX.md](SANDBOX.md#what-each-agents-sandbox-needs-on-linux)).

On native Windows, `openmoat doctor` also shows which of its Windows sandbox modes Codex's
`config.toml` selects (`[windows] sandbox`, `[features] prefer_mxc`). Codex's MXC and
`elevated` modes enforce the read denies OpenMoat writes; its `unelevated` mode does not
(Codex's documentation: it "doesn't support denied read paths"), so there they hold only
through the hook, and `doctor` warns and names the stronger setting. With WSL installed,
`doctor` names WSL2 as the way to OS confinement; inside WSL1 it says that `openmoat run`
and the agents' sandboxes need WSL2 (ADR-083).

Codex runs a new or changed hook only once you trust it: after `openmoat init`, open
Codex, run `/hooks` and trust both OpenMoat hooks (OpenMoat supports Codex 0.160.1 to
0.166.0). Existing args-style entries are broken: `init`, `policy upgrade`
and `sandbox sync` rewrite them as one command string and re-pin the lock. Trust the
replacement again. `status` and `doctor` report an args-style entry as a failure
(`openmoat init` repairs it), and read Codex's separate trust record to report an
installed but not trusted hook as an advisory warning. This hash mirror never blocks
calls or commands. See [Codex's host contract](../crates/openmoat-hosts/src/host/codex/HOST.md).

| Agent | What is hooked | Hook file |
|---|---|---|
| Claude Code | `PreToolUse`: `Bash`, `Monitor`, `PowerShell` (never parsed: `unparseable`), `Read`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, `LSP`, `SendFile`, `Artifact` and `ArtifactData` (the local files they upload or save), `WebFetch` (as `fetch`), `WebSearch` (as `web.search`), `ReadMcpResourceTool` (a `file:` URI as a read, any other as its host), `EnterWorktree` (an existing worktree's `path` as a read; a new worktree, and `Skill`, are left to Claude Code), MCP tools, and in VS Code and JetBrains the editor's `getDiagnostics` (a read of the file it names) and `executeCode` (review). The same hook covers the VS Code extension and the JetBrains plugin; `openmoat init` reads the extension's bundled Claude Code for `onFailure` ([IDE.md](IDE.md)). `ConfigChange`: user, project and local settings. `SessionStart`: each session's credential for `openmoat proxy` (ADR-044). `PostToolUse` (since 0.16.0): what `Bash`, `WebFetch`, `WebSearch`, `ReadMcpResourceTool` and MCP tools returned, read for `injected-input` (ADR-057); it decides nothing itself | `~/.claude/settings.json` |
| Codex | `PreToolUse`: shell commands, `apply_patch` (every file the patch names), MCP tools. Codex hooks cannot prompt (`PermissionRequest` runs only when Codex itself prompts), so a `review` blocks the call until you run `openmoat` or `openmoat allow --last`, for `apply_patch` too. Codex does not hook web search or hosted tools. Codex skips a new or changed user hook until you review and trust it in `/hooks` ([hooks docs](https://learn.chatgpt.com/docs/hooks)): after `openmoat init` (and after an upgrade that rewrites the entry), open `/hooks` in Codex and trust OpenMoat's (`openmoat init` and `openmoat doctor` remind you). `[features] hooks = false` in `config.toml` turns every hook off: `openmoat status` and `openmoat doctor` report Codex as not protected while yours sets it, and warn about a trusted project's `.codex/config.toml` or `.codex/hooks.json` that turns hooks off, adds hooks or starts programs | `~/.codex/hooks.json` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `beforeTabFileRead` (Tab's reads: a secret is denied, any other file allowed), `preToolUse` (`Read`, `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete`, `Grep`, `Glob`, `WebSearch`, `WebFetch`, and any other tool: one that names a path is checked against it, one that does not is decided as `tool.unknown`); installed with `failClosed`. Cursor prompts on its `ask` only for shell and MCP calls, so a `review` on `preToolUse` or `beforeReadFile` is sent as a deny until you run `openmoat` or `openmoat allow --last`. `openmoat init` also writes Cursor's own sandbox settings (`sandbox.json`) on macOS and Linux; Cursor still runs a command outside that sandbox when its Auto-review classifier approves it, in Run Everything mode, and in the CLI without `--sandbox enabled` ([SANDBOX.md](SANDBOX.md#cursors-sandbox)) | `~/.cursor/hooks.json`, `~/.cursor/sandbox.json` |
| OpenClaw | Every tool, through OpenMoat's plugin and OpenClaw's `before_tool_call` hook: `exec` (PowerShell on Windows: `unparseable`), `read`, `write`, `edit`, `apply_patch`, `web_fetch`, `web_search`, `browser` `open`/`navigate`/`upload`, MCP tools (`<server>__<tool>`; each server in `mcp.servers` pinned), `gateway config.get`, `plugins` changes (as a write to `openclaw.json`), `cron` jobs added or updated (review, `runs-later`), `view_image` (a file read, or a fetch of one URL), `nodes` `invoke` (`unparseable`); `process` input is `unparseable`; any other tool is `tool.unknown`, checked for the paths, URLs and commands its arguments name. `exec`'s `workdir` is where the command runs, never the project. A `review` becomes OpenClaw's own approval request; a hook that throws or takes over 60 s blocks the call. `openclaw.json` is read as JSON5 and written back as plain JSON (values kept, formatting not); `openmoat init` refuses a file with comments, which that would drop: move them out of the file first. `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR` and `OPENCLAW_CONFIG_PATH` are followed when `openmoat init` runs and recorded; run `init` again after changing them. An `$include` that may bring MCP servers holds back every OpenClaw MCP call. Restart the Gateway after `openmoat init` | `~/.openclaw/openclaw.json` (or `OPENCLAW_CONFIG_PATH`), `<state dir>/openmoat/openmoat.mjs` |
| GitHub Copilot CLI | `preToolUse` for every tool, in a hook file of OpenMoat's own (Copilot loads every `*.json` in its hooks directory): `bash` (a command that leaves Copilot's shell, which later calls reuse, in a directory OpenMoat cannot know needs review), `write_bash` and `write_powershell` (input typed into a running shell: checked on its own and needs review), `powershell` (`unparseable`), `view`, `create`, `edit`, `str_replace_editor`, `apply_patch` (every file the patch names), `grep`, `glob`, `web_fetch` (as `fetch`), `web_search`; any other tool, MCP tools included, is checked by the paths and URLs its arguments name and by the shell commands under a command key. A `review` is Copilot's own prompt; in autopilot Copilot turns it into a deny. Copilot denies a call whose hook crashes or exits non-zero, but runs one whose hook times out; `openmoat init` sets `timeoutSec` to 600, far above the guard's own 30 s deadline. `disableAllHooks` in `~/.copilot/settings.json` or a repository's `.github/copilot/settings*.json` turns every hook off; agents are denied writing them, and `openmoat doctor` and `openmoat status` report Copilot as not protected while your `settings.json` sets it and warn about a repository that sets it or carries `.github/hooks/*.json`. The MCP servers in `~/.copilot/mcp-config.json` and a project's `.mcp.json` and `.github/mcp.json` are pinned; a call is traced to its server by the `<server>-` prefix of its tool name | `~/.copilot/hooks/openmoat.json` (or `$COPILOT_HOME/hooks/`) |
| pi | Every tool, through OpenMoat's extension and pi's `tool_call` event, calls a `codemode` script makes included: `bash`, `powershell` (`unparseable`), `read`, `write`, `edit`, `grep`, `find`, `ls` (each `path` read as pi reads it: a leading `@` dropped, `~` the home), MCP tools (`mcp__<server>__<tool>`), `read_mcp_resource`; `codemode` and `tool_search` themselves touch nothing; any other tool (an extension's) is `tool.unknown`, checked for the paths, URLs and commands its input names, so one naming a secret is denied. A `review` is a pi dialog; in print and JSON mode, which have no screen, it blocks the call until you run `openmoat` or `openmoat allow --last`. pi has no approval step of its own, so a deferred call runs. An extension that throws, or a guard that takes over 45 s, blocks the call. pi loads every file in `extensions/` on start: restart pi after `openmoat init`. `pi --no-extensions`, or an `extensions` entry in pi's or a trusted project's settings that turns OpenMoat's extension off, leaves calls unchecked: `openmoat status` and `openmoat doctor` report such an entry (not the flag) and warn about a project's `.pi/settings.json` and `.pi/extensions/`. The MCP servers in `~/.pi/agent/mcp.json` and a project's `.pi/mcp.json` are pinned | `~/.pi/agent/extensions/openmoat.js` (OpenMoat's own file) |
| Gemini CLI | `BeforeTool` for every tool (matcher `*`): `run_shell_command` (in its `dir_path`, which never decides the project; PowerShell on Windows: `unparseable`), `read_file`, `write_file`, `replace`, `list_directory`, `glob` and `grep_search` (the directory searched, and where a `glob` pattern or a `grep_search` `include_pattern` climbs to; without `dir_path` Gemini CLI searches every workspace directory, which the hook does not name, so the call needs review), `read_many_files` (each `include` up to its first wildcard; it reads every workspace directory, so it needs review), `web_fetch` (the one URL in its prompt, as `fetch`; a prompt with several is refused, so fetch each in its own call), `google_web_search` (as `web.search`), `read_mcp_resource` (a `file:` URI as a read), MCP tools (`mcp_<server>_<tool>`, named `mcp__<server>__<tool>`; each server in `mcpServers` pinned); its to-do, tracker, plan-mode, skill and subagent tools are not governed (a subagent's own tool calls are), and any other tool is `tool.unknown`, checked for the paths, URLs and commands its arguments name. A `review` is Gemini CLI's own confirmation, even in YOLO mode; an `allow` skips none of Gemini CLI's own confirmations. Gemini CLI has no fail-closed setting: a hook that times out (600 s), is killed by a signal or exits 1 lets the call run, while a missing `openmoat` (the shell exits 127) blocks it. In a folder Gemini CLI does not trust it runs no settings hooks and asks before every tool. `openmoat status` and `openmoat doctor` warn about a project's `.gemini/settings.json` that turns hooks off, adds hooks, sets a tool discovery command or starts MCP servers, and report Gemini CLI as not protected while your own `settings.json` turns OpenMoat's hook off (`hooksConfig.enabled: false`, or `openmoat` in `hooksConfig.disabled`). `openmoat init` refuses a `settings.json` with comments, which Gemini CLI allows: move them out first. When Gemini CLI saves its own `settings.json` for `/model`, `/theme`, a sign-in choice or a display toggle, `openmoat doctor` reports the change and calls are still checked ([POLICY.md](POLICY.md#8-the-policy-lock)); any other change to that file denies every call until you run `openmoat doctor --accept`. `GEMINI_CLI_HOME` moves the home directory `.gemini` is in | `~/.gemini/settings.json` |
| OpenCode | OpenCode 1 (`opencode-ai`, 1.3.4 and later) and OpenCode 2 (`@opencode/cli`), through one plugin of OpenMoat's (ADR-040) on OpenCode 1's `tool.execute.before` and OpenCode 2's `execute.before` hook; `openmoat status` and `openmoat doctor` name the one the `opencode` on your search path runs, and an upgrade from 1 to 2 needs no new `openmoat init`. Every tool, subagents' calls included: `bash` (OpenCode 1) and `shell` (OpenCode 2), in their `workdir`, which never decides the project (on Windows, where they may run Git Bash, PowerShell or `cmd`: `unparseable`), `read`, `write`, `edit`, `apply_patch` (1) and `patch` (2) (every file the patch names), `glob` and `grep` (the directory searched, and where a pattern climbs to), `lsp` (1), `webfetch` (as `fetch`), `websearch` (as `web.search`), `opencode_worktree_remove` (2, a write of the worktree), MCP tools (`<server>_<tool>`, named `mcp__<server>__<tool>` from the server names in OpenCode's configuration; each server under `mcp` or `mcp.servers` pinned), `read_mcp_resource`; `task` (1), `subagent` (2), `todowrite`, `skill`, `question` and Code Mode's `execute` are not governed (a subagent's and Code Mode's own calls are); any other tool (a plugin's or custom tool's) is checked for the paths, URLs and commands its arguments name. Paths are read as OpenCode opens them: a relative one in the project; OpenCode 2 expands a leading `~`, OpenCode 1 does not. On OpenCode 2 a `review` is OpenCode's own permission prompt (the action `openmoat`, with OpenMoat's reason; `--auto` approves it as it approves OpenCode's own); OpenCode 1 has no way for a plugin to prompt, so there a `review` blocks the call until you run `openmoat` or `openmoat allow --last`. A deferred call is left to OpenCode's own permission rules. A plugin that throws, or a guard that takes over 45 s, blocks the call; so does another plugin that changes a call after OpenMoat checked it. OpenCode loads every file in `plugins/` on start: restart OpenCode (on OpenCode 2, its background service: `opencode service restart`) after `openmoat init`. OpenCode 1's `--pure` and `OPENCODE_PURE=1`, OpenCode 2's `-openmoat` (or `-*`) in a configuration's `plugins` or a `policies` entry denying OpenMoat's plugin, or an error loading the plugin leaves calls unchecked: agents are denied starting OpenCode that way or writing your own configuration, writing a project's configuration needs review, `openmoat status` and `openmoat doctor` report OpenCode as not protected while your `opencode.json[c]` removes the plugin and warn about a project that does, about a project's `.opencode/plugins/` and what its `opencode.json` sets. OpenCode before 1.3.4 loads no plugin of this kind: `openmoat init` does not set it up, and `openmoat status` and `openmoat doctor` report it as not protected (told by `opencode --version`). `XDG_CONFIG_HOME` and `OPENCODE_CONFIG_DIR` are followed when `openmoat init` runs and recorded | `~/.config/opencode/plugins/openmoat.js` (OpenMoat's own file; in `OPENCODE_CONFIG_DIR` when that is set) |
| Hermes Agent | `pre_tool_call` for every tool (no matcher), `fail_closed: true`, 60 s: `terminal` (in its `workdir`, which never decides the project; a command that leaves the session's shell where OpenMoat cannot know needs review), `read_file`, `write_file`, `patch` (every file a V4A patch names), `search_files` (the directory searched, and where a file-search `pattern` climbs to), `web_search` (as `web.search`), `web_extract` (one URL as `fetch`, several as an unknown tool), `browser_navigate` (as `net`), `execute_code` (`unparseable`; each tool the script calls fires the hook on its own), `process_manage` input to a running process and `cronjob_manage` changes (both need review), MCP tools (`mcp__<server>__<tool>`; each server in `mcp_servers` pinned); its to-do, clarify, session-search, skill-list, subagent and terminal-reading tools are not governed, and any other tool (`memory`, `skill_manage`, the other browser tools) is `tool.unknown`, checked for the paths, URLs and commands its arguments name. The payload's `cwd` is the Hermes process's, not the session's, so a file tool's relative path needs review. `openmoat init` also approves the hook's exact command in `shell-hooks-allowlist.json`, without which Hermes's gateway, cron and ACP sessions skip it; `openmoat status` and `openmoat doctor` report a hook it does not approve. It edits `config.yaml` as text, keeping your comments, and refuses a `hooks:` written on one line or a quoted key, printing the entry to add by hand. A `review` is Hermes's own approval prompt; where Hermes would approve it unseen (`HERMES_YOLO_MODE`, which `--yolo` sets, `approvals.mode: off`, or a cron, single-query or unattended mode set to `approve`) it is a deny you approve with `openmoat allow --last`; the in-session `/yolo` and `hermes -z` are not visible. A change to `config.yaml` other than `model`, `display`, `_config_version` or `mcp_servers` (pinned server by server), and any change to the allowlist, denies every call until you run `openmoat doctor --accept`. `HERMES_HOME` moves the home (default `~/.hermes`, `%LOCALAPPDATA%\hermes` on Windows); a profile (`~/.hermes/profiles/<name>`) is protected only when `openmoat init` runs with `HERMES_HOME` naming it | `~/.hermes/config.yaml` |
| Cline CLI | OpenMoat's script `PreToolUse` for every tool (Cline has no matcher), which prints Cline's `cancel` itself when `openmoat` is missing or fails (Cline runs a call whose hook fails), 120 s (Cline's own): `run_commands` (every command shape Cline accepts; several are decided together, each in a subshell, and need review when one cannot be read alone; PowerShell on Windows is not read), `read_files`, `editor`, `apply_patch` (every file the patch names), `search_codebase` (the workspace), `fetch_web_content` (one URL as `fetch`, several as an unknown tool), MCP tools (`<server>__<tool>`, recorded as `mcp__<server>__<tool>`; each server in `data/settings/cline_mcp_settings.json` pinned); `ask_question` and `submit_and_exit` are not governed, and any other tool (`skills`, subagent and team tools, a plugin's) is `tool.unknown`, checked for the paths, URLs and commands its arguments name. Cline's hooks cannot prompt: a `review` is a deny, which ends Cline's run, that you approve with `openmoat allow --last`. `--yolo` runs no hooks; the Cline VS Code extension reads hooks only from `~/Documents/Cline/Hooks` and is not covered. `CLINE_DIR` moves `~/.cline`. `PostToolUse` (since 0.17.0, the same script): what each call returned, read for `injected-input` (ADR-057; ADR-063, proposed); it prints nothing and decides nothing itself | `~/.cline/hooks/PreToolUse`, `~/.cline/hooks/PostToolUse` |
| goose | `PreToolUse` for every tool (no matcher), `on_failure: block`, 60 s, in OpenMoat's plugin: `shell` (`cmd` on Windows: `unparseable`), `write`, `edit`, `tree`, `analyze`, `read_image`, every extension tool (`<extension>__<tool>`, MCP extensions included), and a tool OpenMoat does not know by what its arguments name. goose hooks cannot prompt, so a `review` blocks the call until you run `openmoat allow --last`. Code Mode's `execute_javascript` needs review: the tools its script calls skip the hook | `~/.agents/plugins/openmoat/hooks/hooks.json` |
| Continue CLI (`cn`) | Runs the Claude Code hook, recorded as host `continue`. `cn` ignores Claude Code's `"ask"`, so a `review` blocks the call until you run `openmoat allow --last`. The released `cn` does not run hooks, so nothing is checked; use `openmoat run` (`openmoat doctor` warns). [Continue's repository](https://github.com/continuedev/continue) is no longer maintained and is read-only | Claude Code's |

## Install from an agent's plugin channel (preview)

> [!NOTE]
> **Preview.** The packages below are in the repository's
> [`plugins/`](../plugins/README.md) folder, generated from the host specs
> ([ADR-099](adr/ADR-099-plugin-packages.md)). None is listed in its channel yet; until
> one is, install it from the folder or keep using `openmoat init` alone.

Each agent below can take OpenMoat's hook from its own plugin channel in one step. A
package holds no binary and downloads nothing: you still install `openmoat` and run
`openmoat init` once, which writes the policy and its lock. The package runs
`openmoat guard --host <id> --plugin` with the `openmoat` the policy lock pins (`binary`
in `~/.moat/policy.lock`, the path `openmoat init` recorded). Before there is a lock it
looks in `~/.cargo/bin` and Homebrew's folder, then on the search path; the guard then
denies every call anyway.

- **No `openmoat`**, or it gives no answer: every call is blocked, and the message
  names the install command (`brew install crocodile-labs/tap/openmoat`, then
  `openmoat init`). A lock that names no program the package can run blocks every call
  too.
- **No policy lock** (`openmoat init` not run yet): every call is denied, and the reason
  says to run `openmoat init`.
- **`openmoat init`'s own hook installed for the agent as well**: the package gives no
  decision (on Cursor, `allow`, which never changes what the other hook answers), so
  each call is decided once, by `init`'s hook, which the lock pins and which runs the
  binary by its path. The package stands aside only when all of these hold:
  - the lock is intact;
  - it pins the hook file this agent reads, taken from the agent's own environment
    (its `CLAUDE_CONFIG_DIR` and the like, else the default folder), never from where
    `init` last ran;
  - OpenMoat's entry there is the one `init` wrote;
  - no settings file the agent reads, yours or the project's, turns that hook off;
  - for pi, OpenCode and OpenClaw, `init`'s plugin has itself reported loading since
    it last changed. A call the package decided does not count.

  Otherwise the package decides.
- **Only the package**: it decides each call as `init`'s hook would. Answer `n` for that
  agent in `openmoat init` to keep it that way.

`openmoat doctor` reports each package that ran: when, and whether it stood aside for
`init`'s hook or decided itself (`~/.moat/plugins/<id>.json`). The default policy's
`kernel-self` keeps an agent from changing the folder where its host keeps OpenMoat's
package, by that folder's name: another plugin's folder is left as it was.

**With a package alone**, without `openmoat init`'s hook:

- The package is outside the lock. The agent may update it, and you or a project's
  settings may turn it off, without OpenMoat seeing it.
- It decides only with the default state directory, `~/.moat`; a `MOAT_HOME` that names
  another one is denied. It finds the lock from the agent's `HOME`.
- A plugin's report that `init`'s plugin loaded stays valid until that plugin's file or
  the agent's program changes; it says nothing about the process now running.
- The guard scripts are POSIX `sh`, so on native Windows use `openmoat init`.

`openmoat init`'s hook names its binary and state directory itself and is pinned by the
lock, so it stays the setup to rely on.

### Claude Code

```bash
claude plugin marketplace add crocodile-labs/openmoat-plugins
claude plugin install openmoat@crocodile-labs
```

The plugin (`plugins/claude-code`) carries the four hooks `openmoat init` writes, with
`onFailure: "block"` (Claude Code 2.1.295 or later). Before the marketplace repository
exists, add the folder itself: `claude plugin marketplace add ./plugins`.

### Cursor

In Cursor: **Customize**, find OpenMoat in the Marketplace, **Install**. Before it is
listed, copy `plugins/cursor` to `~/.cursor/plugins/local/openmoat` and run
**Developer: Reload Window**. The plugin carries the five hooks `openmoat init` writes,
each with `failClosed: true`.

### Gemini CLI

```bash
gemini extensions install https://github.com/crocodile-labs/openmoat-gemini
```

Before that repository exists: `gemini extensions link plugins/gemini-cli`. The
extension's `BeforeTool` hook is the one `openmoat init` writes; Gemini CLI's limits
stay (a hook that times out or exits 1 lets the call run; untrusted folders run no hooks).

### GitHub Copilot CLI

```bash
copilot plugin install crocodile-labs/openmoat:plugins/copilot-cli
```

Needs Copilot CLI 1.0.111 or later, which runs a plugin's hook in the plugin's folder.

### OpenCode

```bash
opencode plugin add @openmoat/opencode
```

The package is `init`'s OpenCode plugin (OpenCode 1 and 2) finding `openmoat` on the
search path, under the id `openmoat-npm` so both can be loaded. Restart OpenCode
(OpenCode 2: `opencode service restart`).

### pi

```bash
pi install npm:@openmoat/pi
```

The package is `init`'s pi extension finding `openmoat` on the search path.

### OpenClaw

```bash
openclaw plugins install clawhub:@openmoat/openclaw
```

The package is `init`'s OpenClaw plugin under the id `openmoat-clawhub`, so both can be
loaded; restart the Gateway. It takes OpenClaw's default handler timeout (15 s) unless
you set `plugins.entries.openmoat-clawhub.hooks.timeouts.before_tool_call`; `openmoat
init` sets 60 s for its own.

### Hermes Agent

```bash
hermes plugins install openmoat && hermes plugins enable openmoat
```

A Python plugin whose `pre_tool_call` callback sends the call to `openmoat guard` and
returns a block for every failure (Hermes skips a callback that raises).

### Antigravity CLI

```bash
agy plugin install https://github.com/crocodile-labs/openmoat-antigravity
```

Antigravity CLI is a preview host: check that the hook fires (`openmoat doctor` shows
the package's last run) before you rely on it. Its build-plugins guide says a plugin
hook must exit 0 with its JSON answer and that any other exit is ignored, so the
package blocks with the deny on stdout and exit 0.

### Codex, Cline and goose

No package: Codex's Plugins Directory does not take plugins that carry hooks, Cline's
SDK plugins wait 3 s and ignore a failed hook, and goose has no registry for hook plugins
(`openmoat init` already writes OpenMoat as an Open Plugins folder). Use `openmoat init`.

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
own commands. The sandboxed-start shims of the agents it uninstalls go, and with the
last one the two `PATH` lines (the start-up file given back from its backup when the rest
is unchanged); uninstalling every agent deletes the decoy keys. A shim or decoy you
changed since `init` wrote it stays, and is named. `~/.moat`
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
   - `hook entry for … is out of date (written by an older OpenMoat, or for another state
     directory), …; run openmoat init`: the new
     release writes its hook entry differently (after 0.18.0 every hook names the state
     directory, `--home`, ADR-071; more tools, another timeout, a new event
     such as Claude Code's `SessionStart`, which from 0.12.0 gives each session
     its credential for `openmoat proxy`, ADR-044, or Claude Code's `PostToolUse`, which
     from 0.16.0 reads what untrusted calls returned for `injected-input`, ADR-057, and
     from 0.17.0 Cursor's `beforeTabFileRead` and the Cline CLI's `PostToolUse` file,
     ADR-060 and ADR-063).
     Run `openmoat init`. It keeps your policy, backs up the agent's file before it changes
     OpenMoat's own entry, and re-pins.
   - `hook runs …, which does not exist`, `a different OpenMoat binary than this one`, or
     `lock expects …, running …`: `openmoat` now lives at another path (another
     install method, another Cargo `--root`). Run `openmoat init` with the `openmoat` the hooks
     should use, and `openmoat proxy install` again if the proxy runs as a service
     ([Upgrade note](#upgrade-note)).
   - `binary is release …, the lock recorded …; run openmoat init to record it`: the lock
     keeps a digest of the binary (ADR-071); the hooks keep working, and `openmoat init`
     records the new one. `the openmoat binary … changed since the lock recorded it`
     instead means the file changed under the same release, and every call is denied
     until you check it and run `openmoat init`.
   - a sandbox line ending `run openmoat sandbox sync`: the new release writes the agents'
     sandbox settings differently. Run `openmoat sandbox sync`.
   - `Policy  N changes from the OpenMoat … default to review → openmoat policy upgrade`:
     see step 2.

   Re-run `openmoat init` only when doctor asks for it.
2. **`openmoat policy upgrade`.** `openmoat init` and an upgrade keep your `policy.yaml` as it
   is, so rules the new default policy gained, security fixes among them, reach you only
   this way. It shows what changes, grouped (new protections, fewer interruptions, the
   comment updates counted), and asks; `d` at the question or `--diff` shows the full
   diff, `--dry-run` only shows the changes, `--undo` puts the previous policy back
   ([USAGE.md](USAGE.md#after-upgrading-openmoat)). Once applied it updates the agents'
   sandboxes as `openmoat sandbox sync` does. `openmoat` alone offers the same at a
   terminal.

### From 0.28.0 to 0.29.0

What you will see, and what to run:

- **The audit log moves to schema version 13** (ADR-130): a `phases_us` column, which
  holds how long each call spent in each of the guard's phases. The new `openmoat` adds
  it the first time it opens the log; nothing to run. An older `openmoat` then refuses
  to open the log ("schema version 13 is newer than this build supports"), and its hook denies every call. So update every
  `openmoat` on the machine together (a Homebrew install beside a `cargo install`, say:
  [Upgrading](#upgrading)), and restart a running `openmoat proxy`, `openmoat approvals
  listen` and any agent with a wrapped MCP server, so that no process of the older build
  is left. `openmoat doctor` names a hook that still runs another binary.
- **Decisions are faster, with the same answers**: the guard builds only the globs and
  redaction patterns a call needs. On one developer Mac, `openmoat bench`'s ordinary
  work went from p50 102 ms, p95 192 ms and p99 260 ms on 0.28.0 to 87, 123 and 156 ms,
  and reading the session's earlier calls from 22.7 to 10.9 ms. Your times depend on
  the machine and its load.
- **`openmoat audit stats` shows where the time goes**, phase by phase, for calls
  recorded after the upgrade ([USAGE.md](USAGE.md#audit-stats-time-per-guard-phase)),
  and `openmoat bench` prints each phase's p50 and p95.
- **The default policy is unchanged**, so `openmoat policy upgrade` has nothing new to
  offer.

### From 0.27.0 to 0.28.0

What you will see, and what to run:

- **`openmoat policy upgrade` offers the new default rules**: `encoded-secret-egress`
  holds a token or credential sent hidden by an encoding (URL encoding, base64, hex,
  zero-width characters), `hostname-data` holds encoded bytes in the labels of a host no
  allow rule lists (ADR-123), the `data-flow` review holds an MCP tool that acts after
  another MCP server's result (ADR-126, preview), and `kernel-self` also keeps agents away
  from `openmoat mcp login` and its token folder. The upgrade from the 0.27.0 default only
  narrows. To see what a URL gets:
  `openmoat policy check --kind fetch '<url>'`.
- **On Windows, `openmoat run` can hold reads and the network too** (ADR-129, preview):
  run `openmoat agent-account setup` once from an administrator terminal, and later runs
  start the agent as its own local account; Windows then refuses the reads your policy
  denies and every connection but the one to the run's proxy. Without it, Windows runs are as in
  0.27.0. How to try it:
  [USAGE.md](USAGE.md#run-the-agent-as-its-own-windows-account).
- **`openmoat policy check-diff` reads lockfiles** (ADR-125): a look-alike name, an
  install script the lockfile records or a `go.sum` hash changed for the same version is
  flagged in a pull request even when a dependency pulls it in.
- **New, all optional**: remote (Streamable HTTP) MCP servers through the gateway with
  `openmoat mcp login <server> --url <url>` (ADR-127, preview), the agent never holding
  the token.

### From 0.26.0 to 0.27.0

What you will see, and what to run:

- **`openmoat policy upgrade` offers the new default rules**: `obfuscated` holds a shell
  line built to hide what it runs for review (ADR-116), `persistence` names
  `Set-ExecutionPolicy`, and `kernel-self` keeps agents away from `openmoat team` and
  from the gate's secret and state files. The upgrade from the 0.26.0 default only
  narrows.
- **PowerShell lines are read now** (ADR-116): `pwsh -c '…'` and
  `powershell -EncodedCommand …` get the same rules as a POSIX line, so a PowerShell
  listing of `~/.ssh` is denied where it used to be left to the agent.
- **A slow check is denied, not run** (ADR-120): when OpenMoat cannot decide a call within
  its deadline (30 s; 25 s for Hermes Agent), it denies it in the agent's own format,
  where Codex, Copilot CLI, Gemini CLI, Qwen Code, Crush, the Cline CLI and the
  Antigravity CLI used to run it after their hook timed out.
- **`openmoat init` asks once per hook-only agent** whether typing its name should start it
  confined in `openmoat run`'s sandbox (default no); `openmoat confine` and
  `openmoat confine --off` change it later, and `openmoat status` shows each agent's
  protection score.
- **A long session keeps working through an upgrade or a policy change** (ADR-121): calls
  read on from the session's earlier taint instead of reading the whole session again.
- **New, all optional**: `openmoat gate setup` adds an authenticator code to every command
  that loosens the protection, and every policy change is listed by
  `openmoat show --session policy-changes` (ADR-117); `mint:` secrets hand git and the
  AWS tools short-lived credentials under `openmoat run` (ADR-118); `openmoat team join`
  takes a team's signed bundle that can only narrow your policy, and `openmoat inventory`
  reports this machine's agents and hooks (ADR-119).

### From 0.25.0 to 0.26.0

What you will see, and what to run:

- **Codex, Gemini CLI, Qwen Code and Crush show their hook as out of date** until you run
  `openmoat init`: the new hook entry blocks the call when `openmoat` is missing or killed
  (ADR-109). Run `openmoat init` once; Codex then asks you to trust the changed hook in
  `/hooks`, once.
- **The first `openmoat init` records the other hooks the agents load** (plugin hooks,
  helper commands, a project's hook files, `.git/config` programs), so nothing already
  there is named or blocked; until then `openmoat status` and `openmoat doctor` say they
  are not recorded yet. One added later is named by `openmoat status` until you run
  `openmoat hooks accept` ([USAGE.md](USAGE.md#other-hooks-the-agents-run)).
- **`openmoat policy upgrade` offers the new default rules** (ADR-112): `system-files`,
  `stops-system`, `credential-egress`, and more paths and patterns in `secrets-paths`,
  `persistence` and `token-egress`. After it, a listing or recursive read of `/etc` or
  `/etc/ssh` itself (`ls /etc`, `grep -r … /etc`) needs review, because those folders now
  hold secret paths; writes in the system's folders and stopping a system process need
  review too. An upgrade that would move any call toward allow is listed and applied only
  with `openmoat policy upgrade --accept-widening`; the upgrade from the 0.25.0 default
  only narrows.
- **New reviews after private data meets untrusted content** (ADR-113): once a session
  has read private data (a key, an agent's login, the whole environment) and content
  someone else may have written (a page, an MCP result, `gh issue view`), a call that can
  send data out needs review (`lethal-trifecta`), to an allowed host and `git push` too.
  This needs no upgrade step; sessions that never read private data are unchanged
  ([USAGE.md](USAGE.md#private-data-untrusted-content-and-a-way-out-the-lethal-trifecta)).
- **Collect-then-send needs review**: a send of a file the session packed from outside the
  project, and any send after the session copied private data into a file, are reviewed
  by the new default rule `staging-egress`, which `openmoat policy upgrade` adds
  ([USAGE.md](USAGE.md#data-packed-or-copied-before-it-is-sent-staging)).
- **Rules may test arguments** (`when:`, POLICY.md §2.4). An older binary refuses a
  policy that uses it, so update every machine before you share such a rule.
- **`openmoat doctor` shows new rows**: the protection score of each `openmoat run` tier,
  and the audit log's checkpoint public key. The checkpoint signing key
  (`~/.moat/audit.key.ed25519`) is made by `openmoat init` or the first
  `openmoat audit checkpoint`; logs from earlier releases keep verifying as before.
- **`openmoat status` lists hook-only agents `openmoat run` can confine here** under
  `Needs your attention`, with the command; Qwen Code and Crush now get one.
- **`openmoat run` starts on native Windows** (preview, ADR-115) instead of refusing. It
  refuses writes outside the project, the run's temp directory and `--write` paths, and
  ends every process the agent started when the run ends; reads and the network are not
  held by the OS, so it scores at most 55/100 and `sandbox.strict: true` or
  `require.run: full-boundary` still refuse there. Start the agent's `.exe`, not an npm
  `.cmd` shim, which is refused. The first run in a folder adds one access-list entry for
  a SID no account has (`icacls <folder>` lists it) and keeps it, so later runs change
  nothing ([SANDBOX.md](SANDBOX.md#openmoat-run-on-windows-preview)).
- **Wrapped MCP servers' sampling requests are refused** unless the policy sets
  `mcp: { allow_sampling: true }`, and a link a server asks you to open must be `https`
  to a host the policy allows (`openmoat allow --site <host>` for a server's own sign-in
  page). An older binary refuses a policy that sets `allow_sampling`, so update every
  machine first ([USAGE.md](USAGE.md#mcp-servers-through-the-gateway)).
- **Stdio MCP servers are held when their package release changes**: accepting a server
  started with `npx`, `uvx` or `docker run` also records the release it runs, and another
  release holds the server until you accept it again. A server accepted before this
  release is not held for having none recorded; its release is recorded the next time you
  accept it. Agents that speak MCP
  2026-07-28 keep a server accepted under the older revision while its text is the same;
  one whose results name another server is held.
- **Linux, Claude Code: `openmoat doctor` names another AppArmor fix** (#784). If you
  loaded Ubuntu's `bwrap-userns-restrict` profile because an earlier release suggested
  it, Claude Code's sandbox fails under it; doctor now warns and names the profile
  Claude Code's documentation gives for `/usr/bin/bwrap`
  ([SANDBOX.md](SANDBOX.md#what-each-agents-sandbox-needs-on-linux)).

### What can change between 0.x minor releases

Before 1.0 a minor release (0.5 → 0.6) may change things a patch release does not.
Read the [CHANGELOG](../CHANGELOG.md) entries since your version first; so far these
kinds of change have happened:

- **The audit log schema moves forward** (version 3 in 0.5.0, version 4 in 0.6.0,
  version 5 in 0.11.0, version 7 in 0.12.0, version 8 in 0.14.0, version 10 in 0.16.0, version 11 in the release after 0.21.0, version 13 in 0.29.0). The
  new `openmoat` updates the log when it first opens it; an older `openmoat` then refuses to
  open it (`schema too new`), and its hook denies every call. Going back to an older
  release is not supported.
- **The default policy changes.** In 0.5.0, calls no rule names moved from `ask` to
  `defer` (the agent's own prompt decides, ADR-025). Your policy keeps its own rules
  until you run `openmoat policy upgrade`.
- **Policy names change.** In 0.14.0 the verdict `ask` became `review`, and the rule
  group `ask:` became `review:` (ADR-053). A policy that still says `ask` works as before;
  `openmoat policy lint` warns and `openmoat policy upgrade` renames it.
- **Hook entries change.** `openmoat doctor` then says the hook is out of date, and
  `openmoat init` rewrites it (step 1).
- **The library crates' API** (`openmoat-core`, `openmoat-hosts`, `openmoat-audit`,
  `openmoat-proxy`, `openmoat-sdk`) breaks in minor releases, marked **Breaking** in the CHANGELOG. This
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
pinned `openmoat` binary. On Linux the file is written readable by your account alone (`0o600`);
on macOS the `LaunchAgents` directory already restricts access to the
user. Token values the policy brokers are read from the user's
environment at run time by the proxy itself; they never touch the service
file.

The service manager starts the proxy exactly as that file says, so `openmoat doctor`
and `openmoat status` read it back and compare it with what `openmoat proxy install`
writes for the current binary and state directory. Each difference is a problem, and
`doctor` exits 64:

- an environment variable other than `MOAT_HOME` (`DYLD_INSERT_LIBRARIES`,
  `LD_PRELOAD`, `HTTPS_PROXY`), or a systemd `EnvironmentFile=` or `PassEnvironment=`;
- any other change (another binary, an `ExecStartPre=`, extra arguments), or a file in
  a form it cannot read (a binary plist);
- a mode that lets others read or write it (anything but readable and writable by your account alone).

```bash
openmoat doctor   # ✗ service file     ~/.config/systemd/user/moat-proxy.service sets environment the proxy is started with beyond `MOAT_HOME`: LD_PRELOAD; `openmoat proxy install` writes it again
openmoat proxy install   # writes it again, the old file kept as a backup
```

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
hook runs. OpenMoat blocks such a change mid-session, `openmoat doctor` and `openmoat status`
warn about it, and `openmoat run` starts Claude Code with `--settings
'{"disableAllHooks":false}'` on every run (or refuses where you pass your own
`--settings`; POLICY.md §9.5, ADR-098), but an
agent started directly loads it (THREAT_MODEL §5). Only Claude Code's
[managed settings](https://code.claude.com/docs/en/managed-settings), which an
administrator deploys and the user cannot edit, make the hooks immune: a `disableAllHooks`
outside them cannot turn off a hook set in them.

```bash
openmoat init --managed
```

writes the same entries `openmoat init` writes to the user file into a drop-in of its
own, `managed-settings.d/50-openmoat.json`, and does the same for the other agents set
up that have such a place: GitHub Copilot CLI's policy hooks (`policy.d/openmoat.json`,
which a repository's `disableAllHooks` cannot turn off either) and Cursor's enterprise
`hooks.json` (only while there is none, or it holds OpenMoat's hook alone). It needs a
person at a terminal. Where the folder needs root, or the agent loads the file only when
root owns it (Copilot CLI), OpenMoat keeps the file at `~/.moat/managed/<agent>.json` and
prints the `sudo install` command to run; it never escalates itself. It is idempotent and
never edits an administrator's own file; `openmoat uninstall` removes it (or prints the
command that does), and `openmoat doctor` reports it. Codex's `requirements.toml`, Gemini
CLI's system settings and OpenCode's system directory are named but not written: each is
an administrator's one file, or its behaviour towards a project is not documented.

The managed file applies to every account of the machine and runs this person's
`openmoat` with their state directory: use it on a machine one person uses, or in an
image an administrator builds. Claude Code applies one managed source: a device profile
or server-managed settings take the files' place.

For teams that deploy managed settings themselves:

1. Copy the `PreToolUse`, `PostToolUse`, `ConfigChange` and `SessionStart` entries `openmoat init` wrote to
   `~/.claude/settings.json` (they run `openmoat` by its stable path, ADR-016) into the
   managed settings file, and keep them in the user file too, which `openmoat doctor`
   checks.
2. Add `"allowManagedHooksOnly": true` there to also block user, project, local and
   plugin hooks (except plugins the managed settings force on) and to take `statusLine`
   and file suggestion commands only from managed settings.

OpenMoat does not pin managed settings; whoever deploys them keeps them in step with
`openmoat init` after an upgrade that changes the hook entries (`openmoat doctor` says
when OpenMoat's drop-in is outdated).

`openmoat status` and `openmoat doctor` read the system-wide settings of three agents,
without changing them, and call the agent not protected when they keep its hook from
running. They name the file and the key:

| Agent | Files read | What turns OpenMoat's hook off |
|---|---|---|
| Claude Code | `managed-settings.json` and the `*.json` drop-ins of `managed-settings.d/` beside it (`/Library/Application Support/ClaudeCode/` on macOS, `/etc/claude-code/` on Linux and WSL, `C:\Program Files\ClaudeCode\` on Windows) | `disableAllHooks: true`; `allowManagedHooksOnly: true` with no OpenMoat entry among their `hooks` |
| Gemini CLI | system `settings.json` and `system-defaults.json` (`/Library/Application Support/GeminiCli/`, `/etc/gemini-cli/`, `C:\ProgramData\gemini-cli\`; `GEMINI_CLI_SYSTEM_SETTINGS_PATH` and `GEMINI_CLI_SYSTEM_DEFAULTS_PATH` move them) | `hooksConfig.enabled` not `true`; `hooksConfig.disabled` naming OpenMoat's hook |
| Codex | `requirements.toml` (`/etc/codex/` on macOS, Linux and WSL, `C:\ProgramData\OpenAI\Codex\` on Windows) | `[features] hooks = false` (or `codex_hooks`); `allow_managed_hooks_only = true` with no OpenMoat entry in its `[hooks]` |

```bash
openmoat status    # Claude Code   not protected: hook turned off by /etc/claude-code/managed-settings.json: `disableAllHooks` turns off every hook, OpenMoat's included
```

A file that is missing, that this user cannot read (the agent, running as the same
user, cannot read it either) or that does not parse says nothing. Codex settings an MDM
profile delivers on macOS are not read.

## Teams: request rules for allowed hosts

The hosts the default policy allows (GitHub, the package registries) can receive data
through endpoints that publish what they are sent, such as a new gist. Request rules
(`requests:`, [POLICY.md](POLICY.md) §2.3, ADR-062) name those endpoints per host. There
are three levels, and a team picks how far to go:

1. **The hook, on by default.** The default policy's `exfil-gists` entry is `hook_only`:
   the hook denies `curl -X POST https://api.github.com/gists -d @notes.txt`, `gh gist
   create` and the other spellings it reads, and holds for review a request whose URL is
   made at run time. It needs no setup and no CA, for every agent with a hook. A
   repository policy can add more entries (deny lists only) for everyone in the project.
2. **The proxy, with a CA.** An entry without `hook_only` is also held inside HTTPS, for
   every client and script, by `openmoat run`'s proxy and, with `sandbox.proxy_port`,
   by `openmoat proxy` for the Claude Code sessions it gives the CA. Each person makes
   the CA once, at a terminal, and again whenever a host is added:

   ```bash
   openmoat proxy ca init
   ```

   Without a CA that covers the host, `openmoat run` does not start, and `openmoat
   proxy` refuses the host's connections (`requests_untrusted: refuse`, the default;
   `relay` passes them unread). Codex's sandbox sessions cannot be given the CA, so
   under `openmoat proxy` they are refused for such hosts; inside `openmoat run` they
   are held like any other.
3. **The pack, to share the rules.** The `exfil-endpoints` pack
   (`crates/openmoat-core/policies/packs/exfil-endpoints.yaml` in the source) lists the
   same denies. A pack's (and a repository's) entries are held by the hook alone unless
   your own policy has the proxy hold the host: to opt in for `api.github.com`, set
   `hook_only: false` on the default policy's `exfil-gists` entry, or add your own entry
   for it, and make the CA. The opt-in is off by default because on macOS Go programs
   (`gh`) do not read `SSL_CERT_FILE`, so under `openmoat proxy` they do not trust the
   CA and fail against a proxy-held host. Whoever maintains the team's rules signs the
   pack, and each person installs it:

   ```bash
   ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n openmoat-pack exfil-endpoints.yaml   # the maintainer
   openmoat policy trust-key maintainer.pub --name maintainer                       # each person, once
   openmoat policy install exfil-endpoints.yaml
   ```

`openmoat doctor` and `openmoat status` say, where the host sandboxes use `openmoat
proxy`, when a CA exists and your policy has the proxy hold a host but the pack is not
installed, and when a host a proxy-held
entry names is not covered by the CA (run `openmoat proxy ca init` again). The rules
narrow what an allowed host receives; they do not read request bodies, so an endpoint
they allow (an issue comment) still carries what is put in it (THREAT_MODEL T12).

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
its own (`HERMES_HOME=~/.hermes/profiles/<name>`). goose's directory is its
configuration directory (`~/.config/goose`, or `goose` in `XDG_CONFIG_HOME`), by which
`openmoat init` finds it; its hook file is OpenMoat's plugin,
`~/.agents/plugins/openmoat/hooks/hooks.json`, outside it. `GOOSE_PATH_ROOT` moves
both, to `<root>/config` and `<root>/.agents/plugins`. The
table is generated from each agent's `HostSpec` (`OPENMOAT_TEST_UPDATE_DOCS=1 cargo test
-p openmoat-hosts --test docs`); do not edit it.

<!-- generated:hosts-install -->
| Agent | Directory | Moved by | Hook file | Entries `openmoat init` writes |
|---|---|---|---|---|
| Claude Code | `~/.claude` | `CLAUDE_CONFIG_DIR` | `settings.json` | `PreToolUse` (600 s), `ConfigChange` (60 s), `SessionStart` (60 s), `PostToolUse` (60 s) |
| Codex | `~/.codex` | `CODEX_HOME` | `hooks.json` | `PreToolUse` (600 s), `PostToolUse` (60 s) |
| Cursor | `~/.cursor` | `CURSOR_CONFIG_DIR` | `hooks.json` | `beforeShellExecution` (600 s), `beforeMCPExecution` (600 s), `beforeReadFile` (600 s), `preToolUse` (600 s), `beforeTabFileRead` (600 s) |
| OpenClaw | `~/.openclaw` | `OPENCLAW_STATE_DIR` | `openclaw.json` | `before_tool_call` (60 s) |
| GitHub Copilot CLI | `~/.copilot` | `COPILOT_HOME` | `hooks/openmoat.json` | `preToolUse` (600 s), `postToolUse` (60 s) |
| pi | `~/.pi/agent` | `PI_CODING_AGENT_DIR` | `extensions/openmoat.js` | `tool_call` (45 s) |
| Gemini CLI | `~/.gemini` | `GEMINI_CLI_HOME` | `settings.json` | `BeforeTool` (600 s), `AfterTool` (60 s) |
| OpenCode | `~/.config/opencode` | `XDG_CONFIG_HOME` | `plugins/openmoat.js` | `tool.execute.before` (45 s), `execute.before` (45 s) |
| Hermes Agent | `~/.hermes` | `HERMES_HOME` | `config.yaml` | `pre_tool_call` (60 s) |
| Cline CLI | `~/.cline` | `CLINE_DIR` | `hooks/PreToolUse` | `PreToolUse` (120 s) |
| goose | `~/.config/goose` | `GOOSE_PATH_ROOT` | `~/.agents/plugins/openmoat/hooks/hooks.json` | `PreToolUse` (60 s) |
| Antigravity CLI | `~/.gemini/antigravity-cli` | `HOME` | `~/.gemini/config/hooks.json` | `PreToolUse` (600 s) |
| Qwen Code | `~/.qwen` | `QWEN_HOME` | `settings.json` | `PreToolUse` (600 s) |
| Crush | `~/.config/crush` | `XDG_CONFIG_HOME` | `crush.json` | `PreToolUse` (600 s) |
<!-- /generated -->

If you start Claude Code with `CLAUDE_CONFIG_DIR`
set, run `openmoat init` once with the same value. `init` records the directory of each
agent it sets up in `~/.moat/hosts.json` (pinned by the lock), and every later command
(`status`, `doctor`, `allow`, `sandbox sync`, `uninstall`) uses the recorded directory,
so you do not export the variables again. When a variable in your shell names another
directory than the record, `openmoat doctor` reports it instead of following it; run
`openmoat init` with the variable set to move OpenMoat to that directory. `MOAT_HOME` is
not recorded: it says where the record is. `init` writes the state directory into each
hook instead (`guard --host <id> --home <dir>`), and the hook decides with that
directory whatever the agent's environment says; a `MOAT_HOME` there that names another
directory makes the hook deny every call. After you move `MOAT_HOME`, run
`openmoat init` with the new value:

```bash
MOAT_HOME=/srv/me/openmoat openmoat init   # rewrites every hook with --home /srv/me/openmoat
openmoat status                            # a hook written for another directory shows as out of date
```

Next: [USAGE.md](USAGE.md) for daily use, [SANDBOX.md](SANDBOX.md) for the OS sandboxes.
