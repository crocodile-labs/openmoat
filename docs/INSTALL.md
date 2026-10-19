# Install and set up OpenMoat

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you install or upgrade OpenMoat on macOS, Linux or Windows, run `moat init`, want to know what each agent's hook covers, or use other config directories.

**On this page:** [Install](#install) · [Upgrading](#upgrading) · [Set up with moat init](#set-up-with-moat-init) · [Keep moat proxy running as a user service](#keep-moat-proxy-running-as-a-user-service) · [Undo with moat uninstall](#undo-with-moat-uninstall) · [Non-default config directories](#non-default-config-directories)

## Install

Release builds cover macOS (arm64, x64), Linux (x64, arm64; glibc and static musl)
and Windows (x64). The installer URLs below always fetch the latest release; every
release is listed on [Releases](https://github.com/crocodile-labs/openmoat/releases).

```bash
# Homebrew (macOS, Linux)
brew install crocodile-labs/tap/moat

# macOS and Linux: installs moat into ~/.cargo/bin
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/crocodile-labs/openmoat/releases/latest/download/openmoat-installer.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/crocodile-labs/openmoat/releases/latest/download/openmoat-installer.ps1 | iex"

# From crates.io (Rust 1.95)
cargo install openmoat --locked
```

Then run `moat init` ([below](#set-up-with-moat-init)).

> [!IMPORTANT]
> **macOS version.** `moat run` needs macOS 14 or later: its Seatbelt profile names
> `(ioctl-command TIOCSTI)` (CVE-2017-5226 class), an identifier `sandbox-exec`
> only recognises from macOS 13 onwards. On macOS 12 and earlier, `sandbox-exec`
> refuses to parse the profile and `moat run` exits without starting the agent
> (fail closed). The hook, `moat init` and `moat status` work on earlier macOS;
> only `moat run` has this floor. CI covers `macos-14` and `macos-15-intel`;
> GitHub Actions no longer offers a `macos-13` runner, so macOS 13 is not
> exercised in CI and is unsupported in practice.

To build from a clone instead (Rust 1.95, pinned by `rust-toolchain.toml`):

```bash
git clone https://github.com/crocodile-labs/openmoat && cd openmoat
cargo install --locked --path crates/openmoat-cli    # installs the `moat` binary
```

Each release carries `sha256.sum` and GitHub build attestations:
`gh attestation verify <archive> --repo crocodile-labs/openmoat`.

## Upgrading

Upgrade the binary the way you installed it:

```bash
brew update && brew upgrade moat                              # Homebrew: update the tap first
cargo install openmoat --locked --force                       # crates.io
```

With the installers, run the installer again: its URL always fetches the latest release.
From a clone, pull and run `cargo install --locked --path crates/openmoat-cli` again.

Then, in a terminal of your own:

1. **`moat doctor`.** After an upgrade in the same place the hooks keep working, because
   they run `moat` by its stable path (ADR-016), and nothing has to be re-pinned. Doctor
   names what is left, if anything:
   - `hook entry for … is out of date (written by an older moat); run moat init`: the new
     release writes its hook entry differently (more tools, another timeout, a new event).
     Run `moat init`. It keeps your policy, backs up the agent's file before it changes
     OpenMoat's own entry, and re-pins.
   - `hook runs …, which does not exist`, `a different moat than this one`, or
     `lock expects …, running …`: `moat` now lives at another path (another
     install method, another Cargo `--root`). Run `moat init` with the `moat` the hooks
     should use, and `moat proxy install` again if the proxy runs as a service
     ([Upgrade note](#upgrade-note)).
   - a sandbox line ending `run moat sandbox sync`: the new release writes the agents'
     sandbox settings differently. Run `moat sandbox sync`.
   - `policy update  N changes from the OpenMoat … default`: see step 2.

   Re-run `moat init` only when doctor asks for it.
2. **`moat policy upgrade`.** `moat init` and an upgrade keep your `policy.yaml` as it
   is, so rules the new default policy gained, security fixes among them, reach you only
   this way. It shows the diff and asks; `--dry-run` only shows it, `--undo` puts the
   previous policy back ([USAGE.md](USAGE.md#after-upgrading-openmoat)). `moat` alone
   offers the same at a terminal.

### What can change between 0.x minor releases

Before 1.0 a minor release (0.5 → 0.6) may change things a patch release does not.
Read the [CHANGELOG](../CHANGELOG.md) entries since your version first; so far these
kinds of change have happened:

- **The audit log schema moves forward** (version 3 in 0.5.0, version 4 in 0.6.0). The
  new `moat` updates the log when it first opens it; an older `moat` then refuses to
  open it (`schema too new`), and its hook denies every call. Going back to an older
  release is not supported.
- **The default policy changes.** In 0.5.0, calls no rule names moved from `ask` to
  `defer` (the agent's own prompt decides, ADR-025). Your policy keeps its own rules
  until you run `moat policy upgrade`.
- **Hook entries change.** `moat doctor` then says the hook is out of date, and
  `moat init` rewrites it (step 1).
- **The library crates' API** (`openmoat-core`, `openmoat-hosts`, `openmoat-audit`,
  `openmoat-proxy`) breaks in minor releases, marked **Breaking** in the CHANGELOG. This
  matters only to Rust code that depends on them; the `moat` command is not affected.
- **The minimum Rust version** for `cargo install` is raised only in a minor release.

The policy format and the commands may still change before 1.0
([README](../README.md#status)); every such change has a CHANGELOG line.

## Set up with `moat init`

```bash
moat init      # policy, lock, audit log; asks before hooking each agent it finds
moat status    # policy, lock, hooks and protection level per agent, recent decisions
```

`moat init` writes `~/.moat/policy.yaml` (the default policy), pins it and the hook
files in `~/.moat/policy.lock` and creates the audit log. Then it lists each agent
whose configuration directory exists, with the files it would change, and asks once
per agent:

```
Found these agents:
  Claude Code  /Users/you/.claude (changes settings.json)
  Codex        /Users/you/.codex (changes hooks.json, config.toml)
Protect Claude Code (/Users/you/.claude)? [Y/n]
Protect Codex (/Users/you/.codex)? [Y/n]
```

Only the agents you accept get the hook and sandbox settings. The last lines name the
backups and how to undo: `Undo anytime: moat uninstall`. `init` never overwrites an
existing policy, never duplicates a hook and backs up a host file before editing it
(`<file>.moat-backup` for hooks, `<file>.moat-sandbox-backup` for sandbox settings), so
it is safe to run again. The backups it creates are listed in `~/.moat/hosts.json`;
a file of yours that already has one of those names is left alone, and
`moat uninstall` never deletes it.

To choose without questions, name the agents: `moat init --hosts claude-code` (or
`codex`, `cursor`, comma-separated). `moat init --yes` sets up every agent found, for
scripts. Without a terminal and without `--yes` or `--hosts`, `init` changes no agent's
files and says how to go on. `moat init --dry-run` prints what would change first.

Hooks run the `moat` you ran `moat init` with, by its stable path (ADR-016). After
moving or reinstalling the binary somewhere else, run `moat init` again; `moat doctor`
names a hook whose binary is missing or is a different `moat`.

On native Windows, `init` does not turn on Claude Code's sandbox: it runs on macOS,
Linux and WSL2 only, and Claude Code would not start with it required. The hook still
applies the policy to Claude Code's tool calls, and `init`, `doctor` and `status` say so. For OS
confinement, run Claude Code and `moat` inside WSL2. Codex's sandbox is set up as on
other systems; Cursor's `sandbox.json` is not written, because Cursor documents its
sandbox for macOS and Linux only.

| Agent | What is hooked | Hook file |
|---|---|---|
| Claude Code | `PreToolUse`: `Bash`, `Monitor`, `PowerShell` (never parsed: `unparseable`), `Read`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, `LSP`, `SendFile`, `WebFetch` (as `fetch`), `WebSearch` (as `web.search`), MCP tools. `ConfigChange`: user, project and local settings | `~/.claude/settings.json` |
| Codex | `PreToolUse`: shell commands, `apply_patch` (every file the patch names), MCP tools. Codex hooks cannot ask (`PermissionRequest` runs only when Codex itself prompts), so an `ask` blocks the call until you run `moat` or `moat allow --last`, for `apply_patch` too. Codex does not hook web search or hosted tools | `~/.codex/hooks.json` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` (`Read`, `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete`, `Grep`, `Glob`, `WebSearch`, `WebFetch`, and any other tool: one that names a path is checked against it, one that does not asks as `tool.unknown`); installed with `failClosed`. Cursor prompts on `ask` only for shell and MCP calls, so an `ask` on `preToolUse` or `beforeReadFile` is sent as a deny until you run `moat` or `moat allow --last`. `moat init` also writes Cursor's own sandbox settings (`sandbox.json`) on macOS and Linux; Cursor still runs a command outside that sandbox when its Auto-review classifier approves it, in Run Everything mode, and in the CLI without `--sandbox enabled` ([SANDBOX.md](SANDBOX.md#cursors-sandbox)) | `~/.cursor/hooks.json`, `~/.cursor/sandbox.json` |
| OpenClaw | Every tool, through OpenMoat's plugin and OpenClaw's `before_tool_call` hook: `exec` (PowerShell on Windows: `unparseable`), `read`, `write`, `edit`, `apply_patch`, `web_fetch`, `web_search`, `browser` `open`/`navigate`/`upload`, MCP tools (`<server>__<tool>`; each server in `mcp.servers` pinned), `gateway config.get`, `plugins` changes (as a write to `openclaw.json`), `cron` jobs added or updated (ask, `runs-later`), `view_image` (a file read, or a fetch of one URL), `nodes` `invoke` (`unparseable`); `process` input is `unparseable`; any other tool is `tool.unknown`. An `ask` becomes OpenClaw's own approval request; a hook that throws or takes over 60 s blocks the call. `openclaw.json` is read as JSON5 and written back as plain JSON (values kept, formatting not); `moat init` refuses a file with comments, which that would drop: move them out of the file first. `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR` and `OPENCLAW_CONFIG_PATH` are followed when `moat init` runs and recorded; run `init` again after changing them. An `$include` that may bring MCP servers holds back every OpenClaw MCP call. Restart the Gateway after `moat init` | `~/.openclaw/openclaw.json` (or `OPENCLAW_CONFIG_PATH`), `<state dir>/openmoat/openmoat.mjs` |
| Continue CLI (`cn`) | Runs the Claude Code hook, recorded as host `continue`. `cn` ignores an `ask`, so an `ask` blocks the call until you run `moat allow --last`. The released `cn` does not run hooks, so nothing is checked until it does; use `moat run` (`moat doctor` warns) | Claude Code's |

## Keep `moat proxy` running as a user service

The egress proxy records every connection and injects brokered secrets. The
host sandboxes `moat init` configures send their commands' traffic through
it when the policy sets `sandbox.proxy_port`, so a stopped proxy leaves
sandboxed `npm install`, `cargo build` and `git fetch` without network. To
keep it up without opening a terminal every time, install it as a per-user
service (#272):

```bash
moat proxy install     # macOS: launchd user agent at ~/Library/LaunchAgents/dev.openmoat.proxy.plist
                       # Linux: systemd user unit at ~/.config/systemd/user/moat-proxy.service
moat proxy status      # not installed | stopped | running | drift-blocked | crashlooping
moat proxy uninstall   # stop and remove the service
```

The service restarts on failure (`KeepAlive = {SuccessfulExit=false}` on
macOS; `Restart=on-failure` on Linux). A policy-lock drift is a clean exit
(code 64), not a crash, so the service deliberately stops instead of
loop-restarting into the same error; `moat doctor` names the problem and
the fix. `moat sandbox sync` restarts the service after re-pinning the
lock so the proxy picks up the new policy (which it reads once at
start-up). `moat uninstall` removes the service alongside the hooks, so
a stale service never keeps listening with a reference to a gone binary.

Windows has no user service yet (#272): `moat proxy install` and `moat proxy
status` refuse with exit 64 and say to run `moat proxy` in a terminal.

The plist/unit holds only `MOAT_HOME` (a path, never a secret) and the
pinned `moat` binary. On Linux the file is written owner-only (`0o600`);
on macOS the `LaunchAgents` directory already restricts access to the
user. Token values the policy brokers are read from the user's
environment at run time by the proxy itself; they never touch the service
file.

On Windows `moat proxy install` is refused for now: Standard-tier proxy
routing is not planned for the first release (#272). Run `moat proxy` in
a terminal to keep the proxy up by hand.

### Upgrade note

The service names the pinned `moat` by its stable path (ADR-016), so an
upgrade through Homebrew or a cargo-install swap keeps working as long as
the stable path still resolves to the new binary. After a reinstall at a
different path (a Cargo change of `--root`, say), run `moat proxy install`
again so the service file names the new path.

## Undo with `moat uninstall`

```bash
moat uninstall                    # every agent; --hosts codex for one
moat uninstall --purge            # also delete ~/.moat (policy, lock, audit log)
```

`moat uninstall` removes OpenMoat's hooks and sandbox settings from each agent and
prints what it did per file. When the file is otherwise unchanged since `moat init`,
the backup `init` took is written back byte for byte; a file `init` created is
deleted; a file you changed since keeps your changes and only loses OpenMoat's
entries (its backup stays next to it). The lock stops pinning those files. `~/.moat`
stays unless you pass `--purge`. Like `moat allow`, it runs only from a terminal, and
the default policy denies it to agents (`kernel-self`).

## Non-default config directories

`moat` finds each agent's configuration the way the agent does: `CLAUDE_CONFIG_DIR`,
`CODEX_HOME` and `CURSOR_CONFIG_DIR` replace `~/.claude`, `~/.codex` and `~/.cursor`,
and `MOAT_HOME` replaces `~/.moat`. If you start Claude Code with `CLAUDE_CONFIG_DIR`
set, run `moat init` once with the same value. `init` records the directory of each
agent it sets up in `~/.moat/hosts.json` (pinned by the lock), and every later command
(`status`, `doctor`, `allow`, `sandbox sync`, `uninstall`) uses the recorded directory,
so you do not export the variables again. When a variable in your shell names another
directory than the record, `moat doctor` reports it instead of following it; run
`moat init` with the variable set to move OpenMoat to that directory. `MOAT_HOME` is
not recorded: it says where the record is.

Next: [USAGE.md](USAGE.md) for daily use, [SANDBOX.md](SANDBOX.md) for the OS sandboxes.
