# Install and set up OpenMoat

## Install

Release builds cover macOS (arm64, x64), Linux (x64, arm64; glibc and static musl)
and Windows (x64). The installer URLs below always fetch the latest release; every
release is listed on [Releases](https://github.com/crocodile-labs/openmoat/releases).

`moat run` needs macOS 14 or later: its Seatbelt profile names
`(ioctl-command TIOCSTI)` (CVE-2017-5226 class), an identifier `sandbox-exec`
only recognises from macOS 13 onwards. On macOS 12 and earlier, `sandbox-exec`
refuses to parse the profile and `moat run` exits without starting the agent
(fail closed). The hook, `moat init` and `moat status` work on earlier macOS;
only `moat run` has this floor. CI covers `macos-14` and `macos-15-intel`;
GitHub Actions no longer offers a `macos-13` runner, so macOS 13 is not
exercised in CI and is unsupported in practice.

```bash
# macOS and Linux: installs moat into ~/.cargo/bin
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/crocodile-labs/openmoat/releases/latest/download/openmoat-installer.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/crocodile-labs/openmoat/releases/latest/download/openmoat-installer.ps1 | iex"

# Homebrew (macOS, Linux)
brew install crocodile-labs/tap/moat

# From crates.io (Rust 1.95)
cargo install openmoat --locked
```

To build from a clone instead (Rust 1.95, pinned by `rust-toolchain.toml`):

```bash
git clone https://github.com/crocodile-labs/openmoat && cd openmoat
cargo install --locked --path crates/openmoat-cli    # installs the `moat` binary
```

Each release carries `sha256.sum` and GitHub build attestations:
`gh attestation verify <archive> --repo crocodile-labs/openmoat`.

### Upgrade

```bash
brew update && brew upgrade moat                              # Homebrew: update the tap first
cargo install openmoat --locked --force                       # crates.io
```

With the installers, run the installer of the new release. Hooks keep working after an
upgrade in the same place; `moat doctor` confirms it. Your policy is kept as it is;
`moat policy upgrade` shows what the new default policy adds and asks before applying it.

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
it is safe to run again.

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
| Claude Code | `PreToolUse`: `Bash`, `Monitor`, `PowerShell` (always asks), `Read`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, `LSP`, `SendFile`, `WebFetch` (as `fetch`), `WebSearch` (as `web.search`), MCP tools. `ConfigChange`: user, project and local settings | `~/.claude/settings.json` |
| Codex | `PreToolUse`: shell commands, `apply_patch` (every file the patch names), MCP tools. Codex hooks cannot ask (`PermissionRequest` runs only when Codex itself prompts), so an `ask` blocks the call until you run `moat` or `moat allow --last`, for `apply_patch` too. Codex does not hook web search or hosted tools | `~/.codex/hooks.json` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` (`Read`, `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete`, `Grep`, `Glob`, `WebSearch`, and any other tool that names a path); installed with `failClosed`. Cursor prompts on `ask` only for shell and MCP calls, so an `ask` on `preToolUse` or `beforeReadFile` is sent as a deny until you run `moat` or `moat allow --last`. `moat init` also writes Cursor's own sandbox settings (`sandbox.json`) on macOS and Linux; Cursor still runs a command outside that sandbox when its Auto-review classifier approves it, in Run Everything mode, and in the CLI without `--sandbox enabled` ([SANDBOX.md](SANDBOX.md#cursors-sandbox)) | `~/.cursor/hooks.json`, `~/.cursor/sandbox.json` |
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
