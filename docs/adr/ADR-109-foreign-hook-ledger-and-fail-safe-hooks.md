# ADR-109: Foreign-hook ledger, fail-safe hook commands and a faster liveness check

Status: accepted · Date: 2026-11-22 · Builds on ADR-026 (MCP pins in the lock), ADR-079
(hook-failure facts), ADR-097 (another agent in a host's hook file), ADR-104 (hook
liveness)

## Context

OpenMoat's check runs in a hook the agent calls. Two things around that hook were
weak.

**Other hooks run with the person's permissions.** An agent runs every hook in its
settings, a project's settings and its plugins, not only OpenMoat's. A plugin update
or a settings edit that adds a lifecycle hook (a `SessionStart` that runs
`curl … | sh`) runs that command before or beside any tool call, and the
OpenMoat hook never sees it. HookPry, cited by Doberman's benchmarks, reports 77%
verified success for such installs and 0 of 1,000 runs blocked by any harness.
`.git/config` keys (`core.fsmonitor`, `core.pager`, `core.sshCommand`, `!` aliases)
are the same class: git runs them before any hook. OpenMoat named some of these
(`openmoat status` "project settings", "other hook", "git config" lines) but kept no
record, so a new one and an old one looked the same, and nothing changed for the
agent's calls.

**Nine agents ran a call when the hook failed in some way** (`docs/LIMITS.md` "If the
hook fails"). Several of those were failures of the process OpenMoat starts, not of
its decision: `openmoat` missing (the shell exits 127) or killed (128 + the signal).
Codex, Qwen Code and Crush read any exit but 2 as a hook error and run the call;
Gemini CLI does the same for a signal or exit 1. The guard already turns every error
it can catch, a panic included, into a deny (invariant 4); it cannot catch its own
absence.

**Liveness came late.** ADR-104 warns only once a session is ten minutes old, and a
Claude Code session start, which reaches the guard through its `SessionStart` hook,
counted as "the hook runs" even when the tool-call hook did not.

## Decision

### 1. The ledger

`openmoat-cli/src/hook_ledger.rs` keeps, in the policy lock's new `hook_ledger`
section, one pin per thing an agent loads that runs a program besides OpenMoat's
hook: id, host, file, what it is, the SHA-256 of what is pinned, and the commands as
shown (redacted, 300 characters). Every place is read from a host's spec, never from
a path in the CLI:

| Source | Spec fact | Pinned by |
|---|---|---|
| The hook file's other entries | `InstallSpec::hook_file` (`HookFile::foreign_entries`, `command_keys`) | each entry's canonical JSON; id `<file>#<event>@<digest>` |
| Helper commands in the person's settings (`apiKeyHelper`, `statusLine`, …) | `SettingsReader::programs` (Claude Code's reader, also Copilot CLI's) | the command; id `<file>#<key>` |
| A project's settings files in the hook file's layout | `Ledger::project_hook_files` under `ProjectSettingsSpec::dir` | each entry, as above |
| A project's hook directory (`.github/hooks`, `.pi/extensions`, `.opencode/plugins`) | `ProjectSettingsSpec::hook_dir` | JSON files as entries; code by its bytes |
| A project's plugin directory (goose, Antigravity CLI) | `ProjectSettingsSpec::plugin_dir` | each entry of the plugin's hook file |
| Installed plugins (Claude Code's `plugins/cache/<marketplace>/<plugin>/<version>`, plugins under `skills/`) | `Ledger::plugin_hooks` (`hooks/hooks.json`, the manifest's `hooks` paths or inline map) | each entry |
| Other hook files (Cline's `PreToolUse` files and plugins) | `OtherHooks` | the file's bytes (a directory by every file in it) |
| The repository's git configuration | `project_settings/git_config.rs` (`programs`) | each value; id `<file>#<key>` |

A file that is not JSON where JSON was expected is pinned by its bytes, so it is named
like any other change rather than skipped.

Each new or changed entry is classified by the existing shell classifier under the
person's effective policy (`Action::Shell` per command, strictest wins). A file of code
has no command to classify and counts as `review`.

### 2. What a change does

While an entry the calling agent loads (or the repository's git configuration names)
is new or differs from its pin:

- **Its command is one the classifier denies** (`curl … | sh`, a download piped to a
  shell): `openmoat guard` denies every call of that agent with rule `foreign-hook`
  until a person accepts it.
- **Anything else** (a command that classifies as `review`, `defer` or `allow`, a file
  of code with no command to classify, a `.git/config` program such as
  `core.fsmonitor` whose value is not denied): no call's verdict changes. `openmoat
  status` names it under "Needs your attention", `openmoat doctor` and `openmoat watch`
  name it too, each with its verdict, the rules behind it and the fix, `openmoat hooks
  accept`.
- **`hooks.foreign: hold`** in the person's policy (default `warn`) holds the calls for
  every such entry instead: `review`, or `deny` where the command is denied, as above.
  Only the person's policy holds the key; a repository policy or a pack with it does
  not parse (the same rule as `unattended:`, ADR-102).

The tightening is applied last, after a person's grant, which cannot answer it; it
only tightens. A host that cannot prompt receives a review as a deny, as for every
other review. MCP tool calls held by their own pins and calls of ungoverned tools are
decided before it and are not held by it.

Why the default warns: OpenMoat denies what must never happen and otherwise stays
quiet and leaves the call to the person. A plugin update or a project's
`.git/config` change that adds an ordinary command is a common, legitimate event;
holding every call of the agent for it stops the session for something the person
will almost always accept, and teaches them to accept without looking. A command the
policy denies is what must never happen, so it still stops the session. The program
has usually run already either way (a `SessionStart` hook runs before any tool call),
so the hold never prevented the run; what it adds is a stop, which `hold` keeps for a
person who wants it.

`openmoat status` and `openmoat doctor` count an entry that holds calls as a problem
(`status` exits 64) and one that does not as a warning, which leaves the exit code
alone, as a hook liveness warning does (ADR-104): OpenMoat is set up as it should
be, and only the person can judge the hook. `status --format json` gives each
entry's `holds`. `openmoat watch` prints one line when an entry appears, as it does
for liveness. `openmoat hooks list` lists the ledger and what waits, and exits 64
while something waits. `openmoat hooks accept` shows each change and records it on yes: it refuses
without a terminal, with an agent among its parents (`terminal::refuse_agent`) and
over a drifted lock; the default policy denies `openmoat hooks accept` to agents
(`kernel-self`, attack fixtures `T9-agent-accepts-its-own-foreign-hook`,
`…-by-path`, `T9-script-wraps-openmoat-hooks-accept`). `openmoat doctor --accept`
asks through the same code. A pin of a scanned file whose entry is gone is dropped on
accept; pins of files the scan did not read (another project's) stay.

### 3. Migration

A lock from before this ADR has no `hook_ledger` and holds nothing; `status` and
`doctor` say the hooks are not recorded yet. The first `openmoat init`, `openmoat
hooks accept` or `openmoat doctor --accept` records what is there. The first record by
`init` records everything found even without a person at the terminal, so an
upgrade never blocks what was there before it. After that, an `init` with no person
at the terminal leaves new and changed entries for `openmoat hooks accept`, as it
leaves MCP definitions (ADR-026), and an `init` by a person prints each one it
accepts, so none is accepted unseen. Re-pins (`allow`, `trust`, `doctor --accept`, …)
carry the ledger over unchanged, as they carry the MCP pins.

### 4. Fail-safe hook commands

Where a host reads exit 2 as a block and runs the call on any other failure, the hook
command OpenMoat installs ends in a tail that turns every status but the guard's own
0 or 2 into exit 2 with a reason on stderr (`wire/guard_command.rs` `SH_TAIL` for
POSIX shells; Codex's Windows command does the same in PowerShell). The guard's
answer on stdout stands. Recognition of OpenMoat's entries strips the tail first.

| Agent | Before | Change | Source of the exit-2 block |
|---|---|---|---|
| Codex | missing, crash, timeout run the call | missing or killed blocks (POSIX and Windows) | [hooks](https://learn.chatgpt.com/docs/hooks), [command_runner.rs](https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/hooks/src/engine/command_runner.rs#L417) (exit 2 with stderr blocks) |
| Gemini CLI | killed or exit 1 runs the call | killed blocks | [hooks reference](https://geminicli.com/docs/hooks/reference/) ("Exit 2: System Block"), [hookRunner.ts](https://github.com/google-gemini/gemini-cli/blob/v0.65.0/packages/core/src/hooks/hookRunner.ts) |
| Qwen Code | missing, crash run the call (POSIX) | blocks | [hooks](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/), [hookRunner.ts](https://github.com/QwenLM/qwen-code/blob/main/packages/core/src/hooks/hookRunner.ts) |
| Crush | missing, crash run the call | blocks | [hooks README](https://github.com/charmbracelet/crush/blob/main/docs/hooks/README.md), [runner.go](https://github.com/charmbracelet/crush/blob/main/internal/hooks/runner.go) |

Their `HookFailure::fails` is now `Blocks`; the weekly real-agent job (ADR-079)
checks that claim against the released agents and fails if one runs the call.

What remains, with no documented setting that changes it:

- **Timeouts** still run the call for Codex, GitHub Copilot CLI (`timeoutSec`, set to
  600 s), Gemini CLI, Qwen Code, Crush, Cline (120 s) and Antigravity CLI (not
  documented). The guard denies on its own after 30 s (`GUARD_BUDGET_S`), below every
  host's limit, so a timeout means the guard process was stopped, not slow.
- **Claude Code before 2.1.295** has no `onFailure`; `init` writes it where the
  version knows it (ADR-079). Its command is not given the tail: the versions that
  need it are old, and changing every Claude Code entry would ask each person to
  re-accept the hook file.
- **Cline** already prints its own `cancel` from its script; it runs the call when
  the script cannot start (no `sh` on native Windows) or is killed after 120 s.
- **The Continue CLI** fires no hook in its released versions.
- **Gemini CLI, Qwen Code on Windows** already end in `POWERSHELL_TAIL`.
- A setting that turns hooks off is not a failure: the table's "Turned off" column
  and `openmoat status` stay the answer.

Rewriting the entry makes existing ones stale until `openmoat init` runs again
(`status` says so); Codex then asks the person to trust the changed hook in `/hooks`,
as for any change of its command.

### 5. Faster liveness

`Liveness::started` (Claude Code: the `SessionStart` event, the `PreToolUse` matcher,
and a reader of transcript lines' `tool_use` blocks) lets `openmoat status`, `doctor`
and `watch` warn at once: a session whose start the guard recorded since the last
change, whose own transcript was made at that start (not a resumed one's), names a call
of a tool OpenMoat's entry covers, was last written at least the guard's budget (30 s)
ago, and of which no call reached the guard. That is `Loaded::Unchecked`, a warning
with the fix ADR-104 gives. A matcher this code cannot read (anything but
`A|B|prefix.*`) turns the check off for that host. It never decides a call.

## Consequences

- A plugin update or settings edit that adds a hook is named by `status`, `doctor`
  and `watch` until a person accepts it; one that pipes a download to a shell denies
  the agent's calls until then, and `hooks.foreign: hold` holds them for any. The
  program itself may already have run (a `SessionStart` hook runs before any tool
  call): the ledger makes the change visible, and stops the session's tool calls only
  where it denies or holds them; it does not undo it. Only `openmoat run` keeps such
  programs in a sandbox.
- A new hook whose command the classifier does not deny but that does harm (a script
  file it runs, an ordinary-looking command) is not stopped by default: it is reported,
  and the person decides. `hooks.foreign: hold` is the setting for a machine where
  every new hook must wait for a person.
- Hosts and places not in a spec are not read: Gemini CLI and Qwen Code extensions,
  GitHub Copilot CLI and Codex plugins, OpenClaw and Hermes Agent plugins beyond
  OpenMoat's, and pi's and OpenCode's user extension folders. Each needs its source
  read before a spec fact is added.
- Every guarded call reads the calling agent's hook, settings and plugin files and
  the repository's git configuration (bounded: 1 MiB a file, 256 directories a level,
  512 files a plugin directory).
- `openmoat status` exits 64 while something that waits for `openmoat hooks accept`
  holds the agent's calls; a warning alone leaves it at 0.
- A policy with `hooks:` is refused by a release from before the key (unknown keys
  are rejected), whose guard then denies every call.
- The lock gains a section older builds ignore; a downgrade keeps working without the
  ledger.
