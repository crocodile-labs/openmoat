# ADR-098: A project that turns the hook off is refused before the agent starts; OpenMoat's hook where an administrator's hooks live

Status: accepted · Date: 2026-11-14 · Builds on ADR-018 (`openmoat run`), ADR-034
(`hook_only`), ADR-072 (project settings writes), ADR-079 (hook-failure facts),
ADR-090 (person-only `sandbox:` keys), ADR-091 (agent facts from host specs) · Numbered
098: 095 to 097 are taken by branches open at the time of writing

## Context

Seven of the thirteen hosts load settings from the project at session start that can
turn OpenMoat's user hook off: Claude Code's `.claude/settings.json` `disableAllHooks`,
GitHub Copilot CLI's repository `settings.json` with the same key, a trusted Codex
`.codex/config.toml` with `[features] hooks = false`, a trusted Gemini CLI folder's
`hooksConfig.enabled: false`, a pi `extensions` entry that excludes OpenMoat's
extension, an OpenCode `-openmoat` plugin entry, a goose `disabledPlugins` entry or a
project plugin named `openmoat`, an Antigravity CLI `.agents/hooks.json` with OpenMoat's
hook `enabled: false`. A cloned repository is the attacker's (THREAT_MODEL §2). The guard
denies a write that would leave such a file (ADR-072) and Claude Code's `ConfigChange`
blocks loading one mid-session, but a file that comes with the repository is loaded when
the session starts, before any call reaches the guard: `openmoat status` and `doctor`
could only say so afterwards.

Five hosts have a place for hooks an administrator deploys, which outrank the person's:
Claude Code's managed settings, Codex's `requirements.toml`, Cursor's enterprise
`hooks.json`, Copilot CLI's `policy.d`, OpenCode's system directory. OpenMoat read three
of them (to say when the installed hook does not run) and wrote none.

## Decision 1: the facts are each host's, with their sources

`HostSpec::hook_off` (`contract/hook_off.rs`, one `host/<module>/hook_off.rs` per host):

- `project`: `Files { example, source }` when a project file can turn the hook off, with
  one such file (path and text) that the tests write for every host, or `Nothing { why,
  source }`. Which keys do it stays the host's `SettingsReader::project_switched_off` over
  its `ProjectSettingsSpec` files, plus a plugin of its `plugin_dir` named as OpenMoat's:
  the same reading `status` and the guard's write check use.
- `session_override`: arguments of the host's that keep its hooks on for one session
  whatever a project sets, the top-level keys they replace, and the person's options that
  would take their place. Only Claude Code has one documented:
  `--settings '{"disableAllHooks":false}'` (the hooks reference: `--settings` "takes
  precedence over project and local settings"). The `--trust-workspace false` flag named
  in an early review is not in Claude Code's CLI reference and is not used.
- `managed`: `Written(ManagedHooks)` where OpenMoat writes its hook (the file per
  platform; a drop-in of its own or the host's one file; whether the host requires root
  ownership; whether the host's documentation says a project's settings cannot turn a
  hook there off; sources that make the host skip the file), `Manual { locations, why }`
  where the place exists but OpenMoat does not write it, `None { why }`.

| Host | Project turns the hook off | Session override | Managed hooks |
|---|---|---|---|
| Claude Code | yes (`disableAllHooks`) | `--settings` | written: `managed-settings.d/50-openmoat.json`; outlasts the project |
| Codex | yes, trusted project (`features.hooks`) | none | manual: `requirements.toml` `[hooks]` needs scripts under `managed_dir` |
| Cursor | nothing documented | none | written: enterprise `hooks.json` while missing or OpenMoat's alone; not documented to outlast a project |
| OpenClaw | nothing (Gateway configuration) | none | none |
| Copilot CLI | yes (`disableAllHooks`) | none | written, root-owned: `policy.d/openmoat.json`; outlasts the project |
| pi | yes, trusted project (`extensions`) | none | none |
| Gemini CLI | yes, trusted folder (`hooksConfig`) | none | manual: system settings, the administrator's one file |
| OpenCode | yes (`-openmoat`) | none | manual: system `plugins/`, removal by a project undocumented |
| Hermes Agent | nothing (person's profiles) | none | none |
| Cline CLI | nothing (project hooks add, never remove) | none | none |
| goose | yes (`disabledPlugins`, project plugin) | none | none |
| Antigravity CLI | yes (`.agents/hooks.json`) | none | none documented |
| Continue CLI | nothing (no hook) | none | none |

## Decision 2: `openmoat run` refuses before it starts the agent

Before the sandbox is made, for the agent `openmoat run` starts (told by its program
name, ADR-054) and only when OpenMoat's hook for that host is installed, the project's
files are read per spec in the working directory, every directory above it up to the
project root, and the root (OpenCode looks for its configuration up to the nearest git
directory, Codex reads each `.codex/` layer between the root and the working directory;
reading them all is the safe side for a host that reads fewer). Where the host's hook file
cannot be located the run is refused.

1. A host with a session override (Claude Code) gets it on **every** run, before the
   person's arguments, whether or not a file turns the hook off now: the host may reload a
   project's settings mid-session, and it applies one managed source, so a server-managed
   policy, a device profile or the Windows `HKLM` value would take the drop-in's place.
   For such a host the managed file never clears the check on its own. Not added when the
   person passes the same option (an option word before any `--`; a prompt that mentions
   it does not count), and not when the person's own settings turn hooks off: that is
   theirs, the run says so in one line and records `run-own-settings-hook-off`. A run
   where a file would have turned the hook off records `run-project-hook-off-overridden`.
2. For a host without one, OpenMoat's managed hook file holding its current hook, where
   the host's documentation says a project cannot turn it off and no shadowing source is
   present, lets the run start.
3. The person's own policy says `sandbox.project_hook_off: start`: honoured only while the
   policy lock matches (checked again here, after `openmoat run`'s own lock check); the
   run starts, warns that only the sandbox holds, and records `run-project-hook-off`
   before the agent starts (a row that cannot be written stops the run). A repository
   policy or pack has no `sandbox:` (ADR-090), so a repository can never set it; `openmoat
   policy check` warns while it is set.
4. Otherwise the run refuses (exit 64), records `run-project-hook-off-refused`, and names
   each file and what in it does it, and the ways out: remove the setting, `openmoat init
   --managed` where the host's managed hook outlasts the project, or the policy key.

A file that cannot be read counts as turning the hook off; text the host cannot parse
does not (the host refuses to load it). A file of a host that replaces text before parsing
it (OpenCode's `{env:…}` and `{file:…}`) counts when it holds such a marker, and so does a
`plugins`/`plugin` entry holding one in the guard's write check and `status`. A profile's
own `[profiles.<name>.features] hooks = false` counts for Codex, whichever profile is
chosen. A program OpenMoat cannot tell as an agent (`sh`, `npx`, `env`, a wrapper script)
is not checked.

## Decision 3: `openmoat init --managed` writes OpenMoat's hook where an administrator's hooks live

For each host set up in that run whose `managed` is `Written`, `init --managed` writes the
document `init` writes into the person's own hook file, started from an empty one (the
host reads both in the same format). It refuses without a terminal or with an agent among
its parents, like the other trust-widening commands (AGENTS §7). It is idempotent: a file
that already holds the current hook is left alone. A host's one file holding an
administrator's own hooks is never edited, nor removed, and a file it cannot read is never
written over, whatever its shape. A file written in place is `0644` in folders created as
the system creates them (`0755` under the usual umask): the host reads it for every
account. OpenMoat never escalates: where it cannot write the file itself, or the host
loads it only when root owns it (Copilot CLI), it keeps the file at
`~/.moat/managed/<host>.json` and prints the exact command: it first checks the kept
file's SHA-256, creates the folder only when it is missing (an existing folder's mode and
access list stay), then `sudo install -m 644 -o 0 -g 0` (an elevated PowerShell with
`-LiteralPath` on Windows). `openmoat uninstall` removes a
file that holds OpenMoat's hook alone, or prints the command that does. `openmoat doctor`
reports each set-up host's managed file: in place, missing, staged and not yet copied,
outdated, shadowed. For `Manual` hosts `init --managed` names the place and why OpenMoat
does not write it.

## Decision 4: the agent cannot change these places

The default policy's `managed-settings` rule, generated from each host's spec
(`tests/protect.rs`), covers the folders of every `managed` location besides the system
settings it covered: Copilot CLI's `policy.d`, Cursor's and OpenCode's system folders.
`~/.moat/managed` is inside OpenMoat's state directory, which `kernel-self` covers.

## Consequences

- A cloned repository can no longer start an `openmoat run` session of these hosts with
  OpenMoat's hook off without the person's own policy saying so.
- Outside `openmoat run` (the agent started directly) the gap stays: `status` and `doctor`
  still only report it. `init --managed` closes it for Claude Code and Copilot CLI, where
  the host's documentation says a project cannot turn a managed hook off.
- A managed file applies to every account of the machine, and its command names this
  person's binary and state directory: `init --managed` is for a machine one person uses,
  or an image an administrator builds. Another account's sessions would run a guard that
  cannot read that state directory, which fails closed.
- With both the person's hook and the managed one, a host runs OpenMoat's hook twice per
  call where it does not merge identical hooks: two decisions and two audit rows.
- Claude Code applies one managed source by default: a server-managed policy, a device
  profile or the Windows `HKLM` value takes the place of the files. OpenMoat sees the
  macOS profile and reports it, and `doctor` names the others it cannot see; under
  `openmoat run` the `--settings` override covers Claude Code whatever the managed source.
- Every Claude Code session under `openmoat run` starts with an extra `--settings`
  argument; a person who passes their own `--settings` keeps it and is checked as before.
- Not checked against real agents in this change: Claude Code honouring `--settings` over
  a project's `disableAllHooks` (also after it reloads the project's settings) and loading
  a drop-in without a `managed-settings.json`; Copilot CLI loading the policy file;
  Cursor's enterprise file outranking a project; whether a Codex profile's `features`
  apply; OpenCode's substitution and ancestor lookup as read from its documentation. Each
  is what the host's documentation says, or the safe side where it says nothing.
