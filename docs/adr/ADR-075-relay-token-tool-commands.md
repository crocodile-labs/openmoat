# ADR-075: tool commands do not receive the relay token

Status: accepted · Date: 2026-11-09 · Amends ADR-028, ADR-070, ADR-071

## Context

Under `openmoat run` the agent, its hooks and its tool commands share one sandbox and
one user. `MOAT_GUARD_SOCKET` and `MOAT_GUARD_TOKEN` are in the agent's environment, so
every tool command inherits them, and a tool command holding them can add misleading
audit rows for its own agent and sessions and can probe policy decisions.

The aim is that tool commands do not receive the token, while hooks keep it. It is not
a binding of the token to the hook process: ADR-071 section 4 explains why no host gives
a way to do that. This ADR records what is true of each host and each OS, then what was
built on it.

## Step 0: the facts

Sources were read on 2026-11-09. Line numbers are left out because the files move;
names of files and functions are given instead.

### 1. A tool command reading the token from its parent

Removing the variables from a tool command's environment is worth nothing if the tool
command can read them from the agent.

**Linux.** `/proc/<pid>/environ` and `/proc/<pid>/mem` are the route.

- Landlock path rules apply to `/proc`, a user-visible filesystem. The default policy's
  read roots do not include `/proc` or `/`, so under `openmoat run` a process opening
  `/proc/<pid>/environ` is refused today, for the agent, its hooks and its commands
  alike. A person's policy that adds `/proc` or `/` to `sandbox.read_roots` opens it.
- A second, independent check: a process in a nested Landlock domain cannot use ptrace
  access on a process in an outer domain (`domain_ptrace` and `domain_scope_le` in the
  kernel's `security/landlock/task.c`; the [Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
  says sensitive `/proc` files "are automatically restricted according to domain
  hierarchies"). `/proc/<pid>/environ` and `mem` are opened through a ptrace access
  check, so a tool command that a wrapper has placed in a nested domain cannot read
  either from the agent, even where a policy grants `/proc`.
- `ptrace`, `process_vm_readv` and `pidfd_getfd` are already refused by the run's
  seccomp filter (`commands/run/linux.rs`, `DENIED`).
- A core dump of the agent (`prlimit` on the agent, then a signal) needs the agent to be
  killed; the run ends with it and the token dies with the run. Landlock's signal
  scoping (kernel 6.12) also stops the signal.

**macOS.** The route is the `KERN_PROCARGS2` sysctl, which `ps eww` uses.

- XNU's `sysctl_procargsx` checks only that the caller has the target's uid or is root
  (`bsd/kern/kern_sysctl.c`). Nothing in it asks the sandbox about the target.
- The run's Seatbelt profile allows `sysctl-read` for every name today, so this read
  works under `openmoat run`.
- XNU passes each sysctl to the sandbox by name, with the integer elements of the call
  appended (`sysctl_root` in `bsd/kern/kern_newsysctl.c`: `kern.procargs2.<pid>`), so
  `(deny sysctl-read (sysctl-name-prefix "kern.procargs"))` covers it. `sysctl-name-prefix`
  is a filter Apple's own profiles use.
- `/bin/ps` is setuid root, which does not take it out of the sandbox.
- Reading another process's memory needs `task_for_pid`, which the profile's
  `(deny default)` does not allow.

The attack is an end-to-end test (`tests/e2e/relay_token.rs`). macOS's rule has not been
exercised on a real Mac yet: nested `sandbox-exec` cannot run where this was written.
CI's macOS jobs run the test.

### 2. How each host starts hooks and tool commands

"Facts" names the sources. UNKNOWN means the source does not say. Versions: Codex
`main` at 27fcd7cb; Gemini CLI `main` a7bf415 and v0.67.0; OpenCode v1.19.5 and `dev`;
goose `main` 0edf2bd and v1.57.0; Cline `main` 5413dc1 and v4.1.26; pi `main` 5c37d3b;
Hermes Agent `main` aa5fb1c; OpenClaw `main` 81ab38d; Continue CLI `main` 5522c6f.
Claude Code, Cursor and GitHub Copilot CLI are closed source: their docs only.

| Host | Tool command | Hook | Per-run tool-only setting |
|---|---|---|---|
| Claude Code | `CLAUDE_CODE_SHELL`, else `$SHELL` when it points to `bash` or `zsh`, else a search. A value that is not a working `bash` or `zsh` is ignored without a word. Argv and the test of "working": UNKNOWN. ([env-vars](https://code.claude.com/docs/en/env-vars)) | `sh -c`; exec form runs `command` directly, no shell. Inherits the environment. ([hooks](https://code.claude.com/docs/en/hooks)) | `CLAUDE_CODE_SHELL` (tools only). `CLAUDE_CODE_SHELL_PREFIX` also wraps shell-form hooks. `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` also strips hooks. |
| Codex | Passwd shell through `getpwuid_r`; `$SHELL` is not read; `-lc` by default. (`shell-command/src/shell_detect.rs`, `core/src/shell.rs`) | The session shell with `-c`; else `$SHELL -lc`. Environment captured from the process. (`hooks/src/engine/command_runner.rs`) | `-c shell_environment_policy.…`. Snapshots replay names the policy admits, so an exclude is required, not a `set`. Whether a `-c` array replaces the person's own `exclude`, and whether `filters` exists at the release this project checks, were not confirmed. |
| Cursor | UNKNOWN for the agent's commands ([terminal](https://cursor.com/docs/agent/tools/terminal)) | UNKNOWN ([hooks](https://cursor.com/docs/hooks)) | None documented |
| GitHub Copilot CLI | UNKNOWN | `bash`/`command` fields, or `exec` with no shell. Environment: UNKNOWN. ([hooks](https://docs.github.com/en/copilot/reference/hooks-configuration)) | `--secret-env-vars` removes names from shell and MCP environments; its effect on hooks: UNKNOWN |
| Gemini CLI | `bash -c` found on `PATH`; `$SHELL` is not read (`shell-utils.ts`, `shellExecutionService.ts`) | The same `bash -c` (`hookRunner.ts`) | None: the redaction settings reach hooks too |
| OpenCode | Config `shell`, else `$SHELL`; basenames `fish` and `nu` refused, any other accepted (`core/src/shell.ts`, `shell/select.ts`) | In-process plugin, which spawns `openmoat guard` itself | `$SHELL` (when the person's config sets no `shell`) |
| goose | `GOOSE_SHELL`, else `bash` or `sh`; not validated (`developer/shell.rs`) | `sh -c`, whole environment (`hooks/mod.rs`) | `GOOSE_SHELL` |
| Cline CLI | `/bin/bash -c`, absolute; `$SHELL` is not read (`sdk/.../executors/bash.ts`) | Exec form with `process.env` (`hook-file-hooks.ts`) | None found in the CLI |
| pi | `shellPath` setting, else `/bin/bash`; `$SHELL` is not read (`utils/shell.ts`). Environment copied from `process.env` at each call. | In-process extension, which spawns `openmoat guard` itself (`core/exec.ts`, OpenMoat's `integration/openmoat.js`) | No flag or variable. The extension shares the process, so it can take the variables out of `process.env`. |
| Hermes Agent | Foreground: `bash` found on `PATH` (`pm/shell.py`). Background and PTY: `$SHELL` when its name is `bash`, `zsh`, `sh`, `dash`, `ksh` or `mksh`. Snapshot of `export -p` is replayed into later commands. (`tools/environments/`, `tools/process_registry.py`) | Exec form, whole environment (`agent/shell_hooks.py`) | `PATH` and `$SHELL` |
| OpenClaw | `$SHELL` in the gateway's environment, arguments picked by basename (`agents/shell-utils.ts`) | In-process plugin, which spawns `openmoat guard` itself | `$SHELL`, when the gateway starts under `openmoat run` |
| Continue CLI | `$SHELL -l -c`, or `/bin/bash`; no validation (`tools/runTerminalCommand.ts`) | `/bin/sh -c`, whole environment (`hooks/hookRunner.ts`) | `$SHELL` |

Snapshots and login start-up can only return a value that is somewhere they can read.
Stripping the variables before the shell starts leaves none, except where a host writes
the environment to a snapshot from a process that still holds it (Codex, without an
exclude).

### 3. Other children

| Host | MCP stdio | Others |
|---|---|---|
| Claude Code | Inherits, unless `CLAUDE_CODE_MCP_ALLOWLIST_ENV=1` | Background Bash is the Bash tool. Subagents, LSP, plugin monitors: UNKNOWN |
| Codex | Fixed list plus configured names: no relay variables | Unified exec goes through the tool shell's policy |
| Cursor | UNKNOWN | UNKNOWN |
| GitHub Copilot CLI | Only `PATH` and configured names | Detached shells: UNKNOWN |
| Gemini CLI | Started directly; the token is stripped by name, the socket is not | `tools.discoveryCommand` and `callCommand`: whole environment |
| OpenCode | Whole environment | PTY: whole environment; goes through the shell |
| goose | Whole environment | Subagents in-process; background jobs in the tool shell |
| Cline CLI | Whole environment | Detached commands: tool path. Plugins: UNKNOWN |
| pi | Whole environment, from `process.env` when started | `pi.exec` and subagent examples: `process.env` |
| Hermes Agent | Allowlist: no relay variables | Background and PTY through the wrapper; subagents in-process |
| OpenClaw | UNKNOWN | Plugin children: inherit by default. PTY and background through the shell |
| Continue CLI | Whole environment | Background jobs through the shell |

## Decision

Tool commands do not receive the relay token where the host gives a way to tell them
from its hooks. Where it does not, nothing changes and OpenMoat says so.

### The sandbox rule

- **macOS:** the run's Seatbelt profile denies `sysctl-read` of `kern.procargs*`, for
  every process in the run, the hook's included. A process's own arguments come from
  the C runtime, so programs do not need this call; `ps` still lists processes.
- **Linux:** nothing is added to the run's policy. A policy that grants `/proc` is still
  covered for a command the wrapper started, by the nested Landlock layer below.

### The wrapper

`openmoat run` makes a directory of its own (`openmoat-tools-<random>`) in the system's
temp directory, holding links named `bash` and `zsh` to the `openmoat` binary, and
points the host's tool shell at one of them (`commands/run/tool_shell.rs`). Started
under one of those names with `MOAT_TOOL_SHELL_DIR` set, the binary:

1. drops `MOAT_GUARD_SOCKET`, `MOAT_GUARD_TOKEN` and its own variables, and puts back
   the person's `SHELL`;
2. on Linux, when it held the token, adds one Landlock layer that restricts nothing but
   hides the agent's `/proc/<pid>/environ` and `mem` from the command. Failing to add it
   refuses the command. Signals stay allowed: a later command must be able to stop what
   an earlier one left running;
3. replaces itself with the real shell, looked up by name.

The wrapper never reads the command it is given, so a tool command cannot keep the token
by writing a hook's command line. The directory is read-only to commands: a run whose
write grants (the project, `--write`, the run's temp directory) hold it gets no wrapper,
because a command could then replace it, and `openmoat run` says so when it starts. MCP servers `openmoat mcp proxy` starts lose the
two variables too.

### Each host (`HostSpec::tool_token`)

| Host | Result | How | Limits |
|---|---|---|---|
| Claude Code | Withheld | `CLAUDE_CODE_SHELL`, `SHELL` | A value Claude Code does not accept is ignored silently, so the weekly real-agent job checks that the Bash tool starts through the shell it names. MCP servers it starts inherit the token. |
| OpenCode | Withheld | `SHELL` | A `shell` in the person's config outranks it. MCP servers and PTY sessions inherit the token. OpenCode 2's tool path was read from `dev`, not a release. |
| goose | Withheld | `GOOSE_SHELL` | MCP servers inherit the token. |
| Hermes Agent | Withheld | `bash` first on `PATH`, `SHELL` | Its MCP servers already get an allowlist. |
| OpenClaw | Withheld | `SHELL` | Only for a gateway started by `openmoat run`. MCP servers: not known. |
| Continue CLI | Withheld | `SHELL` | MCP servers inherit the token. |
| pi | Withheld | The extension takes the variables out of `process.env` and hands them to the guard alone | MCP servers started before the extension loads keep them. A second pi started inside the run gets no token, so its hook denies every call. |
| Codex | Not withheld | | Codex reads its shell from the login record. Its `shell_environment_policy` could do this, but a `-c` array may replace the person's own exclusions, and `filters` was not confirmed at the release checked. |
| Cursor | Not withheld | | Its documentation says neither how tool commands start nor how to change their environment. |
| GitHub Copilot CLI | Not withheld | | `--secret-env-vars` might do this; whether hooks lose the variables too is not documented. |
| Gemini CLI | Not withheld | | Tool commands and hooks both run `bash` from `PATH`. |
| Cline CLI | Not withheld | | `/bin/bash`, absolute, with no CLI setting. |
| Antigravity CLI | Not withheld | | Its documentation does not say how tool commands and hooks start, or which environment they get; nothing was checked on a running `agy` (ADR-074). |

A host OpenMoat does not recognise gets no wrapper.

### What is reported

`openmoat doctor` names the hosts in each group and says the row is not tested on the
machine. `openmoat bench --report` runs the attack of step 0 under the sandbox and shows
NOT TESTED HERE where it cannot. The weekly real-agent job checks Claude Code's routing;
the others need the fake model to serve an allowed command, which it does not yet.

## Consequences

- A tool command of a withheld host cannot add rows to the run's sessions or probe
  decisions through the relay. ADR-070's bindings stay.
- Described as "tool commands do not receive the token", never as binding it to the
  hook process: an MCP server or a plugin on the host's side still can hold it.
- Every process in the run's sandbox on macOS loses `KERN_PROCARGS2`. `ps` shows other
  processes without their arguments; a tool that needs another process's argument list
  fails.
- Inside the run on macOS, the check for an agent among a command's parents reads `ps`
  and so no longer sees an interpreter's script name. It guards commands that write the
  state directory, which the sandbox refuses anyway.
- Where the attack test cannot run (a Linux kernel without Landlock ABI 4, macOS before
  13), `openmoat run` refuses anyway.
