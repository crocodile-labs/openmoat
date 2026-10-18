# Adding an agent

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you add support for another AI coding agent: adapter, installer, fixtures, tests and docs.

**On this page:** [What an adapter is](#what-an-adapter-is) · [Before you write code](#before-you-write-code) · [Checklist of files](#checklist-of-files) · [Map the payload to an Action](#map-the-payload-to-an-action) · [Answer allow, defer, ask or deny](#answer-allow-defer-ask-or-deny) · [Install, uninstall and the lock](#install-uninstall-and-the-lock) · [The config directory variable](#the-config-directory-variable) · [Fixtures](#fixtures) · [End-to-end tests](#end-to-end-tests) · [Be honest about coverage](#be-honest-about-coverage) · [The pull request](#the-pull-request)

How to add support for another AI coding agent: a *host adapter*. Claude Code, Codex
and Cursor are maintained by the project; other agents come from contributors and are
reviewed by maintainers. `AGENTS.md` ("Add a host adapter") is the short version of
this guide; this file explains each step.

## What an adapter is

An agent that supports hooks runs a command before each tool call, passes the call as
JSON on stdin and reads an answer from stdout. `moat init` installs
`moat guard --host <id>` as that command. For each call, `guard`:

1. reads the payload and asks the adapter to turn it into a `HookRequest` (host,
   session id, call id, working directory, tool name, and an `Action` or none);
2. decides with `openmoat-core` and records the decision in the audit log;
3. asks the adapter to render the agent's response document, and exits 2 on a deny.

Adapters live in `crates/openmoat-hosts`. They translate; they never decide. The full
flow is in [ARCHITECTURE.md](ARCHITECTURE.md) §2–3.

If the agent has no hook that runs before a tool call, it cannot get an adapter. Point
its users at `moat run` ([SANDBOX.md](SANDBOX.md)) instead.

## Before you write code

- Open an issue (or comment on the existing one for the agent) with links to the
  agent's hook documentation: event names, payload fields, response format, what it
  does when the hook crashes or times out, and the variable that moves its config
  directory.
- List every tool the agent has and which of them its hooks report. This list becomes
  the coverage table and the "ungoverned" line in the threat model.

## Checklist of files

| File | What to add |
|---|---|
| `crates/openmoat-hosts/src/<agent>.rs` | `parse` (payload → `HookRequest`) and `render` (`Decision` → response), with unit tests |
| `crates/openmoat-hosts/src/lib.rs` | `mod`, a `Host` variant, `id()`, `display_name()`, `Host::ALL`, the dispatch in `parse_request` and `render_response`, `answer` if the agent cannot ask, the host list in `HostError::UnknownHost` |
| `crates/openmoat-cli/src/install.rs` | a `HookSpec` list, `dir_variable`, the file name and `HookFormat` in `HostConfig::at` |
| `crates/openmoat-cli/src/install/hook_file.rs` | only if the hook file has a new layout: a `HookFormat` variant in `desired_entry`, `is_ours`, `hook_binary` and `remove` |
| `crates/openmoat-cli/src/context.rs` | the config directory and its variable in `moved_dirs` |
| `tests/fixtures/hosts/<agent>/` | captured payloads and a `README.md` naming each one's source |
| `crates/openmoat-cli/tests/e2e/<agent>.rs` | end-to-end tests, registered in `e2e/main.rs` |
| `docs/INSTALL.md`, `README.md` | a row in the hooks table and in "Supported agents" |
| `docs/ARCHITECTURE.md` §3, `docs/THREAT_MODEL.md` §5 | the tool mapping rows and the agent's limits |
| `CHANGELOG.md` | an `### Added` line under Unreleased |

The compiler points at every other `match` on `Host` that needs a new arm. Lock pinning,
`moat status`, `moat doctor` and `moat uninstall` loop over `Host::ALL`, so they pick up
the new agent without further code.

## Map the payload to an `Action`

Copy the shape of `cursor.rs` (its own format) or `pre_tool_use.rs` (the Claude Code
format). If the agent sends Claude Code's `PreToolUse` document unchanged, reuse that
parser through `Host::wire`, as the Continue CLI does (`continue_cli.rs`).

| The tool | `Action` | Example |
|---|---|---|
| runs a POSIX shell command | `Shell { command }` | Claude Code `Bash`, Cursor `beforeShellExecution` |
| runs a shell OpenMoat cannot parse | `ForeignShell { shell, command }` (always `unparseable`: `defer` under the default policy) | Claude Code `PowerShell` |
| reads one file or directory | `FsRead { path }` | `Read`, `beforeReadFile` |
| reads several | `ReadFiles { paths }` | `SendFile`, Cursor search tools |
| searches a directory | `FsRead` of its path, else the working directory (`search_root`) | `Grep`, `Glob` |
| writes, edits or deletes a file | `FsWrite { path }` | `Edit`, `Write`, `Delete` |
| applies a multi-file patch | `Patch { writes }` | Codex `apply_patch` (`patch.rs`) |
| fetches a URL with no request body | `Fetch { url }` | `WebFetch` (ADR-017) |
| opens a connection that can send data | `Net { url }` | `Monitor` WebSocket |
| calls an MCP tool | `mcp::action("mcp__<server>__<tool>", input)` | `mcp.rs` finds path and URL arguments |
| a tool the hook receives for every tool and cannot classify | `UnknownTool { host, tool }`: `defaults.tool.unknown` decides, `defer` in the default policy | Cursor `preToolUse` |
| anything else | `None`: recorded with rule `ungoverned` and deferred to the host (no output) | `TodoWrite`, `Task` |

Rules the existing adapters follow:

- **A missing or empty field is an error, not a guess.** Use `input_str`, which returns
  `HostError::MissingField`. `guard` answers every `HostError` with a deny. The Continue
  CLI sends `Read` `filepath` instead of `file_path`, and that call is denied as
  malformed rather than passed.
- **Arguments you cannot read are `MalformedArguments`**, never ignored.
- **Read every path a tool can touch.** Cursor's `preToolUse` reads every path key a
  tool carries, so a file tool the adapter does not know is checked, not passed.
- **Mark a tool `None` only when another hook governs it** (Cursor `Shell` under
  `preToolUse` is decided by `beforeShellExecution`) **or it touches no file, command
  or network.**
- **Return `HostError::WrongEvent` for an event the adapter does not handle.**
- Keep the agent's session id (`session_or_unknown`) and call id. Grants, session
  taint and `moat allow --last` depend on them.

## Answer allow, defer, ask or deny

`render` writes the response the agent expects; `reason_line` gives the one-line reason
for the model and the person. On a deny, `guard` also prints the reason on stderr and
exits 2, so write the response even if the agent only reads the exit code.

A `defer` (ADR-025) means OpenMoat neither objects nor vouches: the agent's own
permission flow decides, as it would without OpenMoat. For an agent that runs its own
flow when a hook gives no answer, render nothing and exit 0, as `pre_tool_use.rs` does.
An agent with no such answer needs a mapping: Cursor's shell and MCP hooks send it as
`ask` (`cursor.rs`), and for events that cannot prompt `Host::decided` records and
answers it as `ask`. Find out from the agent's source which applies.

Some agents cannot ask. Codex rejects `ask` and runs the call; the Continue CLI ignores
it; Cursor accepts `ask` on `preToolUse` but runs the call, and `beforeReadFile` takes
only allow or deny. For these, `Host::answer` turns an `ask` into a `deny` and adds a
line saying how to approve it (`CODEX_ASK`, `CONTINUE_ASK`, `CURSOR_ASK`). The audit
log keeps the `ask`, which is what `moat` and `moat allow --last` look for. If the
agent cannot ask, add a constant and an arm to `answer`. If it can ask only on some
events, return `HookEvent::PreToolUseNoAsk` for the others, as `cursor.rs` does.
Verify from the agent's documentation or source code what it does with each answer.
When the documentation and the agent disagree, trust the agent, and say which you
checked in the fixtures `README.md`.

## Install, uninstall and the lock

`moat init` calls `HostConfig::install`, which adds one entry per `HookSpec` (event,
matcher, timeout) to the agent's hook file. It must stay idempotent (invariant 8):

- Our entries are recognised by their command, `guard --host <id>`; re-running `init`
  updates them in place and never adds a second one.
- Other keys and other hooks in the file are kept.
- The file is copied to `<file>.moat-backup` before the first edit.
- The matcher must name every tool the adapter maps. A tool missing from it never
  reaches `guard` (see `TOOL_MATCHER`).
- Use a timeout of `TOOL_HOOK_TIMEOUT_S` (600 s), long enough for a person to answer a
  prompt.

`moat uninstall` calls `HostConfig::remove`, which deletes only our entries and any
event list or `hooks` object that leaves empty. Test that installing and then removing
gives back the original file (`hook_file.rs` tests).

`moat init` pins every installed hook file in `~/.moat/policy.lock`
(`integrity::installed_hook_files` loops over `Host::ALL`). If the file changes, the
next tool call is denied with `kernel-integrity` until a person runs `moat init` or
`moat doctor --accept`. Only Claude Code has a `ConfigChange` event that catches the
edit as it happens; for other agents, say in the threat model that a tampered hook file
is caught on the next tool call.

The default policy's `kernel-self` rule protects the known agent directories and hook
files from the agent's own writes. Adding the new agent's paths there is a policy
change: it needs an attack fixture in `tests/conformance/` and is `risk: high`, so it
can be a separate PR.

## The config directory variable

Most agents let a variable move their config directory (`CLAUDE_CONFIG_DIR`,
`CODEX_HOME`, `CURSOR_CONFIG_DIR`). Add the agent's variable and default directory to
`dir_variable` and `moved_dirs`. `moat init` installs where that variable points and
records the directory in `~/.moat/hosts.json`, and later commands use the record. An
agent counts as present when its directory exists; `init` names an agent whose variable
points at a missing directory instead of skipping it silently.

## Fixtures

Golden payloads go in `tests/fixtures/hosts/<agent>/*.json`. They must be real payloads
captured from the agent, not built from the documentation. When only documented field
names are available, say so in the folder's `README.md`, as
`tests/fixtures/hosts/cursor/README.md` does.

To capture one safely:

1. Point the agent at a scratch config directory with its variable, never your own
   (`AGENTS.md` §7).
2. Install a hook there that only copies stdin to a file, such as `cat > /tmp/payload.json`,
   and run a harmless tool call in a throwaway project.
3. Replace tokens, emails, user names and absolute paths with placeholders: `/p` for
   the project, `/Users/me` for the home directory. Keep field names and structure as
   they are.
4. Record the agent version and capture date in the `README.md`.

Cover every tool kind the agent exposes, at least one ungoverned tool, and the
agent-specific quirks (an empty `cwd`, a JSON string for MCP arguments). In the unit
tests, add a malformed payload, a payload missing a required field, and an event the
adapter does not handle.

## End-to-end tests

`crates/openmoat-cli/tests/e2e/cursor.rs` is the model. `Sandbox::installed(&[".<agent>"])`
runs the real `moat init --yes` with an isolated `HOME`, and `sb.guard("<id>", payload)`
runs the hook. Test at least:

- `init` writes one entry per event, with the fail-closed flag if there is one, and a
  second `init` changes nothing;
- a secret read or exfiltration fixture is denied with exit 2 in the agent's format;
- a safe call is allowed;
- an `ask` arrives as the agent needs it (a deny with `moat allow --last` if it cannot
  ask);
- a deferred call is left to the agent (no output and exit 0, or the agent's own
  prompt) and is not denied;
- malformed arguments are denied;
- `moat uninstall` removes the entries (see `e2e/uninstall.rs`).

## Be honest about coverage

- **List every tool the hook does not see** under "Ungoverned tools" in
  [THREAT_MODEL.md](THREAT_MODEL.md) §5, and in the INSTALL.md table. Never claim
  coverage the code does not have.
- **Fail closed where the agent allows it.** Every error in `guard` is a deny with exit
  2 (invariant 4). If the agent runs the call when the hook crashes, times out or
  cannot start, and it has a setting to block instead, `init` must set it (Cursor's
  `failClosed`). Add the agent's column to the "When the hook fails" table in
  THREAT_MODEL §5, with sources, and to `protection.rs` `gaps`; add its payload shape
  to `e2e/host_failures.rs`. Its hook timeout must stay above `GUARD_BUDGET_S`.
- Say whether the agent can ask, and what the person does when it cannot.

## The pull request

- Link the issue. Keep each PR to one concern and under 500 changed lines (`size: L`);
  split a large adapter into a stack, for example the adapter and its fixtures first,
  then the installer and e2e tests, then the docs.
- Title `host(<id>): …` or `feat: …`; branch `<type>/<topic>`. `pr-standards` sets the
  `type:`, `area: hosts`, `size:` and `risk:` labels (adapters and install are
  `risk: medium`; the default policy is `risk: high`).
- The body needs **Testing** and **Security impact**. Security impact states which tools
  are governed, which are not, and what happens on an ask and on a hook failure.
- Run `scripts/ci/quality-gate.sh` before you push.
