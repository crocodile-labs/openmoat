# Adding an agent

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you add support for another AI coding agent: adapter, installer, fixtures, tests and docs.

**On this page:** [Smallest path first](#smallest-path-first) · [What an adapter is](#what-an-adapter-is) · [Before you write code](#before-you-write-code) · [Checklist of files](#checklist-of-files) · [Map the payload to an Action](#map-the-payload-to-an-action) · [Answer allow, defer, ask or deny](#answer-allow-defer-ask-or-deny) · [Install, uninstall and the lock](#install-uninstall-and-the-lock) · [The config directory variable](#the-config-directory-variable) · [Fixtures](#fixtures) · [End-to-end tests](#end-to-end-tests) · [Be honest about coverage](#be-honest-about-coverage) · [The pull request](#the-pull-request)

How to add support for another AI coding agent: a *host adapter*. Claude Code, Codex,
Cursor, OpenClaw, GitHub Copilot CLI, pi and Gemini CLI are maintained by the project; other agents come from contributors and are
reviewed by maintainers. `AGENTS.md` ("Add a host adapter") is the short version of
this guide; this file explains each step.

## Smallest path first

Take the first step that fits the agent:

1. **It sends a hook format OpenMoat already reads.** Write a spec only: one file,
   `crates/openmoat-hosts/src/host/<module>.rs`, with `speaks: Some(Host::ClaudeCode)`
   (or the host whose format it sends), and its line in the host list, ending in
   `speaks ClaudeCode`. The Continue CLI is this case (`host/continue_cli.rs`).
2. **It has a hook format of its own.** Write a spec, an adapter and, when its hook
   file has a layout no other agent uses, that layout in the CLI: every row of the
   [checklist](#checklist-of-files) applies.
3. **It has no hook that runs before a tool call.** It cannot get an adapter. Point
   its users at `openmoat run` ([SANDBOX.md](SANDBOX.md)), which runs the whole
   agent in an OS sandbox.

## What an adapter is

An agent that supports hooks runs a command before each tool call, passes the call as
JSON on stdin and reads an answer from stdout. `openmoat init` installs
`openmoat guard --host <id>` as that command. For each call, `guard`:

1. reads the payload and asks the adapter to turn it into a `HookRequest` (host,
   session id, call id, working directory, tool name, and an `Action` or none);
2. decides with `openmoat-core` and records the decision in the audit log;
3. asks the adapter to render the agent's response document, and exits 2 on a deny.

Adapters live in `crates/openmoat-hosts`. They translate; they never decide. The full
flow is in [ARCHITECTURE.md](ARCHITECTURE.md) §2–3.

If the agent has no hook that runs before a tool call, it cannot get an adapter. Point
its users at `openmoat run` ([SANDBOX.md](SANDBOX.md)) instead.

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
| `crates/openmoat-hosts/src/host/<module>.rs` | its `SPEC` (`HostSpec`: id, name, the format it sends, what it does with `ask`, what it does when the hook fails, what it does not cover, where its configuration lives and the hook entries `openmoat init` writes there (`install`: `InstallSpec` with `hooks`, one `HookSpec` per event with its matcher, timeout and whether it sets Claude Code's `onFailure`, and `hook_format`, the `HookFormat` of the file); `mcp`: where it reads MCP server definitions, as an `McpFile` and an `McpReader` for the user file and a list of project files with theirs, and how its hook payload names a server's tools (`McpNames`), so a call is traced to the definition it came from; a reader or a naming of its own goes in `host/<module>/mcp.rs`; `sandbox`: the OS sandbox OpenMoat writes into it, as a `SandboxFormat`, the file beside the hook file and why it is not written on native Windows, `None` when OpenMoat writes none; `project_settings`: the settings files a repository carries that the host merges over the user's, and the directory of hook or extension files it loads from a repository (`hook_dir`), which `openmoat doctor` and `openmoat status` warn about, the `reader` (a `SettingsReader`, in `host/<module>/project_settings.rs`, that names what a parsed file sets that turns OpenMoat's hook off or runs a program), and the person's own settings file (`user_file`), whose setting that turns OpenMoat's hook off makes those commands report the agent as not protected) and its `ADAPTER` (`HostAdapter`: `parse` for the events it handles, payload → `HookRequest`; `render`, `Decision` → response; for `openmoat bench`, `bench_payload`, `read_reply` and, if it cannot ask, `seen`), with unit tests; it ends with `..HostSpec::BASE`, so the fields it does not name take their defaults |
| `crates/openmoat-hosts/src/host/<module>/doc.rs` | `DOCS` (`HostDocs`): how OpenMoat is hooked and what protects its calls, as the README says them (`hook only`, or `hook + OS sandbox` when the spec has a `sandbox`), and one `ToolRow` per tool or group of tools the adapter maps, with the ungoverned ones; the spec sets `docs: doc::DOCS`. A test fails when the adapter matches a tool name no row names |
| `crates/openmoat-hosts/src/host/<module>/` | the rest of the adapter's code, one file per concern (`tools.rs`, `bench.rs`, `tests.rs`, as `host/pi/` has) |
| `crates/openmoat-hosts/src/host.rs` | one line in the host list, `Variant => module,` (`Variant => module speaks ClaudeCode,` for a spec-only agent), with a doc comment naming the agent and its hook. It gives the `Host` variant, `Host::EVERY`, `Host::ALL` (when the spec has an `install`), the `--host` id list and the lookups of the spec and adapter |
| `crates/openmoat-cli/src/mcp/servers.rs`, `crates/openmoat-cli/src/sandbox/` | only if the spec's `McpReader` has a new `McpSyntax` (a parser in `parse` and an editor in `wrap.rs`) or names a new `SandboxFormat` (a backend, and its arms in `sandbox/install.rs` and `commands/{sandbox,uninstall}.rs`) |
| `crates/openmoat-hosts/src/host/<module>/hook_file.rs` | only if the hook file has a new layout: a `HookFile` impl (`entry`, `is_ours`, `binary`), a `HookFormat` variant and its arm in `contract/hook_file.rs`; the CLI's `install/hook_file.rs` reads, backs up and writes the file |
| `crates/openmoat-core/policies/default-v1.yaml`, `tests/conformance/attacks.yaml` | the agent's configuration directory and hook file in `kernel-self`, with an attack fixture (a policy change, see [Install, uninstall and the lock](#install-uninstall-and-the-lock)) |
| `tests/fixtures/hosts/<id>/` | captured payloads and a `README.md` naming each one's source |
| `crates/openmoat-cli/tests/e2e/<module>.rs` | end-to-end tests, with a `mod <module>;` line in `crates/openmoat-cli/tests/e2e/main.rs`, and the agent's payload shape in `crates/openmoat-cli/tests/e2e/host_failures.rs` |
| `README.md`, `docs/INSTALL.md`, `docs/ARCHITECTURE.md` §3, `docs/THREAT_MODEL.md` §5 | generated, not edited: run `OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test docs` to write the "Supported agents" row, the configuration directory row, the tool mapping rows and the known gaps line from the spec; then `OPENMOAT_TEST_UPDATE_COVERAGE=1 cargo test -p openmoat-core --test conformance` for `docs/COVERAGE.md` |
| `docs/THREAT_MODEL.md` §5 | by hand: the agent's column in the "When the hook fails" table and its ungoverned tools |
| `CHANGELOG.md` | an `### Added` line under Unreleased |

`<module>` is the agent's id with `-` written as `_` (`copilot-cli` is `copilot_cli`);
the docs test reads the agent's code from `host/<module>.rs` and `host/<module>/`.

The compiler points at every other `match` on `Host` that needs a new arm. Lock pinning,
`openmoat status`, `openmoat doctor` and `openmoat uninstall` loop over `Host::ALL`, so they pick up
the new agent without further code.

## Map the payload to an `Action`

Copy the shape of `host/cursor.rs` (its own format) or `wire/pre_tool_use.rs` (the
Claude Code format). If the agent sends Claude Code's `PreToolUse` document unchanged,
set `speaks: Some(Host::ClaudeCode)` in its spec and end its host list line with
`speaks ClaudeCode` to reuse that parser, as the Continue CLI does (`host/continue_cli.rs`).

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
| calls an MCP tool | `mcp::action("mcp__<server>__<tool>", input)` | `wire/mcp.rs` finds path and URL arguments |
| a tool the hook receives for every tool and cannot classify | `wire::unknown::action(host, tool, input)`: `UnknownTool` with every path, URL and command its arguments name; `defaults.tool.unknown` decides the tool itself, `defer` in the default policy | pi, OpenClaw, Gemini CLI, Cursor `preToolUse` |
| a call the payload shows only in part | `Action::unchecked(action, reason)`: `action` is decided and the call asks (`unchecked`) | GitHub Copilot CLI `write_bash`, Gemini CLI `grep_search` without `dir_path` |
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
  taint and `openmoat allow --last` depend on them.

## Answer allow, defer, ask or deny

`render` writes the response the agent expects; `reason_line` gives the one-line reason
for the model and the person. On a deny, `guard` also prints the reason on stderr and
exits 2, so write the response even if the agent only reads the exit code.

A `defer` (ADR-025) means OpenMoat neither objects nor vouches: the agent's own
permission flow decides, as it would without OpenMoat. For an agent that runs its own
flow when a hook gives no answer, render nothing and exit 0, as `wire/pre_tool_use.rs` does.
An agent with no such answer needs a mapping: Cursor's shell and MCP hooks send it as
`ask` (`host/cursor.rs`), and for events that cannot prompt, `Asks::defer_is_ask_on_no_ask`
in its spec makes `Host::decided` (`contract::decided`, driven by the spec's `Asks`) record and answer it as `ask`. Find out from the
agent's source which applies.

Some agents cannot ask. Codex rejects `ask` and runs the call; the Continue CLI ignores
it; Cursor accepts `ask` on `preToolUse` but runs the call, and `beforeReadFile` takes
only allow or deny. For these, the spec's `Asks` says why the agent cannot ask, and
`Host::answer` (`contract::answer`) turns an `ask` into a `deny` with that reason and the line saying how to
approve it. The audit log keeps the `ask`, which is what `openmoat` and `openmoat allow --last`
look for. If the agent cannot ask, fill in `Asks::on_pre_tool_use`. If it can ask only
on some events, return `HookEvent::PreToolUseNoAsk` for the others and fill in
`Asks::on_no_ask`, as `host/cursor.rs` does.
Verify from the agent's documentation or source code what it does with each answer.
When the documentation and the agent disagree, trust the agent, and say which you
checked in the fixtures `README.md`.

## Install, uninstall and the lock

`openmoat init` calls `HostConfig::install`, which adds one entry per `HookSpec` (event,
matcher, timeout) of the spec's `install.hooks` to the agent's hook file, in the
layout `install.hook_format` names. It must stay idempotent (invariant 8):

- Our entries are recognised by their command, `guard --host <id>`; re-running `init`
  updates them in place and never adds a second one.
- Other keys and other hooks in the file are kept.
- The file is copied to `<file>.moat-backup` before the first edit.
- The matcher must name every tool the adapter maps. A tool missing from it never
  reaches `guard` (see `TOOL_MATCHER` in `host/claude_code.rs`).
- Use a timeout of `TOOL_HOOK_TIMEOUT_S` (600 s, `contract.rs`), long enough for a
  person to answer a prompt. Every timeout must exceed `GUARD_BUDGET_S`, and only an
  entry the host can block on gets `block_on_failure`; `tests/contract.rs` checks both
  for every host.

`openmoat uninstall` calls `HostConfig::remove`, which deletes only our entries and any
event list or `hooks` object that leaves empty. Test that installing and then removing
gives back the original file (`hook_file.rs` tests).

`openmoat init` pins every installed hook file in `~/.moat/policy.lock`
(`integrity::installed_hook_files` loops over `Host::ALL`). If the file changes, the
next tool call is denied with `kernel-integrity` until a person runs `openmoat init` or
`openmoat doctor --accept`. Only Claude Code has a `ConfigChange` event that catches the
edit as it happens; for other agents, say in the threat model that a tampered hook file
is caught on the next tool call.

The default policy's `kernel-self` rule protects the known agent directories and hook
files from the agent's own writes. Adding the new agent's paths there is a policy
change: it needs an attack fixture in `tests/conformance/` and is `risk: high`, so it
can be a separate PR.

## The config directory variable

Most agents let a variable move their config directory (`CLAUDE_CONFIG_DIR`,
`CODEX_HOME`, `CURSOR_CONFIG_DIR`). Put the agent's variable and default directory in
its spec's `install` (`InstallSpec`): `dir_variable` and `moved_dirs`
(`crates/openmoat-cli/src/context.rs`) read them from there for every host in
`Host::ALL`. `openmoat init` installs where that variable points and
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
runs the real `openmoat init --yes` with an isolated `HOME`, and `sb.guard("<id>", payload)`
runs the hook. Test at least:

- `init` writes one entry per event, with the fail-closed flag if there is one, and a
  second `init` changes nothing;
- a secret read or exfiltration fixture is denied with exit 2 in the agent's format;
- a safe call is allowed;
- an `ask` arrives as the agent needs it (a deny with `openmoat allow --last` if it cannot
  ask);
- a deferred call is left to the agent (no output and exit 0, or the agent's own
  prompt) and is not denied;
- malformed arguments are denied;
- `openmoat uninstall` removes the entries (see `e2e/uninstall.rs`).

## Be honest about coverage

- **List every tool the hook does not see** under "Ungoverned tools" in
  [THREAT_MODEL.md](THREAT_MODEL.md) §5, and in the INSTALL.md table. Never claim
  coverage the code does not have.
- **Fail closed where the agent allows it.** Every error in `guard` is a deny with exit
  2 (invariant 4). If the agent runs the call when the hook crashes, times out or
  cannot start, and it has a setting to block instead, `init` must set it (Cursor's
  `failClosed`). Add the agent's column to the "When the hook fails" table in
  THREAT_MODEL §5, with sources, and to its spec's `on_hook_failure` and `gaps`; add its payload shape
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
