# Architecture

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you change the code: where it lives, and how a tool call becomes a decision, a hook response and an audit record.

**On this page:** [1. Crates](#1-crates) · [2. One tool call, end to end](#2-one-tool-call-end-to-end) · [3. Classification](#3-classification) · [4. Decision](#4-decision) · [5. Hook responses and exit codes](#5-hook-responses-and-exit-codes) · [6. Self-protection](#6-self-protection) · [7. Audit log](#7-audit-log) · [8. Files on disk](#8-files-on-disk) · [9. Invariants](#9-invariants) · [10. Repository layout](#10-repository-layout) · [11. Testing layers](#11-testing-layers) · [12. Egress proxy](#12-egress-proxy) · [13. Standard tier: host sandboxes](#13-standard-tier-host-sandboxes) · [14. Lightweight tier: openmoat run](#14-lightweight-tier-openmoat-run)

How OpenMoat turns one agent tool call into a decision, a hook response and an audit
record. This describes the code on `main`. The working rules for changing it are in
[AGENTS.md](../AGENTS.md); the policy language is in [POLICY.md](POLICY.md); what
it defends against is in [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Crates

```
openmoat ──► openmoat-hosts ──► openmoat-core
   │                                ▲
   ├──► openmoat-audit ─────────────┤
   ├──► openmoat-proxy ─────────────┘
   └──► openmoat-core
```

| Crate | Role | Rules |
|---|---|---|
| `openmoat-core` | Policy model and lint, POSIX lexer (`lexer/`), shell classifier (`shell/`), URL host parser (`host.rs`), patterns, path normalisation, the engine, the policy compiler (`ir/`), the repository policy merge (`repo.rs`), the popular-package lists and near-miss check (`packages.rs`, data in `data/top-packages/`, ADR-030), the Codex `apply_patch` file list (`patch.rs`), `ProgramResolver` and `PathResolver` traits | Pure: no I/O, no `unsafe`, depends only on `serde`, `serde-saphyr`, `globset`, `thiserror`. Builds for `wasm32-unknown-unknown` in CI; `tests/architecture.rs` enforces the dependency allowlist and the 500-line file budget |
| `openmoat-hosts` | Host adapters: `host/<id>.rs` per host with its `HostSpec` and adapter (`host/claude_code.rs` with `claude_code/config_change.rs` for Claude Code `ConfigChange`, `host/codex.rs`, `host/continue_cli.rs`, `host/cursor.rs` with `cursor/pre_tool.rs`, `host/openclaw.rs` with `openclaw/tools.rs`, `host/copilot_cli.rs` with `copilot_cli/tools.rs` for GitHub Copilot CLI `preToolUse`, `host/pi.rs` with `pi/tools.rs`, `host/gemini_cli.rs` with `gemini_cli/tools.rs` and `gemini_cli/settings.rs`, `host/opencode.rs` with `opencode/tools.rs` (`tools/v1.rs`, `tools/v2.rs`) and `opencode/location.rs`, `host/hermes.rs` with `hermes/tools.rs`, `hermes/consent.rs` and `hermes/settings.rs` for Hermes Agent `pre_tool_call`), `host/<module>/doc.rs` per host (its README row and tool mapping rows), `contract.rs` (`HostSpec`, `Asks`, `InstallSpec`, `HostDocs`, the `HostAdapter` trait), `host.rs` (the one list of hosts: each line declares a host's module and `Host` variant), `registry.rs` (the `hosts!` macro that expands the list into `Host`, `Host::EVERY`, `Host::ALL` and each host's spec and adapter), `wire/pre_tool_use.rs` (the `PreToolUse` format Claude Code, Codex and the Continue CLI send), `wire/mcp.rs` (MCP arguments to paths and URLs), `wire/unknown.rs` (the one rule for a tool an adapter does not map), `bench.rs` (what `openmoat bench` needs from a host); the Codex `apply_patch` file list is `openmoat-core`'s `patch.rs` | Translate payload to `Action` and `Decision` to response. Never decide |
| `openmoat-audit` | SQLite store, time-window and session queries, redaction | Redact before persisting. Typed `thiserror` errors |
| `openmoat-proxy` | The egress proxy behind `openmoat proxy` (§12): request and `ClientHello` parsers, host decisions through openmoat-core, the address guard, connection relay, the `Recorder` trait the CLI implements over `openmoat-audit` | Network I/O only through `std::net`; no async runtime; no storage. Depends on `openmoat-core`, `httparse`, `thiserror` |
| `openmoat` (`crates/openmoat-cli`) | The `openmoat` binary, and `moat` (`src/bin/moat.rs`), the old name kept for a few releases, which starts the `openmoat` beside it: commands, hook installation, the policy lock and its MCP server pins, `openmoat mcp proxy`, the MCP gateway (`mcp/relay.rs`, its decisions in `commands/mcp/gate.rs`, tool pins in `mcp/tools.rs`), approvals, the repository policy file, the environment snapshot, the filesystem resolvers, the sandbox backends generated from the IR (§13, §14), rendering, exit codes | The only crate that touches files, the environment and the terminal; the only one that starts processes |

No crate depends on `openmoat`.

## 2. One tool call, end to end

```
host payload (stdin)
  └─► adapter (openmoat-hosts)             Action, or none for an ungoverned tool
        └─► policy lock check              drift ⇒ deny [kernel-integrity]
          └─► MCP server pins              McpTool of a changed or new server ⇒ deny [mcp-server-changed]
              └─► load policy + overlay    ~/.moat/policy.yaml + policy.d/approved.yaml
                    + repository policy    <project>/.moat/policy.yaml, tightening only
                    └─► classify (openmoat-core)  Action ⇒ atomic actions
                          └─► engine            per atom: deny → allow → ask → defer → defaults
                                └─► combine     strictest wins ⇒ Decision
                                      └─► session grant   ask or defer on a granted call ⇒ allow
                                            └─► session taint     earlier calls in the audit log ⇒ allow or defer may become ask
                                                  └─► session code      runs a file this session wrote, no OS sandbox ⇒ allow or defer may become ask
                                                        └─► push check        git push / gh pr create: what it publishes ⇒ may become deny or ask
                                                              └─► audit record      failure ⇒ deny [kernel-error]
                                                                    └─► hook response (stdout) + exit code
```

`openmoat guard --host <id>` (`commands/guard.rs`) runs this once per tool call and
exits. There is no daemon.

1. **Read.** At most 1 MiB of UTF-8 from stdin. An empty or unreadable payload is a
   `kernel-error` deny.
2. **Adapt.** The host adapter parses the payload into a `HookRequest`: host, session
   id, call id, working directory, tool name, and an `Action` (`Shell`,
   `ForeignShell`, `FsRead`, `FsWrite`, `Net`, `Fetch`, `Patch`, `McpTool`). A
   malformed payload is a `kernel-error` deny.
3. **ConfigChange.** A Claude Code `ConfigChange` takes its own path: every pinned
   file is compared with `policy.lock`, and while any drifted the change is blocked for
   the session, whichever file it names (§6).
4. **Lock.** `integrity::check` recomputes every digest in `policy.lock`. Any drift
   denies the call with `kernel-integrity` before the policy is read, except drift of
   only the Claude Code settings keys `integrity/relaxed.rs` allowlists (§6): then the
   call is decided as usual and the first call of the session records the drift with
   rule `settings-drift`. The check reads each pinned file once: the rest of the call
   parses OpenMoat's own state files (policy, `openmoat allow` overlay, policy packs,
   `hosts.json`, `environment.json`, `approvals.json`, `trust.json`) from the bytes
   that matched their pins, and sorts settings drift by the bytes found to differ
   (`integrity/kept.rs`). Otherwise a tool
   the adapter does not govern (no action) is recorded with rule `ungoverned` and
   deferred: the host decides it as if no hook had answered (Cursor, whose hooks have
   no such answer, gets an allow). An `McpTool` call is then checked against the MCP
   server pins in the lock (`mcp.rs`, `mcp/servers.rs`, `mcp/pins.rs`, ADR-026): the
   host's MCP configuration files, user and project, are read, and when the server the
   tool belongs to has a definition that differs from its pin or has none, the call is
   denied with `mcp-server-changed`. Other servers are not affected.
5. **Context.** `EvalContext` carries the home directory, the project root (git root
   above the call's working directory, never the home directory, an ancestor of it or
   a filesystem root; `project.rs`), their symlink-resolved spellings, the working
   directory and whether paths compare case-insensitively.
6. **Policy.** `~/.moat/policy.yaml` is parsed and linted (1 MiB limit). Rules from
   `policy.d/approved.yaml` are appended to `allow` and the result is linted again.
   When the project has a repository policy (`<project>/.moat/policy.yaml`, ADR-022),
   `repo.rs` reads it and `openmoat_core::RepoPolicy::merge`, a pure function, merges it:
   its deny groups join `deny`, its ask groups go into `repo_ask`, which the engine tries
   between `deny` and `allow`. Its allow groups are appended to `allow` only when
   `~/.moat/trust.json` is pinned by the lock and records the SHA-256 of these exact
   bytes for this project root (symlinks resolved); otherwise they are dropped. Its
   rule ids get the prefix `repo:`. A repository policy that is not a regular file,
   cannot be read or does not parse is a `kernel-error` deny.
7. **Decide.** `CompiledPolicy::compile(policy, ctx).decide_with(action, snapshot,
   FsPathResolver)` classifies and evaluates (§3, §4).
8. **Grant.** An `ask` or `defer` for a call whose exact text was granted for this host
   session with `openmoat allow` becomes `allow` with rule `approved-session`. A grant
   never touches a `deny` and expires 24 h after it was given; expired grants are
   ignored and pruned.
9. **Taint.** `taint::of_session` (`taint.rs`) reads this host session's earlier events
   from the audit log. It folds `CompiledPolicy::exposure` over the calls that may have
   run: allowed and deferred calls, and asks on a host that can ask. Each call is resolved from its
   own recorded working directory. `CompiledPolicy::with_taint` then tightens the
   decision (POLICY.md §4.1). This runs after the grant, so a grant cannot lift a taint
   ask, with one exception (`taint::answered`): a grant for this exact call made after
   the session last read untrusted content answers that content's ask; a later read
   asks again. A taint from a
   secret the session read is never answered this way. A log or session event that cannot be read is a `kernel-error` deny. An edited
   or deleted event is found by the hash chain (`openmoat doctor`), not on every call.
    **Session code.** `CompiledPolicy::executed` lists the files the shell command runs
    as code (core `shell/executes.rs`). When the decision is `allow` or `defer` and the
    session wrote one of them (`session_writes` in the audit log, or this very call),
    and no OS sandbox from OpenMoat holds the call (`protection::os_sandboxed`, or
    `openmoat run`'s `--relayed`), `session_code.rs` asks (`session-written-code`,
    ADR-039, POLICY.md §4.3); a session grant made after the session last wrote the file
    answers it. Every call that may have run records the files it writes there, with
    its audit row.
10. **Push.** `CompiledPolicy::pushes` lists the shell command's pushes (`git push`,
    `gh pr create`; core `shell/push.rs`) with the directories each may run in. Unless the
    call is already denied, `push.rs` runs git read-only there, within 10 s for the whole
    call, and tightens the decision: `push-secret` deny, `push-runs-later` or
    `push-unchecked` ask (POLICY.md §4.2). With no finding the decision is unchanged.
11. **Record.** The event is appended to the audit log's hash chain (§7). If it cannot
   be written, the decision becomes a `kernel-error` deny: an unrecorded call is not
   allowed.
12. **Respond.** The adapter renders the host's response document. `deny` also prints
    the reason line on stderr and exits 2.

A panic inside steps 1–11 is caught and answered with a deny and exit 2, because
Claude Code treats exit 101 as a non-blocking error. A `guard` with no answer after
30 s (`GUARD_BUDGET_S`, below every hook timeout `openmoat init` sets) writes a deny,
unrecorded, and exits 2, since a host that times the hook out runs the call
(THREAT_MODEL §5, "When the hook fails"). Only one response is ever written. The
limit is wall-clock time, which includes waiting for a CPU and for the audit
database's lock, so it is set well above the 10–40 ms a call takes: on a machine
loaded by parallel builds a call can take seconds without being stuck. The deny
appends `<ms> <host> <phase> <elapsed ms>` to `~/.moat/guard-hangs.log`, the
phase being the step the guard was in (`stdin`, `relay` for a hook inside `openmoat run`
waiting for the run to decide, `lock`, `context`, `compile`, `taint`, `cache`,
`record`, `answer`); `openmoat doctor` reports the hangs of the last
week and the phase most of them were in.

## 3. Classification

`openmoat-core` turns an `Action` into atomic actions (`AtomicAction`): `Shell`,
`Pipeline`, `FsRead`, `FsWrite`, `Net`, `NetWord`, `Fetch`, `WebSearch`, `UnknownTool`, `EnvRead`, `EnvSet`, `McpTool`. An `Action::Unchecked` wraps another action and adds an `unchecked` ask.

- **Shell** (ADR-005). The lexer (`lexer/`) reads words, quotes, escapes, operators,
  redirections, `$( … )`, backticks, here-documents and here-strings, up to 64 KB, and
  makes the words bash makes of unquoted braces (`lexer/brace.rs`). The
  classifier (`shell/`) emits one `Shell` atom per simple command and one `Pipeline`
  atom per pipeline suffix. It recurses into `sh -c`, `eval`, substitutions and
  wrappers (`sudo`, `env`, `xargs`, `timeout`, `taskset`, `systemd-run`, …) to depth 4. It adds `fs.read`/`fs.write`
  atoms for redirections and file operands (`operands.rs`), relative paths resolved
  through `cd`/`pushd` (`cwd.rs`), `net` atoms for URLs, the hosts of programs that name hosts (any other host-shaped word is a `NetWord`) and the host of a `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT` redirection, which bash opens as a connection (`host::of_dev_socket`), and `env.*` atoms
  for assignments and `$VAR` reads. Leading reserved words (`do`, `then`, `if`, …) are skipped, and a
  variable set earlier on the line with a known value is substituted where it is used
  (`commands/locals.rs`); a path through one whose value is not known is `unparseable`. Shell options are read per shell
  (`invocation.rs`), git's global options are unwrapped (`git.rs`), `make` arguments
  that run code (`make.rs`), options that run programs (`options.rs`), option values
  that name files in every spelling (`path_options.rs`), the files `curl` and `wget`
  write, read by the same parser as the fetch check (`options/transfer.rs`, ADR-035), and decoder pipelines
  (`decoders.rs`) are surfaced. Inline interpreter code (`python -c`, `python3.12 -c`, `node -e`, `lua -e`, `Rscript -e`, …;
  `tables.rs`) is scanned for paths, hosts and variable names, not parsed. Output is
  capped at 2048 atoms.
- **ForeignShell** (Claude Code `PowerShell`). Always rule `unparseable` (below);
  there is no PowerShell parser.
- **ReadFiles** (Claude Code `SendFile`, absolute Glob patterns). One `fs.read` per
  path; an empty list is `unparseable`.
- **Patch** (Codex `apply_patch`, a write-shaped Cursor tool naming several paths). One
  `fs.write` per added, updated, deleted or moved-to file; a patch naming no file is `unparseable`.
  A header line is matched trimmed and in any case, as Codex reads it, wherever it is.
- **McpTool.** An `mcp` atom for the tool name, plus `fs.*` and `net` atoms for path-
  and URL-shaped arguments found down to 8 levels of nesting (`openmoat-hosts/src/wire/mcp.rs`),
  and, for a GitHub Copilot CLI tool that may be its own, the atoms of the shell commands
  its arguments name.
  When deeper nesting stops the search, the adapter names the limit in `unchecked`, and
  the engine adds an `unparseable` atom to the decision.
- **Fetch** (Claude Code `WebFetch`). A `fetch` atom for the URL's host (ADR-017).
- **WebSearch** (Claude Code and Cursor `WebSearch`). A `web.search` atom for the query;
  the host picks the search provider, so only `defaults` and session taint decide it.
- **UnknownTool** (a tool an adapter does not map: an extension's, a subagent's, a
  Cursor `preToolUse` tool naming no path key). A `tool.unknown` atom for the tool
  name, which only `defaults` (`defer` in the default policy) and session taint
  decide, plus `fs.*` and `net` atoms for every path and URL its arguments name, by
  key or by look, and the atoms of every shell command under a command key
  (`openmoat-hosts/src/wire/unknown.rs`, shared by every adapter); strictest wins.
  Cursor's `preToolUse` cannot prompt, so `Host::decided` records and answers a
  `defer` there as `ask` (§5).
- **Unchecked** (a call the payload shows only in part: GitHub Copilot CLI typed
  shell input or a shell left in an unknown directory, a Gemini CLI search over every
  workspace directory, a glob whose brace group may climb further than computed).
  The atoms of the action it wraps, and an `unchecked` decision that asks.

Anything the lexer or classifier cannot make sense of is `unparseable`, never `allow`:
the engine gives it `Defaults::unclassified`, which is `defer` when the catch-all
(`"*"`) is `allow` or `defer`, as in the default policy, and `ask` when it is `ask` or
`deny` (ADR-025). `ParseOutcome::Unparseable` carries the atoms classified around the
part that failed (other simple commands, other MCP arguments), and the engine merges the
`unparseable` verdict with their decisions, so the failing part cannot hide a deny.

### Host tool mapping

The table is generated from each agent's rows in `crates/openmoat-hosts/src/host/<module>/doc.rs`
(`host/claude_code/doc.rs`, …; `OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test docs`), and the same test
fails when an adapter matches a tool name its rows do not mention; do not edit it.

<!-- generated:hosts-tools -->
| Agent | Host tool | Field read | Action |
|---|---|---|---|
| Claude Code | `Bash` | `command` | `Shell` |
| Claude Code | `Monitor` | `command`, or `ws.url` (exactly one) | `Shell`, or `Net` |
| Claude Code | `PowerShell` | `command` | `ForeignShell` |
| Claude Code | `Read` | `file_path` | `FsRead` |
| Claude Code | `LSP` | `filePath` | `FsRead` |
| Claude Code | `Glob`, `Grep` | `path`, else the working directory; an absolute or `~` Glob `pattern` also reads its directory part (Claude Code searches that instead of `path`), and a relative one where its `..` climbs to | `FsRead`, `ReadFiles` |
| Claude Code | `SendFile` | every path in `files` (the contents go to another session; an empty or non-string list is an adapter error, so `deny`) | `ReadFiles` |
| Claude Code | `Artifact`; `ArtifactData` | every local file it uploads to a claude.ai page (`file_path`, `file_paths`, each source of `files`, a relative one also below `root`); with `action: "read"` and `out_dir`, each file it saves there, and without, the page it reads (`url`, as `fetch`: untrusted content); `ArtifactData`'s `file_path` | `ReadFiles`, `Patch`, `Fetch`; `FsRead` |
| Claude Code | `Edit`, `Write`, `MultiEdit`; `NotebookEdit` | `file_path` (`Write` `content` for provenance); `notebook_path` | `FsWrite` |
| Claude Code | `WebFetch` | `url` | `Fetch` |
| Claude Code | `WebSearch` | `query` (`allowed_domains` and `blocked_domains` only filter results) | `WebSearch` |
| Claude Code | `ReadMcpResourceTool` | `server`, `uri`: a `file:` URI is a read of its (percent-decoded) path, any other URI a host; a `file:` URI without an absolute path is an adapter error, so `deny` | `McpTool` `mcp__<server>__read_resource` |
| Claude Code | `EnterWorktree` | `path` (an existing worktree becomes the session's directory and project root); with `name` or nothing, ungoverned | `FsRead` |
| Claude Code | `mcp__<server>__<tool>` | tool name and arguments | `McpTool` |
| Claude Code | any other tool (`Task`, `Skill`, …) | — | none: `ungoverned` |
| Codex | `Bash` | `command` | `Shell` |
| Codex | `apply_patch` | `command` (the patch envelope) | `Patch` |
| Codex | `mcp__<server>__<tool>` | tool name and arguments | `McpTool` |
| Codex | any other tool (`update_plan`, …) | — | none: `ungoverned` |
| Cursor | `beforeShellExecution` | `command` | `Shell` |
| Cursor | `beforeReadFile` | `file_path` | `FsRead` |
| Cursor | `beforeMCPExecution` | `mcp_server_name`, `tool_name`, `tool_input` | `McpTool` `mcp__<server>__<tool>` |
| Cursor | `preToolUse` `Read` | `file_path` | `FsRead` |
| Cursor | `preToolUse` `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete` | `file_path` | `FsWrite` |
| Cursor | `preToolUse` `Grep`, `Glob` | every path in `path`, `file_path`, `target_file`, `target_directory`, `target_directories`, else the working directory | `FsRead`, `ReadFiles` |
| Cursor | `preToolUse` listing and search tools (`LS`, `ListDir`, `list_dir`, `SemanticSearch`, `codebase_search`, `grep_search`, `file_search`, `read_file`) that name a path under those keys | every such path | `FsRead`, `ReadFiles` |
| Cursor | `preToolUse`, any other tool that names a path under those keys (an editing tool need not have a write verb in its name) | every such path | `FsWrite`, `Patch` |
| Cursor | `preToolUse` `WebFetch` | `url` | `Fetch` |
| Cursor | `preToolUse` `WebSearch` | `query` (`allowed_domains` and `blocked_domains` only filter results) | `WebSearch` |
| Cursor | `preToolUse`, any other tool that names no path key, except to-do tools (`TodoWrite`, `TodoRead`, `todo_write`: ungoverned) | tool name and arguments | `UnknownTool` (`tool.unknown`) |
| Cursor | `preToolUse` `Shell`, `Task`, `MCP:<tool>` (`beforeShellExecution` and `beforeMCPExecution` decide shell and MCP calls; a `Task` subagent's own calls are hooked) | — | none: `ungoverned` |
| OpenClaw | `exec` | `command`, with each `env` entry written as `NAME='value'` before it; `workdir` as a `cd` before the command, the project staying the session's; PowerShell on Windows | `Shell`; `ForeignShell` on Windows |
| OpenClaw | Code Mode `exec` | the params as JSON | `ForeignShell` (`unparseable`) |
| OpenClaw | `process` | `list`, `poll`, `log`, `kill`, `clear`, `remove`: ungoverned; any other action (`send-keys`, `submit`, `paste`, `write`, typed into a running session): the params as JSON | none; `ForeignShell` (`unparseable`) |
| OpenClaw | `read` / `write`, `edit` | `path` and `file_path` when both are given; a relative path with no workspace (`cwd`) is an adapter error | `FsRead`, `ReadFiles` / `FsWrite`, `Patch` |
| OpenClaw | `apply_patch` | `input` (the patch envelope) | `Patch` |
| OpenClaw | `web_fetch` / `web_search`, `x_search` | `url` / `query` | `Fetch` / `WebSearch` |
| OpenClaw | `browser` | `open`, `navigate`: `url` or `targetUrl`; `upload`: `paths`; any other action | `Net`; `ReadFiles`; `UnknownTool` |
| OpenClaw | `gateway` | `config.get`: the plugin's `configPath`; `config.schema.lookup`: ungoverned; any other action | `FsRead`; none; `UnknownTool` |
| OpenClaw | `plugins` | `list`, `inspect`, `search`: ungoverned; any other action (`install`, `enable`, `disable`, `uninstall`, `reload`, `reloadAndResume`): the plugin's `configPath` | none; `FsWrite` (`kernel-self` denies it) |
| OpenClaw | `cron` | `status`, `list`, `get`, `runs`: ungoverned; `add`, `update`, `next_check`: the state database `<stateDir>/state/openclaw.sqlite` (beside `configPath` from a plugin that sends no `stateDir`); any other action (`run`, `remove`, `wake`) | none; `FsWrite` (`kernel-self` denies it); `UnknownTool` |
| OpenClaw | `nodes` | `status`, `describe`, `pending`, `camera_list`, `device_*`, `which`: ungoverned; `invoke`: the params as JSON; an action with `outPath`: `outPath`; any other action | none; `ForeignShell` (`unparseable`); `FsWrite`; `UnknownTool` |
| OpenClaw | `view_image` | `path` and each of `paths`: local files (a `file://` URL as its path); `http(s)` URLs when no file is named; `data:` images touch nothing | `FsRead`, `ReadFiles`; `Fetch` for one URL, `UnknownTool` for several |
| OpenClaw | `<server>__<tool>` | `mcp__<server>__<tool>` and `params` | `McpTool` |
| OpenClaw | `ask_user`, `session_status`, `agents_list`, `agents_wait`, the goal tools, `progress_card`, `theme`, `screen`, `wait`, `tool_search`, `tool_describe`, `heartbeat_respond` | — | none: `ungoverned` |
| OpenClaw | any other tool (`message`, `sessions_*`, a plugin's tool) | tool name and arguments | `UnknownTool` (`tool.unknown`) |
| GitHub Copilot CLI | `bash`, `local_shell` / `write_bash` | `command` (asks when it leaves the shell in a directory OpenMoat cannot know) / `input` (typed into a running shell: asks); `toolArgs` is parsed when it is a JSON string | `Shell` / `Unchecked` |
| GitHub Copilot CLI | `powershell` / `write_powershell` | `command` / `input` (asks) | `ForeignShell` / `Unchecked` |
| GitHub Copilot CLI | `view` / `create`, `edit`, `str_replace` | `path` (`create` `file_text` for provenance) | `FsRead` / `FsWrite` |
| GitHub Copilot CLI | `str_replace_editor` | `path`; `command` `view` reads, any other command writes | `FsRead` / `FsWrite` |
| GitHub Copilot CLI | `apply_patch` | the patch text: `toolArgs` itself, or its `input` or `patch` | `Patch` |
| GitHub Copilot CLI | `grep`, `rg`, `glob` | every path in `paths` and `path`, the directory of an absolute `glob` `pattern`, else the working directory | `FsRead`, `ReadFiles` |
| GitHub Copilot CLI | `web_fetch` / `web_search` | `url` / `query` | `Fetch` / `WebSearch` |
| GitHub Copilot CLI | `ask_user`, `report_intent`, `task`, `think`, `update_todo`, `read_bash`/`stop_bash`/`list_bash` and their PowerShell forms | — | none: `ungoverned` |
| GitHub Copilot CLI | any other tool, MCP tools included (`<server>-<tool>`; the payload does not mark them) | tool name and arguments, read as an unknown tool's (paths and URLs by key and by look, commands) | `McpTool` |
| pi | `bash` / `powershell` | `command` | `Shell` / `ForeignShell` |
| pi | `read` / `write`, `edit` | `path` as pi resolves it: Unicode spaces as spaces, a leading `@` dropped, a `file:` URL as its path, on Windows `/c/…`, `/mnt/c/…`, `/cygdrive/c/…` as `C:/…`; a relative path with no `cwd` is an adapter error (`write` `content` for provenance) | `FsRead` / `FsWrite` |
| pi | `grep`, `ls` / `find` | `path`, else the working directory / the same, the directory of an absolute `pattern`, and where a `..` in it climbs to | `FsRead` / `FsRead`, `ReadFiles` |
| pi | `mcp__<server>__<tool>`; `read_mcp_resource` | tool name and `input`; `server`, `uri` as for Claude Code's `ReadMcpResourceTool` | `McpTool` |
| pi | `codemode`, `tool_search`, `list_mcp_resources`, `list_mcp_resource_templates` | — | none: `ungoverned` |
| pi | any other tool (an extension's) | tool name and arguments | `UnknownTool` (`tool.unknown`) |
| Gemini CLI | `run_shell_command` | `command`, after a `cd` to `dir_path` (quoted whole: Gemini CLI expands no `~`); the project stays the session's; PowerShell on Windows | `Shell`; `ForeignShell` on Windows |
| Gemini CLI | `read_file`, `list_directory` / `write_file`, `replace` | `file_path`, `dir_path` / `file_path` (`write_file` `content` for provenance) | `FsRead` / `FsWrite` |
| Gemini CLI | `glob`, `grep_search` (`search_file_content`) | `dir_path`, else `cwd` and an ask, since Gemini CLI then searches every workspace directory; for `glob` also the directory `pattern` names before its first wildcard, for `grep_search` where `include_pattern` (`include` before 0.65) climbs to | `FsRead`, `ReadFiles`; `Unchecked` |
| Gemini CLI | `read_many_files` | each `include`, up to its first wildcard, and an ask: it reads every workspace directory | `Unchecked` |
| Gemini CLI | `web_fetch` / `google_web_search` | the one URL in `prompt` (a `github.com` `blob` page as the `raw.githubusercontent.com` file Gemini CLI fetches; none or several is an adapter error) / `query` | `Fetch` / `WebSearch` |
| Gemini CLI | `read_mcp_resource` | `uri`: a `file:` URI as its path; any other URI | `FsRead`; `UnknownTool` |
| Gemini CLI | MCP tool (`mcp_<server>_<tool>`) | `mcp_context.server_name`, `mcp_context.tool_name` and `tool_input`; without `mcp_context` the name cannot be split | `McpTool` as `mcp__<server>__<tool>`; `UnknownTool` |
| Gemini CLI | `write_todos`, `ask_user`, `tracker_*`, `update_topic`, plan-mode, `complete_task`, `activate_skill`, `get_internal_docs`, `list_mcp_resources`, `invoke_agent` and the built-in subagents | — | none: `ungoverned` |
| Gemini CLI | any other tool (a custom subagent's, a browser subagent's, a discovered tool) | tool name and arguments | `UnknownTool` (`tool.unknown`) |
| OpenCode | `bash` (1), `shell` (2) | `command`, run after a `cd` to `workdir` when it names one; on Windows, where it may be Git Bash, PowerShell or `cmd`, left to OpenCode | `Shell` / `ForeignShell` |
| OpenCode | `read`, `lsp` (1) / `write`, `edit` / `apply_patch` (1), `patch` (2) | `filePath` (1) or `path` (2), a relative one joined to the instance directory (`~` is expanded by OpenCode 2 only) (`write` `content` for provenance) / every file `patchText` adds, changes, moves or deletes | `FsRead` / `FsWrite` / `Patch` |
| OpenCode | `glob`, `grep` | `path`, else the instance directory; the directory of an absolute `pattern` (`glob`) or `include` (`grep`), and where a `..` in it climbs to | `FsRead`, `ReadFiles` |
| OpenCode | `webfetch` | `url` | `Fetch` |
| OpenCode | `websearch` | `query` | `WebSearch` |
| OpenCode | `opencode_worktree_remove` (2) | `directory`, which it deletes | `FsWrite` |
| OpenCode | `<server>_<tool>` of a server named under `mcp` (`mcp.servers` in 2); `read_mcp_resource` | decided as `mcp__<server>__<tool>`, the longest server name that begins it when several do, and its arguments; `server`, `uri` as for Claude Code's `ReadMcpResourceTool` | `McpTool` |
| OpenCode | `task`, `invalid`, `list_mcp_resource_templates` (1); `subagent`, `opencode_session_rename`, `opencode_worktree_list`, `opencode_models` (2); `todowrite`, `skill`, `question`, `execute` (Code Mode), `list_mcp_resources` | — | none: `ungoverned` |
| OpenCode | any other tool (a plugin's, a custom tool's, OpenCode 2's other `opencode_*` tools) | decided as an MCP tool of that name, every path, URL and command in its arguments checked | `McpTool` |
| Hermes Agent | `terminal` | `command`, after a `cd` to `workdir`; the project stays the payload's `cwd` (the Hermes process's); a relative `workdir`, or a command that leaves the session's shell where OpenMoat cannot know, asks | `Shell`; `Unchecked` |
| Hermes Agent | `read_file` / `write_file`, `patch` | `path` (`write_file` `content` for provenance); `patch` with `mode: patch`: every file its V4A `patch` names; a relative path asks, since Hermes resolves it against the session's directory, which the payload does not send | `FsRead` / `FsWrite`, `Patch`; `Unchecked` |
| Hermes Agent | `search_files` | `path`, else the session's directory (an ask); for `target: files`, also where a relative `pattern` climbs to | `FsRead`, `ReadFiles`; `Unchecked` |
| Hermes Agent | `web_search` / `web_extract` | `query` / each of `urls`: one URL is a fetch, several an unknown tool with every URL | `WebSearch` / `Fetch`; `UnknownTool` |
| Hermes Agent | `browser_navigate` | `url`: the browser loads the page and runs its scripts | `Net` |
| Hermes Agent | `execute_code` | `code` (Python); the tools it calls through `hermes_tools` are checked one by one | `ForeignShell` (`unparseable`) |
| Hermes Agent | `process_manage` | `list`, `poll`, `log`, `wait`, `kill`, `close`, `handoff`: ungoverned; `write`, `submit`: `data`, typed into a running process | none; `Unchecked` `Shell` |
| Hermes Agent | `cronjob_manage` | `list`: ungoverned; any other action: the arguments, `script` as a command, and an ask, since the job runs the agent later, unattended | none; `Unchecked` `UnknownTool` |
| Hermes Agent | `memory` / `skill_manage` | a write of the notes Hermes puts into later sessions (`memories/` in its home) / of each skill its `operations` name in its `skills/`; a skill write asks (`runs-later`), a memory write once the session read untrusted content (taint) | `FsWrite` / `FsWrite`, `Patch` |
| Hermes Agent | MCP tool (`mcp__<server>__<tool>`) | tool name and `tool_input`; a name cut to 64 characters is traced by the part kept | `McpTool` |
| Hermes Agent | `todo_list`, `clarify`, `session_search`, `skills_list`, `delegate_task` (its subagents' calls fire the hook), `read_terminal`, `close_terminal` | — | none: `ungoverned` |
| Hermes Agent | any other tool (`skill_view`, the other `browser_*` tools, `vision_analyze`, `computer_use`, the messaging tools, connectors, a plugin's tool, a `tool_call` Hermes did not unwrap) | tool name and arguments | `UnknownTool` (`tool.unknown`) |
<!-- /generated -->

OpenClaw has no command hook. OpenMoat's plugin (`crates/openmoat-hosts/src/host/openclaw/integration/openmoat.mjs`,
written by `openmoat init` to `<OpenClaw state dir>/openmoat/openmoat.mjs` with the binary's path,
listed in `plugins.load.paths`, pinned in the lock) handles `before_tool_call` for every tool,
runs `openmoat guard --host openclaw` with the event, the context's session ids, the agent's
workspace (`cwd`), the configuration path, the state directory and the platform on stdin
(`OPENCLAW_HOME`, `OPENCLAW_STATE_DIR` and `OPENCLAW_CONFIG_PATH` resolved as OpenClaw
does, `openmoat-hosts/src/host/openclaw/location.rs`), and maps the answer:
`deny` (exit 2) to `block`, `ask` to `requireApproval`, `allow` or nothing to no decision.
Anything else (no `openmoat`, a crash, another exit code, an unreadable answer, no answer in 45 s)
blocks the call (ADR-033). It registers that handler at the highest priority OpenClaw
takes and a second one at the lowest, which returns the parameters the first decided on:
OpenClaw gives each handler the call as it came and runs the `params` of the last one that
returns some, so a change another plugin returns in between is undone (ADR-041).
`openclaw.json` is JSON5; OpenMoat reads it with its own
JSON5 reader (`crates/openmoat-cli/src/json5.rs`) and writes it back as plain JSON, and
refuses to write a file with comments. The lock pins it without `mcp.servers`, whose
servers are pinned one by one with the other hosts' (ADR-026); it records that form per
file (`pinned_forms`, `integrity/forms.rs`), so only OpenClaw's own file is pinned so
(and Hermes Agent's `config.yaml` in its own form, below).

pi has no command hook either. OpenMoat's extension (`crates/openmoat-hosts/src/host/pi/integration/openmoat.js`)
is pi's hook file: `openmoat init` writes it whole, with the binary's path, to
`<agent dir>/extensions/openmoat.js` (`~/.pi/agent`, or `PI_CODING_AGENT_DIR`), where pi loads
it on start, and the lock pins it whole (`install/owned.rs`). Its `tool_call` handler runs
`openmoat guard --host pi` with the event (`toolName`, `input`, `toolCallId`,
`parentToolCallId`), the session id, `ctx.cwd`, `ctx.hasUI` and the platform on stdin, and maps
the answer: `deny` (exit 2) to `{ block: true, reason }`, `ask` to pi's confirmation dialog,
`allow` or nothing to no result. Anything else (no `openmoat`, a crash, another exit code, an
unreadable answer, no answer in 45 s) blocks the call, and pi blocks a call whose handler
throws. Without a screen (`hasUI` false: print and JSON mode) the call is `PreToolUseNoAsk`, so
an `ask` arrives as a deny that says how to approve it. `openmoat uninstall` deletes the file,
or gives back a file of the person's that `init` backed up.

OpenCode has no command hook either (ADR-040). OpenMoat's plugin
(`crates/openmoat-hosts/src/host/opencode/integration/openmoat.js`) is OpenCode's hook file:
`openmoat init` writes it whole, with the binary's path, to `plugins/openmoat.js` in OpenCode's
configuration directory (`OPENCODE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/opencode`, else
`~/.config/opencode`: `host/opencode/location.rs`, a `Location::Custom` because the XDG
variable names the base of the directory and other programs read it too), where OpenCode loads
it on start, and the lock pins it whole. It exports `{ id: "openmoat", server, setup }`:
OpenCode 1 (1.3.4 and later) calls `server`, whose `tool.execute.before` handler freezes the
call's arguments and sends the hook's `tool`, `sessionID`, `callID` and `args`; OpenCode 2
calls `setup`, whose `execute.before` hook replaces the event's `tool` and `input` with the
checked name and a frozen copy (accessors that throw on assignment) and sends `tool`,
`sessionID`, `agent`, `messageID`, `callID` and `input`. Both add the instance's `directory`
and `worktree`, the MCP server names and the platform, run `openmoat guard --host opencode`,
and map the answer: `deny` (exit 2) to a thrown `Error` whose message is the reason, `allow` or
nothing to a return. The adapter reads the event name (`tool.execute.before` or
`execute.before`) as the API: OpenCode 1 cannot ask (`HookEvent::PreToolUseNoAsk`,
`Asks::on_no_ask`), so there an `ask` arrives as a deny that says how to approve it; OpenCode 2
receives the `ask` and puts it to the person through `ctx.permission.assert`, its own
`permission` `evaluate` hook making the request an ask. Anything else (no `openmoat`, a crash,
another exit code, an unreadable answer, no answer in 45 s) throws too, which blocks the call.
The spec's `InstallSpec::versions` names the oldest version that loads the plugin and the hook
each major runs: `openmoat init` skips an older one, and `status` and `doctor` report it as not
protected and name the hook of a supported one, told by the version the `opencode` on `PATH`
reports (`install/host_version.rs`).

Each of the three plugins also runs `openmoat guard --heartbeat --host <id>` as its host
loads it, which records the time in `loaded/<id>.json` in the state directory and reads
nothing (ADR-042). `status` and `doctor` compare it, and the newest decision the audit log
holds for the host, with the last change that could stop the plugin loading (OpenMoat
writing the plugin file, the host's program on the search path changing) and, where the
spec names a folder the host writes only for a session (`InstallSpec::heartbeat`), with
the host's own writes since: a host that ran without the plugin reporting is not
protected; one that has not run since is a note. The plugins' JavaScript is type-checked
under `// @ts-check` (`crates/openmoat-hosts/jsconfig.json`, `scripts/ci/check-js.sh`)
and run under Node against a stand-in for each host and for the guard
(`crates/openmoat-hosts/tests/js_plugins/`).

Claude Code calls only reach OpenMoat for tools in the installed matcher
(`crates/openmoat-cli/src/install.rs`); a tool outside it is never seen. `Skill`
and `EnterWorktree` are in it so they are recorded, and left to Claude Code's own
permission flow when unmapped. A hook entry written by an older `openmoat` with a shorter
list is reported as out of date by `openmoat doctor` and `openmoat status`, with "run `moat
init`", which rewrites it in place; until then the entry keeps working for the tools it
names.
Cursor's hook matcher is empty, so every tool reaches `preToolUse`. Cursor's hook
documentation names `Grep` but not `Glob` and gives no file tool's arguments. A
third-party capture shows `Grep` and `Read` send `file_path`; the rest is unverified
(`crates/openmoat-hosts/src/host/cursor/fixtures/README.md`, #138).

## 4. Decision

For each atomic action, the lists are tried in order `deny → allow → ask → defer`; the
first list with a match decides that atom. A repository policy's ask groups (`repo_ask`)
are tried between `deny` and `allow`. If none matches, `defaults` decides (rule id
`default.<kind>` or `default`). A `NetWord` atom (a word that only looks like a host,
outside the programs that name hosts) is matched by `net` rules, but with no match the
catch-all decides it, not `defaults.net` (ADR-025). The verdict for the tool call is the
strictest across its atoms: `deny > ask > defer > allow`. `defer` means OpenMoat neither
objects nor vouches: the agent's own permission flow decides. Deny is absolute (ADR-002). A `fetch` atom also
matches `net` patterns and falls back to the `net` default (ADR-017). The decision
carries the rule ids that produced the final verdict and weaker matches as context.

Before deciding, the engine adds egress atoms (`engine/egress.rs`). For each URL a fetch
or network tool opens, MCP URL argument, web search query, and argv of a command that
connects to a host (with the commands piped into it), it looks for a known token shape
(`openmoat_core::token`, the same list as `openmoat_audit::TOKEN_SHAPES`, matched by
hand since core has no regex engine; `openmoat-audit/tests/token_shapes.rs` keeps the
two in step) and for brokered-secret placeholders. Each one going to a host that is not
its own becomes `@token-egress <service> <host>` or `@placeholder-egress <id> <host>`,
which the default policy's `token-egress` and `placeholder-egress` deny. The token
itself never goes into an atom, so it never reaches a reason.

### Resolvers

The engine needs two facts that live on the filesystem. `openmoat-core` defines a trait
for each and the CLI implements it:

| Trait | ADR | Implementation | What it adds |
|---|---|---|---|
| `ProgramResolver` | ADR-008 | `environment.rs` (`Snapshot`) | The first word of each command is resolved through the search path recorded at `openmoat init` (`environment.json`), not the hook's inherited `PATH`. A pinned program (policy `executables:` or the snapshot) that now resolves elsewhere is a deny with rule `executables` |
| `PathResolver` | ADR-009 | `realpath.rs` (`FsPathResolver`) | Every `fs.read`/`fs.write` path is also checked at its symlink-resolved location; both are evaluated and the strictest wins. New files resolve through their deepest existing ancestor. `read_dir` lists the directories an unquoted glob operand searches, so every path it names is checked too (`expand.rs`, POLICY.md §4) |

Patterns naming `${project}` or `~` are compiled for both the written and the resolved
spelling of the root, so a project under macOS `/tmp` → `/private/tmp` matches either
way. `openmoat policy check` uses the same resolvers (the snapshot only when an
installation exists) and, against the installed policy, the same lock check.

### Policy compiler

ADR-019 makes `policy.yaml` the single source for every enforcement point.
`openmoat_core::ir::lower(policy, ctx)` derives the `Enforcement` IR from the same policy
and `EvalContext` the engine compiles. The engine is the hook backend. Claude Code's,
Codex's and Cursor's sandbox settings (§13) and the Lightweight tier's Seatbelt profile
and Landlock rules (§14) are generated from the IR. The egress proxy decides hosts
through the engine (§12).

| IR part | Contents |
|---|---|
| `fs.read`, `fs.write` | per kind: a default (`allow`/`deny`), deny rules, allow rules. Each rule is one policy group's list, expanded like the engine's patterns (both root spellings, `!` exclusions kept) |
| `egress.net`, `egress.fetch` | the same for hosts. `fetch` takes rules from `fetch` and `net` lists. Both always deny `moat.cloud-metadata` (ADR-020) |
| `secrets` | one entry per policy `secrets:` item (ADR-020), carrying `id`, `host`, `header`, `source` and `plain_http` for OS backends to read without the policy |
| `limits` | empty until the policy schema defines process limits |
| `decide_only` | rule ids per kind the IR cannot carry: `shell`, `env.read`, `env.set`, `mcp`, and `executables` program names; `fs.read` and `fs.write` for `hook_only` deny groups, whose paths OS layers leave to the other rules (ADR-034) |
| `losses` | every place the IR is stricter than the hook, with a message |
| `allowances` | where OS layers may be wider than the hook: `sandbox.read_roots` (ADR-021). Kept out of `fs.read`, so the IR's own verdicts never widen; `Checker::check_os` applies them after the deny rules |

Per access the IR applies deny rules, then allow rules, then the default.
`ir::Checker` is that reference evaluation.

**Lowering never widens.** `defer` lowers exactly like `ask` (ADR-025). An `ask` default lowers to deny. An `ask` rule disappears
under a deny default, where the outcome is the same. Under an allow default it becomes a
deny rule, which also denies where an allow matches. Each case is a loss.

Two tests prove agreement with the engine:
- `tests/ir_consistency.rs` checks every fs, net, fetch and patch conformance fixture.
  The IR verdict on the engine's own atoms (`CompiledPolicy::atoms`, symlinks included)
  must equal the engine verdict, with `ask` and `defer` read as deny.
- `tests/ir_never_widens.rs` lowers generated policies and checks that an IR allow is
  always an engine allow.

One test checks the OS backends against the IR: `sandbox/differential.rs` evaluates the
generated Seatbelt profile (a small SBPL reader) and the Landlock grants for the default
policy and for policies with braces, classes, `?` and `!` exceptions, on paths drawn from
their patterns, against `Checker::check_os`. Where a backend is wider, its report must
name the path as an allowance; where it is narrower, it must report a loss.

`openmoat policy compile` prints the IR.

## 5. Hook responses and exit codes

| Host event | Response | Exit |
|---|---|---|
| Claude Code, Codex, Continue CLI `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":…,"permissionDecisionReason":…}}`; nothing for a `defer` | 0, or 2 on deny |
| Cursor `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` | `{"permission":…,"user_message":…,"agent_message":…}` | 0, or 2 on deny |
| OpenClaw `before_tool_call` (OpenMoat's plugin) | `{"decision":…,"reason":…}`; nothing for a `defer` | 0, or 2 on deny |
| GitHub Copilot CLI `preToolUse` | `{"permissionDecision":…,"permissionDecisionReason":…}`; nothing for a `defer` | 0, or 2 on deny |
| pi `tool_call` (OpenMoat's extension) | `{"decision":…,"reason":…}`; nothing for a `defer` | 0, or 2 on deny |
| Gemini CLI `BeforeTool` | `{"decision":"allow"}`, or `{"decision":"ask"\|"deny","reason":…,"systemMessage":…}`; nothing for a `defer` | 0, or 2 on deny |
| OpenCode 1 `tool.execute.before` (OpenMoat's plugin) | `{"decision":…,"reason":…}` (an `ask` as a deny); nothing for a `defer` | 0, or 2 on deny |
| OpenCode 2 `execute.before` (OpenMoat's plugin) | `{"decision":…,"reason":…}`; nothing for a `defer` | 0, or 2 on deny |
| Claude Code `ConfigChange` | `{}` or `{"decision":"block","reason":…}` | 0, or 2 on block |

A `defer` (ADR-025) writes no output for Claude Code, Codex and the Continue CLI and
exits 0, so the host's own permission flow runs as it would without OpenMoat. Cursor's
`beforeShellExecution` and `beforeMCPExecution` receive it as `ask`, which is Cursor's own
prompt; on `preToolUse` and `beforeReadFile`, which cannot prompt, `Host::decided`
records and answers it as `ask` (below). `guard` prints no trace line for a `defer`.

`ask` is the host's own prompt; OpenMoat has no prompt of its own. Codex cannot ask:
its `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and then runs the
call. So for Codex an `ask` is sent as a `deny` (exit 2) whose reason says to approve
it with `openmoat` or `openmoat allow --last`. Cursor's `preToolUse` and `beforeReadFile` get the
same treatment. The audit log keeps the `ask`, which is what `--last` finds
(`Host::answer`); it approves a shell command or the exact files of a file action.

The Continue CLI (`cn`) cannot ask either. The released `cn` (1.5.47) loads hooks but
fires no event (THREAT_MODEL, "The Continue CLI"), so this adapter is ready for a release that does: `cn` merges
hooks from `~/.claude/settings.json` and `.claude/settings.json` with its own files.
Its runner (`extensions/cli/src/hooks/hookRunner.ts` in continuedev/continue) blocks
only on exit 2, `decision: "block"` or `permissionDecision: "deny"`, so an `ask` would
run the call. `guard --host claude-code` treats a call as host `continue` when
`CONTINUE_PROJECT_DIR` is set (`cn` sets it for every command hook; Claude Code never
does) or when the payload's `transcript_path` is empty (`cn` keeps no transcript file;
Claude Code always sends a path). Either sign is enough, because a Claude Code call
mistaken for `cn` only turns an ask into a deny. For `continue` an `ask` is sent as a
`deny` with the same `openmoat allow --last` instruction as for Codex, and the audit log
records host `continue` with the `ask`. Everything else is decided as for Claude Code
(`Host::sender`, `crates/openmoat-hosts/src/host/continue_cli/fixtures/`, built from `cn`'s hook source).
`continue` is not in `Host::ALL`: it has no hook file of its own to install.

Cursor prompts on `ask` for `beforeShellExecution` and `beforeMCPExecution` only
(<https://cursor.com/docs/hooks>: `ask` is an output of both, and its shell example asks
for permission with it). For `preToolUse` the same page says `ask` is "accepted by the
schema but not enforced", so the call runs, and `beforeReadFile` takes only allow or
deny. The Cursor adapter marks those two events `HookEvent::PreToolUseNoAsk`, and an
`ask` there is sent as a `deny` (exit 2) whose reason says to approve it with `openmoat` or
`openmoat allow --last`, which approve the exact file. The audit log keeps the `ask`.

Gemini CLI reads only `deny` (or `block`) and `ask` from a `BeforeTool` hook
(`packages/core/src/scheduler/hook-utils.ts`, `@google/gemini-cli` 0.65.0). An `ask`
forces its own confirmation, also where its policy, auto-edit or YOLO mode would run
the call; `allow` and no output both leave the call to its policy, so an `allow` there
skips none of Gemini CLI's confirmations and a `defer` writes nothing. Gemini CLI parses
stdout as JSON whatever the exit code, so the deny document and exit 2 agree. It has no
fail-closed key: a hook that times out, is killed or exits 1 lets the call run, and one
that exits with another code and prints something blocks it. On Windows it runs the
hook command with PowerShell, so the entry quotes the binary after `&` and exits 2 when
PowerShell cannot run it (`openmoat-hosts/src/host/gemini_cli/hook_file.rs`).

Hermes Agent runs a `pre_tool_call` shell hook from its `config.yaml` (YAML, which Hermes
rewrites itself, comments kept): `openmoat init` adds one entry, `command`, `timeout: 60`
and `fail_closed: true`, with no `matcher`, as text (`HookLayout::Yaml`,
`openmoat-hosts/src/wire/hook_file/yaml.rs`): only the entry's lines are added or taken
out, and the result must parse to the document the `HookFile` edit gives, or nothing is
written and `init` prints the entry to add by hand. Hermes runs the hook only once its
exact command is approved in `shell-hooks-allowlist.json` beside it, so `init` writes
that approval too (`InstallSpec::consent`, a `ConsentFile`, `install/consent.rs`), the
lock pins it with the hook file, and `status` and `doctor` report a hook it does not
approve (`HookState::Unapproved`). The lock pins `config.yaml` in its host's pinned form
(`pinned_forms`), read as YAML: without `mcp_servers` and the keys Hermes rewrites for a
person's choice. The reply is `{"decision": "block", "reason"}` and exit 2 for a deny,
`{"action": "approve", "message", "rule_key"}` for an ask, which Hermes puts to the
person in its own approval prompt, `{}` for an allow and nothing for a defer. Hermes
approves an ask unseen in YOLO mode, with `approvals.mode: off` and in unattended modes
set to `approve`; the spec's `Asks::unseen` names what shows that (`HERMES_YOLO_MODE`, the
settings in `config.yaml`), and `guard` (`commands/guard/unseen.rs`) then marks the call
`HookEvent::PreToolUseNoAsk`, so its ask is a deny with the `openmoat allow --last`
instruction. The payload's `cwd` is the Hermes process's, not the session's, so the
adapter asks about a file tool's relative path (`unchecked`).

Claude Code sends its session's `permission_mode` with `PreToolUse`. Two modes put no
question to a person: `bypassPermissions` skips Claude Code's prompts and `dontAsk`
denies whatever would prompt. For these the adapter marks the call
`HookEvent::PreToolUseNoAsk`, and an `ask` is sent as a `deny` with the same
`openmoat allow --last` instruction; the audit log keeps the `ask`. A `defer` stays a
`defer` (Claude Code decides it as its mode says). Every other mode, `auto` included,
receives the `ask`.

Codex's `PermissionRequest` hook does not change this (#178, checked against
openai/codex `ff9ab4a` and codex-cli 0.160.1). Codex runs it only from
`Session::request_approval` (`core/src/tools/approvals.rs`), after its own approval
policy and sandbox have decided to prompt. The hook can answer allow, deny or nothing;
nothing shows Codex's prompt. No hook can send a call into that path, so a `PreToolUse`
`ask` that let the call through would run unprompted whenever Codex itself does not
prompt. `openmoat init` therefore does not install `PermissionRequest`. `guard` refuses that
event as a wrong event (deny, exit 2, reason on stderr), which Codex reads as a deny
(`crates/openmoat-hosts/src/host/codex/fixtures/permission-request-shell.json`, built from Codex's
`permission-request.command.input.schema.json`). Exit codes follow
ADR-004 and ADR-015: 0 allow, defer or ask, 2 deny, 3 unresolved ask from `openmoat policy
check`, 64 usage or configuration error. `openmoat run` exits 1 when the agent it started
exits non-zero; never 2 or 3. `guard` never exits 64: an argument it cannot
parse is a deny with exit 2, because Claude Code and Codex proceed on any other
non-zero exit. Cursor is fail-open unless a hook sets `failClosed: true`, so
`openmoat init` sets it on every Cursor hook. Claude Code 2.1.295 and later block a call
whose hook fails to start, crashes, exits other than 0 or 2, or times out when the hook
sets `"onFailure": "block"` (<https://code.claude.com/docs/en/hooks>, "Block the action
when a hook fails"). `openmoat init` writes it on its `PreToolUse` entry when `claude --version`
(the `claude` on `PATH`, 5 s at most, asked once per command) reports 2.1.295 or later
(`install/claude_version.rs`); `status` and `doctor` then report an entry without it as
out of date. With an older Claude Code, or none on `PATH`, the key is left out and
`doctor` warns. A key already there is kept, so a shell without `claude` never takes it
away. Codex has no such key: a failed hook "continues the tool call"
(<https://learn.chatgpt.com/docs/hooks>).

## 6. Self-protection

- **Policy lock** (ADR-006). `~/.moat/policy.lock` pins SHA-256 digests of the policy,
  `environment.json`, `approvals.json`, `policy.d/approved.yaml`, `trust.json` and every
  hook file OpenMoat installed, keyed by location so a swap for a symlink is a
  modification. One of those state files that is missing when the lock is written
  (`trust.json` before the first `openmoat trust`, or a file a person accepted as
  deleted) is pinned as `absent`, so a file that appears there later is drift rather
  than read unpinned. Claude Code's `settings.json` is pinned by the canonical JSON without
  its top-level `theme` key, which Claude Code writes itself on first run (#287); a
  file that does not parse is drift, and a whole-file digest from an older lock still
  verifies until the next re-pin. The lock also pins the part of Codex's `config.toml` that holds OpenMoat's sandbox profile
  (§13). It is verified on every `guard` call. For each pinned JSON or TOML file the
  lock also records a digest per top-level key, so drift (in `guard` reasons, `doctor`,
  and `doctor --accept` before it re-pins) names the keys that were changed, added or
  removed: `settings.json was modified: changed hooks; added theme`. A lock written
  before that, or a file that no longer parses, gives the plain `was modified`. For a
  Claude Code `settings.json` the lock also records a digest per key of `permissions`.
  With them, `guard` (and `openmoat policy check`) keep deciding while the only drift is in
  an allowlist of Claude Code keys (`integrity/relaxed.rs`): display and reply toggles
  (`language`, `outputStyle`, `spinnerVerbs`, …; not `autoMode`, whose rules decide
  which calls Claude Code's auto mode runs unasked), the model the person
  switches to (`model` as a string, `switchModelsOnFlag` as a scalar) and Claude Code's own
  permission lists and a mode that keeps its prompts (`permissions.allow`, `ask`, `deny`,
  `blockReadsOutsideWorkingDirectories`, and `defaultMode` set to `default`, `plan` or
  `dontAsk`, or removed). They change only Claude Code's own prompts; the hook still
  decides every call. A `defaultMode` of `acceptEdits`, `auto`, `bypassPermissions` or
  any other value runs deferred calls unasked, and `additionalDirectories` widens what
  Claude Code's sandbox lets commands write, so either denies like other drift. A `deny` list that
  lost a rule OpenMoat wrote (recorded as `claude_rules` in `hosts.json`), any other or
  unknown key (`hooks`, `env`, `apiKeyHelper`, `statusLine`, plugin, MCP and `sandbox` keys),
  a file that no longer parses or is a symlink, a lock without the `permissions` digests,
  or drift in any other pinned file still denies every call. Allowlisted drift stays
  drift: `status` and `doctor` report it until a person re-pins, the commands that
  re-pin still refuse while it is there, and `openmoat proxy` and `openmoat run` still refuse to
  start. A host's spec can list keys of its own hook file the same way
  (`InstallSpec::relaxed_keys`, `integrity/spec_keys.rs`): Gemini CLI writes its
  `settings.json` itself for a new model, theme, sign-in method or display toggle
  (`gemini_cli/settings.rs`: `model.name`, `ui.theme`, `security.auth.selectedType`,
  `general.vimMode`, `ide.hasSeenNudge` and display-only `ui.*` keys, each a string or
  a boolean). For such a file, found by its `<dir_name>/<config_file>` ending, the
  lock also pins the digest of the file with those keys taken out (`relaxed_rest`);
  drift whose rest still has that digest is decided through and reported, and that
  host's list replaces Claude Code's for its file. A value of another shape, any
  other key (`hooks`, `hooksConfig`, `tools`, `mcpServers`, `security.folderTrust`,
  `context`, `advanced`, an unknown one), a file with comments or that no longer
  parses, a link, or a lock without the rest's digest still denies every call.
  Only a person re-pins: `openmoat init`, or
  `openmoat doctor --accept`, `openmoat allow`, `openmoat edit`, `openmoat secret`, `openmoat trust` and `openmoat sandbox sync` from an
  interactive terminal.
- **ConfigChange veto.** Claude Code reports settings changes; while any pinned file
  no longer matches the lock, every change is blocked for the session, unless all of
  that drift is allowlisted settings drift, which loads. Codex and Cursor have no such
  event, so there the next tool call is denied instead. A `/settings-review` accept
  writes the new contents to `<file>.proposed-<8 hex>`, fires `ConfigChange` for that
  copy and renames it over the file only if no hook blocks; when `<file>` is pinned,
  the copy is blocked unless the file still matches the lock and the copy's bytes equal
  the pinned ones, so a reviewed edit of a pinned file cannot pass the hook. A project's
  `.claude/settings.json` and `.claude/settings.local.json` are not pinned: they come
  from the repository. A change of one (source `project_settings` or `local_settings`)
  is read and blocked with `project-settings` when it sets a key that turns hooks off,
  runs a program or redirects the agent, or cannot be parsed (`project_settings.rs`);
  `openmoat doctor` and `openmoat status` warn about such a file in the current project, which
  Claude Code loads at session start without a `ConfigChange`.
- **`kernel-self` rules.** The default policy denies agent writes to the state and
  host directories (also where `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or
  `CURSOR_CONFIG_DIR` moved them, and where `openmoat init` recorded them in `hosts.json`), hook
  files and any `bin/openmoat` or `bin/moat` (`moat` is the command's name up to 0.7.0,
  installed beside `openmoat` for a few releases; it runs the `openmoat` next to it), and
  denies `openmoat allow|doctor|edit|init|policy|secret|trust|uninstall`, `openmoat sandbox
  sync` and `openmoat audit anchor` from an agent, by either name, including under pseudo-terminal
  wrappers (ADR-011, ADR-014). It also denies agent reads of the state beside the
  policy (`audit.db*`, `policy.lock`, `hosts.json`, `approvals.json`, `trust.json`,
  `allowed_signers`, `mcp/`), and every host sandbox and `openmoat run` profile carries the
  same read denies; `policy.yaml` stays readable. Nothing that decides needs those reads
  from inside a sandbox: host hooks run outside the host's sandbox, an `openmoat guard`
  inside `openmoat run` relays the payload to the `openmoat run` process outside before it
  touches OpenMoat's home (ADR-028), and the commands that read them (`show`, `status`,
  `doctor`, `audit`) are a person's, run outside any sandbox.
- **Signed policy** (ADR-031, `signing.rs`, `packs.rs`). `openmoat policy trust-key` adds an
  OpenSSH key to `allowed_signers` for the namespaces `openmoat-repo-policy` (repository
  policies, ADR-037) and `openmoat-pack` (packs, ADR-036); `openmoat policy
  install` checks a pack's detached signature in `openmoat-pack` with the system `ssh-keygen -Y verify`
  (resolved through `environment.json`) before copying it to `policy.d/packs/` and
  recording it in `packs.json`. `Home::load_policy` merges every pack `packs.json` lists
  under `pack:<name>:` ids, only while the lock pins `packs.json` and each pack still has
  its recorded SHA-256. Those files are pinned only by `trust-key`, `install` and
  `remove` (`integrity::signing_files`); other re-pins keep the pins without adding them.
  With `require_signed_repo_policy: true`, `repo.rs` trusts a repository policy only
  when its `policy.yaml.sig` verifies against `allowed_signers`; a `trust.json` record
  alone no longer counts (`repo::is_trusted`).
- **Terminal check.** `openmoat allow`, `openmoat edit`, `openmoat secret`, `openmoat trust`, `openmoat uninstall`, `openmoat doctor --accept`,
  `openmoat sandbox sync`, `openmoat policy upgrade`, `openmoat policy install`/`trust-key`/`remove`,
  `openmoat audit anchor`, `openmoat mcp accept`/`wrap`/`unwrap` and
  `openmoat proxy install`/`uninstall` refuse to
  run without a terminal (`terminal.rs`). They also refuse when an agent host (`claude`,
  `codex`, `cursor-agent`, `cn`, `copilot`, `gemini`, `openclaw`, `pi`, `opencode`, the Cursor
  editor's `Cursor Helper` processes on macOS) or `openmoat` itself (`openmoat run`) is among their parent processes,
  or when those cannot be read (`terminal/ancestry.rs`: `/proc` on Linux, `/bin/ps` on
  macOS; not checked on Windows yet), and the home screen offers no approval there.
  Their answers are read from the controlling terminal (`/dev/tty`), not stdin. The
  debug-only `MOAT_ASSUME_TTY` override exists for tests; release builds do not contain it.
- **Stable hook path** (ADR-016). Hooks run the package manager's stable link to
  `openmoat`, not a versioned file an upgrade deletes; `doctor` and `status` name a hook
  whose binary is missing or is a different `openmoat`.

## 7. Audit log

`~/.moat/audit.db` is SQLite in WAL mode, created with mode 0600 on macOS and Linux
(on Windows it keeps the permissions it inherits from its directory, by default inside the
user's profile; OpenMoat sets none of its own there), with one `events`
table (time, host, session, call id, working directory, tool, action, verdict, rules,
reasons, latency). Every governed and ungoverned call is recorded. `Store::record`
redacts every text the agent can influence (each string of the action, the reasons,
the working directory) in one place, so guard rows, proxy rows and exports are all
covered; host, session and call ids and the tool name come from the host and are
stored as sent. Redaction is two passes (`crates/openmoat-audit/src/redact.rs`):

1. **Exact values.** The values of the policy's brokered secrets (`secrets:`) are
   replaced by `[redacted]` wherever they occur, in any letter case (the proxy
   records host names lowercased), whatever their format. All values are matched by
   one automaton, so the cost is linear in the text. Values shorter than 8 bytes
   (`MIN_SECRET_LEN`) are not matched this way: they occur in ordinary text too. The
   proxy masks every value it holds. `openmoat guard` masks, in every call the policy
   decides, the values it can read, those with a `file` or `env` source; it does not
   start the keychain tool per call, and it skips a source it cannot read. Rows of an
   ungoverned tool, a settings change or a call refused for lock drift are written
   before or without loading the policy and get the patterns only.
2. **Patterns.** Bearer and basic auth, `key=value` and quoted `"key": "value"`
   credentials, `-u user:password`, common token shapes, URL passwords. A few
   matches are kept because they hold no credential (`redact/judge.rs`): a name whose
   last part is `count`, `file`, `path`, `dir`, `name`, `id`, `len`, `length`,
   `size`, `type` or `url` (`token_count=`, `--token-file=`); a `-u` drive path or
   `uid:gid` outside an HTTP client (`python -u C:\x`); prose after `Bearer` or
   `Basic` (`bearer authentication`). Anything else that matches is masked.

The policy has no other declaration of secret environment variables: `env-secrets` is
a list of names the agent may not read (it includes `AWS_REGION`-style names), not of
values to mask. `show`, `replay` and `report` read the log; nothing leaves the machine
unless a person runs `openmoat audit export`.

**Hash chain** (schema 2, `crates/openmoat-audit/src/store/chain.rs`). Each event also
stores `prev_hash`, the `hash` of the event before it, and `hash`, the lowercase hex
SHA-256 of its canonical encoding. The encoding (version 1) is the concatenation of:
the domain tag `moat-audit-chain-v1` as a string; `id` and `ts_ms` as integers;
`host` and `session_id` as strings; `call_id` and `cwd` as optional strings; `tool`,
`action`, `verdict`, `rules` and `reasons` as strings, exactly as stored (the redacted
JSON text for `action`, `rules`, `reasons`); `latency_us` as an integer; `prev_hash`
as a string. An integer is 8 bytes big-endian; a string is its UTF-8 byte length as
8 bytes big-endian followed by the bytes; an optional string is `0x00` when absent,
else `0x01` and the string. The first chained event's `prev_hash` is 64 zeros. The
encoding hashes stored cells, not re-serialised values, so a later build that
serialises actions differently still verifies old events; changing the encoding
needs a new domain tag.

`guard` appends in one `BEGIN IMMEDIATE` transaction: read the newest event's id and
hash, insert the next event with `id + 1` linked to it, commit. Concurrent `guard`
processes serialise on SQLite's write lock (busy timeout 2 s), so the chain never
forks; a write that fails or times out is a `kernel-error` deny as before. The
transaction adds about 0.1 ms to a guard call. `openmoat doctor` re-hashes the whole log
oldest first (about 0.15 s per 100 000 events) and reports the first event that was
edited (contents do not match its hash), unlinked (an event before it was deleted or
inserted, or events were reordered) or unhashed, and exits 64.

**Session cache** (`store/session_cache.rs`). Session taint is the fold of a session's
earlier events (POLICY.md §4.1). `guard` keeps that fold in a `session_folds` table,
one row per session, host and digest of what the fold depends on: this build's
version, the effective policy and context, and the working directory. Each row holds
the newest event it covers. A call reads the row of its own digest, folds only the
events recorded since, and writes it back, so a late call in a long session stays
fast (#570). Calls of one session from different working directories fold under
different digests and keep a row each (up to 16 per session and host, the least
recently written going first), so they read on from their own row instead of
replacing each other's and folding the whole session again. The write goes on the
connection the call then records with, just before the record's transaction, and
does not wait for the database's lock: while another call holds it, the write is
skipped and the older row stays, so the next call folds a few more events. A row
is replaced only by one further on, so a skipped or late write never moves it back.
Without a row for the digest, or when it cannot be read, the session is folded from
its first event. A fold reads the events 512 at a time; one that runs long saves
what it has reached every 2 s, on a writable handle of its own, and at 20 s into
the guard's 30 s budget it stops, saves, and the call is denied (`kernel-error`,
recorded) rather than answered from part of the session, which may lack the event
that tainted it. The next call reads on from the saved row, so a session too long to
fold in one call catches up over a few calls instead of timing out on every one. The
cache is outside the hash chain and never a source of truth: it can only hold what
the events folded to. The table is created on first use, without changing the schema
version, so older builds still open the database (they keep using the one-row
`session_cache` table of earlier versions, which this build no longer reads).

**File provenance** (schema 4, `store/provenance.rs`, `crates/openmoat-cli/src/taint/provenance.rs`,
ADR-029, POLICY.md §4.1.1). A `provenance` table holds one row per file a call wrote or
read that matters for taint: the event id, time, host, session, kind (`tainted-write`,
`clean-write`, `tainted-read`), the path (lowercased where paths are case-insensitive),
the SHA-256 of a `Write`'s whole content when known, and the untrusted content behind it.
Its texts are redacted as an event's are. Triggers refuse an `UPDATE` or `DELETE`, so
rows are only appended, and the table lives in `~/.moat`, which `kernel-self` denies to
the agent. While a call is decided, `guard` classifies it once more, looks up the newest
write row of each file it reads or runs through the index on `(path, id)`, and hashes
the file on disk only when that row is tainted and carries a hash (files over 1 MiB, the
largest payload, cannot match). The rows the call adds are written after its event, in
their own transaction, and only when the call may have run; a failed write fails the
call like the event. A session's `tainted-read` rows (index on `(session_id, host, id)`)
are added to its taint on every call, outside the session cache. A clean session with
no provenance rows in the log skips the lookups. The upgrade from schema 3 creates the
table; a read-only handle on an older database reads it as empty. A schema-4 database
is refused by builds before it (`SchemaTooNew`), as every schema bump is.

**Export** (`openmoat audit export`, `crates/openmoat-audit/src/store/export.rs`). JSON Lines,
oldest first, one object per chained event with the filters `--since`, `--host` and
`--session`. Every line has `"format": "moat-audit-export-v1"` and the fields `id`
(hex), `ts_ms`, `host`, `session_id`, `call_id`, `cwd`, `tool`, `action`, `verdict`,
`rules`, `reasons`, `latency_us`, `prev_hash` and `hash`. `action`, `rules` and
`reasons` are the stored JSON text embedded byte for byte, not re-serialised, so the
line holds exactly the cells the chain hashed; a field outside this list makes the
line invalid. Cells are already redacted in the store and are not touched again, so
an export holds no more than the database. Events from before the chain have no hash
and are left out. A new line format gets a new `format` value.

**Verify** (`openmoat audit verify`, `store/export_verify.rs`). It works without the
database. Every line must hash to its `hash`, ids must rise, and a line whose id
follows the previous line's id must carry that line's hash as `prev_hash`. A jump in
ids is a gap, which is counted and not failed: a filtered export has gaps, and so
does deleting events. The first failing line is named and the command exits 64. The
head is the last line's `hash`. `openmoat doctor` prints the database head. With
`--anchor <hash>`, verify also fails unless a verified line carries that hash.
Without one, the result says the export is not anchored (`"anchor": "not_anchored"`
in JSON), and `--require-anchor` turns that into exit 64.

**Anchors** (`openmoat audit anchor`, `crates/openmoat-cli/src/anchor.rs`, ADR-031). A
person-only command records the database head (`Store::head`: newest event id, its
time and hash) after `verify_chain` finds no break, as one JSON line `{"format":
"moat-audit-anchor-v1", "event", "hash", "event_ms", "anchored_ms"}`. With `--file` the
line is appended to a file the person keeps. With `--git <repo>` it is appended to
`anchors.jsonl` in the tree of `refs/moat/anchors` in that repository, as a new commit
built with plumbing only (`hash-object`, `mktree`, `commit-tree`, then `update-ref`
against the old tip), with a `Signed-off-by` trailer from git's committer identity; the
working tree, index, `HEAD` and branches are not touched, and nothing is pushed.
`~/.moat/anchor.json` remembers the last anchor for `openmoat doctor`. `openmoat audit verify
--against <repo|file>` reads every anchor back and checks each, oldest first, against
the database: the event must still exist (`Store::hash_of`) with the anchored hash, and
the chain must not break at or before it. The first anchor that fails is named
(`missing`: deleted, `rewritten`: another hash, `chain_broken`) and the command exits
64. No code here opens a network connection.

**Team report** (`openmoat audit report <file>…`, `crates/openmoat-cli/src/commands/team.rs`).
It verifies every file first and refuses (exit 64) if one fails. Events with the
same `hash` are counted once, so overlapping exports do not double-count. The report
starts with the `openmoat report` summary (`Summary::of`), then shows each file's head,
verdicts per host, asks and denies per rule, and the most frequent asked and denied
actions. False-positive candidates are actions that asked and were also allowed by
an `approved-…` rule (`openmoat allow`), which suggests the asking rule is too broad.
`--format json` gives the same data.

The upgrade from schema 1 adds the two columns and records the last existing id as
`legacy_last_id` in a `meta` table. Existing events are not hashed: they were written
unprotected, and hashing them during the migration would vouch for whatever they hold
at that moment. `doctor` counts them as not covered; an event without a hash after
`legacy_last_id` is a break. What the chain does not detect is in [THREAT_MODEL.md](THREAT_MODEL.md) §5.

## 8. Files on disk

```
~/.moat/                       ($MOAT_HOME overrides; directory 0700, files 0600 on macOS and Linux; on Windows inherited permissions)
  policy.yaml                  user policy (openmoat init writes the default once)
  policy.yaml.bak              the policy before the last `openmoat edit` applied a change
  policy.base.yaml             the shipped default the policy started from or was last upgraded to
  policy.yaml.before-upgrade   the policy before the last `openmoat policy upgrade` (and the base's copy)
  policy.d/approved.yaml       permanent rules from `openmoat allow --always/--site/--dir`
  approvals.json               session grants from `openmoat allow` (24 h each)
  hosts.json                   the agent config directories `openmoat init` used, and the backups and rules it wrote
  trust.json                   repository policies trusted with `openmoat trust`: root → SHA-256
  allowed_signers              keys trusted with `openmoat policy trust-key` (OpenSSH format)
  packs.json                   installed policy packs: name → SHA-256, signer, time
  policy.d/packs/<name>.yaml   each installed pack, and its `.yaml.sig`
  environment.json             search path and program locations recorded at init
  policy.lock                  digests of the files above and of installed hook files
  audit.db                     audit log
  anchor.json                  when and where `openmoat audit anchor` last recorded the head
  mcp/                         `openmoat mcp proxy` tool pins, per server
  guard-hangs.log              calls the guard denied because no decision came in time
~/.claude/settings.json        Claude Code hooks and sandbox block ($CLAUDE_CONFIG_DIR overrides)
~/.codex/hooks.json            Codex hooks ($CODEX_HOME overrides)
~/.codex/config.toml           Codex [permissions.moat] profile, default_permissions
<file>.moat-backup             each hook file before OpenMoat's first hook edit
<file>.moat-sandbox-backup     each host file before OpenMoat's first sandbox edit
                               (both listed in hosts.json; uninstall deletes only those)
~/.cursor/hooks.json           Cursor hooks ($CURSOR_CONFIG_DIR overrides)
~/.cursor/sandbox.json         Cursor sandbox keys, next to hooks.json
~/.gemini/settings.json        Gemini CLI hooks ($GEMINI_CLI_HOME/.gemini when set)
~/.openclaw/openclaw.json      OpenClaw plugin entries ($OPENCLAW_STATE_DIR overrides)
~/.openclaw/openmoat/          OpenMoat's OpenClaw plugin
~/.copilot/hooks/openmoat.json GitHub Copilot CLI hook file of OpenMoat's own ($COPILOT_HOME overrides)
~/.pi/agent/extensions/openmoat.js  pi extension ($PI_CODING_AGENT_DIR overrides)
~/.config/opencode/plugins/openmoat.js  OpenCode plugin ($OPENCODE_CONFIG_DIR or $XDG_CONFIG_HOME/opencode when set)
<project>/.moat/policy.yaml    repository policy, committed by the team (ADR-022)
<project>/.moat/policy.yaml.sig  its optional detached signature (ADR-031)
```

Host sandboxes and `openmoat proxy` are generated from the user policy only. Repository
rules apply in the hook.

## 9. Invariants

The full list, with the tests that hold each one, is AGENTS.md §3. In short: deny is
absolute; strictest wins; unparseable is never `allow` (`ask`, or `defer` under an allow or defer catch-all); every error path in `guard` is a deny
with exit 2; exit codes 2 and 3 mean nothing else; nothing persisted skips
redaction; the core stays pure; `openmoat init` never overwrites a policy or duplicates a
hook; the lock is checked before any decision.

## 10. Repository layout

```
crates/openmoat-core/          decision core; policies/default-v1.yaml is the shipped policy
crates/openmoat-hosts/         host adapters; src/host/<module>/fixtures/ holds each host's
                               real payloads
crates/openmoat-audit/         audit store
crates/openmoat-proxy/         egress proxy; tests/proxy/ runs it on loopback
crates/openmoat-cli/           the openmoat binary; tests/e2e/ runs it in isolated homes;
                               moatbench/ holds the MoatBench scenarios `openmoat bench` bundles
tests/conformance/             attacks.yaml, ask.yaml, benign.yaml: one tool call each,
                               with the verdict the default policy must give
tests/differential/            differential scenarios and hostile scripts (EVIDENCE.md)
fuzz/                          cargo-fuzz targets: decide_shell, policy_parse,
                               host_payload, literal_pattern, proxy_parse,
                               openclaw_json5 (separate workspace)
docs/                          this document, INSTALL, USAGE, SANDBOX, POLICY,
                               THREAT_MODEL, ROADMAP, COVERAGE and EVIDENCE
                               (generated), adr/
scripts/ci/quality-gate.sh     the one gate CI and the pre-push hook run
scripts/ci/guard-latency.py    times `openmoat guard` per process in CI (the `latency` job)
scripts/ci/guard-session-latency.py
                               times it late in a long session (the same job)
scripts/ci/sync-labels.sh      the repository's label set
```

### Module map

What each module holds. The rules for each path are in `AGENTS.md` §2.

| Path | Contents |
|---|---|
| `crates/openmoat-core` | policy model (`policy.rs`, `lint.rs` with `lint/ports.rs` ports written as no port, `repo.rs` repository policy merge), popular-package lists and the near-miss check (`packages.rs`, data in `data/top-packages/`, ADR-030), lexer (`lexer/`), classifier (`shell/`; `shell/push.rs` the pushes a command makes, `shell/executes.rs` the files a command runs as code, with `executes/interpreters.rs` each interpreter's options and `executes/inline.rs` the modules inline code loads (ADR-039), `shell/commands/payload/opaque.rs` inline code that builds the names it opens, `shell/upload.rs` files curl and wget send, `shell/commands/fetch.rs` curl and wget calls that send nothing, decided like a fetch (ADR-035), `shell/options/transfer.rs` one reading of curl and wget options, shared by that check and the files they write, `shell/in_place.rs` files edited in place, `shell/installs.rs` package installs, `shell/commands/wrappers/launchers.rs` launchers that run a command (`taskset`, `unshare`, `systemd-run`, `launchctl submit`, …), `shell/copy/links.rs` whether `ln` or `cp` makes hard links, `shell/extract.rs` where `tar -x` and `unzip` extract to, `shell/error.rs` why a line cannot be classified), patterns (`pattern/`; `pattern/sequence.rs` linear word matching), URL hosts (`host.rs`), known token formats (`token.rs`), paths, YAML reading (`yaml.rs`, ADR-024), engine (session taint in `engine/taint.rs`, tokens and placeholders sent off their service in `engine/egress.rs`, other spellings of a command that runs OpenMoat's own binary in `engine/aliases.rs`, the folder rule (`protected-contents`, ADR-038) in `engine/contents.rs`, the policy's `taint:` section in `taint.rs`), policy compiler (`ir/`), executable pins (`programs.rs`, `ProgramResolver`), symlink resolution and glob operand expansion (`realpath.rs`, `PathResolver`, `expand.rs`), the files a Codex `apply_patch` names (`patch.rs`), actions, verdict |
| `crates/openmoat-hosts` | host adapters: `host/<id>.rs` per host with its `SPEC` (`host/claude_code.rs` with `claude_code/config_change.rs`, `host/codex.rs`, `host/continue_cli.rs`, `host/cursor.rs`, `host/openclaw.rs` with `openclaw/tools.rs`: OpenClaw's `before_tool_call`, through OpenMoat's plugin, ADR-033; `host/copilot_cli.rs` with `copilot_cli/tools.rs`: GitHub Copilot CLI's `preToolUse`; `host/pi.rs` with `pi/tools.rs`: pi's `tool_call`, through OpenMoat's extension; `host/gemini_cli.rs` with `gemini_cli/tools.rs`: Gemini CLI's `BeforeTool`; `host/hermes.rs` with `hermes/tools.rs`, `hermes/hook_file.rs`, `hermes/consent.rs` (its `shell-hooks-allowlist.json`), `hermes/location.rs` and `hermes/settings.rs` (its pinned form, and the settings that approve an ask unseen): Hermes Agent's `pre_tool_call`; `host/opencode.rs` with `opencode/tools.rs` (`tools/v1.rs`, `tools/v2.rs`): OpenCode 1's `tool.execute.before` and OpenCode 2's `execute.before`, through OpenMoat's one plugin, ADR-040; each host's `doc.rs`: its README row and tool mapping rows); `host.rs` (the one list of hosts); `registry.rs` (the `hosts!` macro: `Host`, `Host::EVERY`, `Host::ALL`, each host's spec and adapter); `contract.rs` (`HostSpec`, `Asks`, `InstallSpec`, `HookSpec`, `HookLayout`, `GUARD_BUDGET_S`, the `HostAdapter` trait, and what each host receives for `defer` and `ask`; `contract/docs.rs`: `HostDocs`, `ToolRow`; `tests/docs.rs` generates the host tables in README, INSTALL, ARCHITECTURE §3 and THREAT_MODEL from the specs; `contract/heartbeat.rs`: `Heartbeat`, how a plugin host's plugin reports loading, ADR-042; `tests/js_plugins/` runs each host's JavaScript plugin under Node against a stand-in for the host and the guard, and `jsconfig.json` type-checks them with `scripts/ci/check-js.sh`); `wire/pre_tool_use.rs` (the format Claude Code, Codex and the Continue CLI send), `wire/pre_tool_use/artifact.rs` (the files Claude Code's `Artifact` and `ArtifactData` upload or save), `wire/hook_file.rs` (the `HookFile` trait: OpenMoat's entries among the person's own in a hook file, as pure edits of the parsed document; `wire/hook_file/nested.rs` Claude Code's and Codex's layout, `wire/hook_file/yaml.rs` the same entries edited as text in a YAML file, each other layout in `host/<id>/hook_file.rs`), `contract/consent.rs` (the `ConsentFile` trait: a host's record of consent to a hook command), `wire/owned_file.rs` (files OpenMoat owns whole: `host/openclaw/integration/openmoat.mjs`, the plugin `openmoat init` installs for OpenClaw, and `host/pi/integration/openmoat.js`, the extension it installs for pi; no dependencies, both fail closed), `wire/mcp.rs` (MCP arguments), `wire/unknown.rs` (what the arguments of a tool an adapter does not map name, for every host), `glob.rs` (where a glob pattern's `..` climbs to, and whether a brace group makes that unknown); `bench.rs` (what `openmoat bench` needs from a host) |
| `crates/openmoat-audit` | SQLite store (`store/`: schema, hash chain, export, session cache, `provenance.rs` file provenance rows, `session_writes.rs` the files each session wrote, `mcp_tickets.rs` the MCP calls the hook let through, which `openmoat mcp proxy` matches (ADR-045), `seen.rs` a host's newest decision since a time), time-window and session queries (`query.rs`), redaction and token formats (`redact.rs`) |
| `crates/openmoat-proxy` | egress proxy behind `openmoat proxy`: `request.rs` (HTTP head), `sni.rs` (ClientHello), `decide.rs` (host and address checks; `decide/ports.rs` which ports of a host), `upstream.rs` (DNS, connect), `server.rs` with `server/{wire,limits,capacity,recheck}.rs` (reading a head or ClientHello in time and answering a refusal; resource limits; recording refusals at accept; session taint at open and again while relaying), `tunnel.rs`, `audit.rs` (`Recorder` trait), `broker.rs` (secret injection and leak blocking), `session.rs` (per-session credentials and taint, the credentials it holds for `openmoat run` (ADR-027) and the `Verify` trait for those the standalone proxy checks (ADR-044)), `slots.rs` (each session's share of the connections), `local.rs` (`LocalService`: a service of the proxy's own process on its port, ADR-028) |
| `crates/openmoat-cli` | the `openmoat` binary: `cli.rs` grammar (`cli/{mcp,policy,audit}.rs` for those command groups), `commands/{overview,init,uninstall,guard,show,status,doctor,allow,edit,secret,trust,mcp,replay,report,audit,team,policy,proxy,sandbox,run}.rs`, `commands/guard/{config_change,drift,session_start,unseen}.rs` (the ConfigChange decision; settings drift the guard decides through; Claude Code's SessionStart, which issues the session its `openmoat proxy` credential (ADR-044); whether the host would approve an ask unseen), `proxy_session.rs` with `proxy_session/hmac.rs` (the standalone proxy's signed session credentials and their key, ADR-044), `commands/audit/anchor.rs` and `commands/policy/pack.rs` (`openmoat audit anchor`; `openmoat policy trust-key`, `install`, `remove`), `protection.rs` (each agent's protection level for `status`, `doctor` and the home screen), `commands/run/{macos,linux,unsupported}.rs` (`openmoat run` per OS), `commands/run/release_age.rs` (the npm and uv release-age variables `openmoat run` sets), `commands/run/linux/isolate.rs` (`openmoat run --isolate`, the Isolated tier on Linux), `commands/run/linux/netns.rs` (`openmoat run`'s network namespace on Linux: loopback and a relay to the proxy), `commands/demo.rs` (`openmoat demo`: verdicts for example calls, nothing runs), `commands/service/` (`openmoat proxy install`: `macos.rs` launchd agent from `plist.rs`, `linux.rs` systemd user unit from `unit.rs`, `unsupported.rs`), `commands/bench/` (`openmoat bench`: `hosts.rs` host payloads and how each host reads a hook reply, `hook.rs` the throwaway home and time limit, `scenario.rs` reads the bundled scenarios, `score.rs` the scorecard; scenarios in `moatbench/<category>.yaml`), `install.rs` with `install/{hook_file,binary,dirs,claude_version,openclaw,owned,yaml,consent}.rs` (`dirs.rs`: the recorded agent config directories; `claude_version.rs`: whether the Claude Code on PATH knows `onFailure`; `openclaw.rs`: OpenClaw's plugin file and `openclaw.json` entries; `owned.rs`: a hook file OpenMoat owns whole, pi's extension; `yaml.rs`: a YAML hook file edited as text, Hermes Agent's `config.yaml`; `consent.rs`: a host's record of consent to the hook, Hermes Agent's allowlist), `sandbox/` (backends from the IR, reached through `backend.rs`, one `SandboxBackend` per `SandboxFormat`: Standard tier `claude`, `codex`, `cursor` and `install.rs` file I/O, `claude/mask.rs` whether Claude Code's own broker masks each policy secret, `claude/nodes.rs` the directory nodes left out of `denyWrite` and the `Edit(./…)` rules that keep them in place, `claude/state_dir.rs` the state directory hidden whole on Linux; Lightweight tier `seatbelt` (`seatbelt/braces.rs` brace expansion, `seatbelt/filter.rs` globs as path filters, case-folded for denies on a case-insensitive disk), `landlock`, `seccomp`; Isolated tier `bwrap`; `patterns.rs` classifies IR patterns for hosts without a project of their own; `differential.rs` checks every backend against the IR's reference semantics; `exposure.rs` whether `openmoat run`'s grants hold or lie inside the state directory, which makes `openmoat run` on Linux refuse), `home.rs`, `context.rs`, `project.rs`, `repo.rs` (repository policy file and whether it is trusted), `project_settings.rs` (what a project's `.claude/settings*.json` turns off or runs: the ConfigChange veto and the doctor/status warning), `time.rs`, `os_version.rs` (the macOS version: `openmoat run`'s macOS 13 floor, `doctor`, the bug-report bundle), `environment.rs` (search-path snapshot), `realpath.rs` (symlink resolution), `integrity/` (policy lock; `digest.rs` what a file is pinned by, `forms.rs` which files the lock pins in a host's pinned form (`pinned_forms`), `kept.rs` the bytes the lock check read, which the rest of the call parses, `keys.rs` the top-level keys drift names, `relaxed.rs` the Claude Code settings drift the guard decides through), `mcp.rs` with `mcp/{servers,pins,tools,relay,wrap}.rs` (ADR-026: MCP server definitions pinned in the lock, the `openmoat mcp proxy` JSON-RPC relay and its tool pins, `openmoat mcp wrap`; ADR-032: a new server's tools are held until accepted) and `mcp/relay/{host,server,frame}.rs` (ADR-045: what the relay does with each message from the host and from the server, and the stdio framing), `commands/mcp/gate.rs` (the gateway's decision on each call: the policy on its arguments, the hook's decision it matches, its audit row), `guard_relay.rs` with `guard_relay/{wire,client,service}.rs` (hook decisions inside `openmoat run`, ADR-028: framing, the sandboxed guard, the decision outside), `anchor.rs` with `anchor/git.rs` (audit anchors, ADR-031: the record, the file and `refs/moat/anchors` git plumbing, `verify --against`), `signing.rs` (OpenSSH signatures through the pinned `ssh-keygen`, namespace `openmoat-repo-policy` for repository policies and `openmoat-pack` for packs, ADR-037), `packs.rs` (signed policy packs: `packs.json`, `policy.d/packs/`, merged under `pack:<name>:`), `approvals.rs` (grants and overlay), `secrets/` (brokered secret sources), `taint.rs` (session taint from the audit log; `taint/run.rs` links an `openmoat run`'s agent sessions to the run so its proxy applies their taint, ADR-027; `taint/issued.rs` the taint of a session the standalone proxy serves, ADR-044; `taint/provenance.rs` taint that follows written files, ADR-029), `session_code.rs` (running a file the session wrote where no OS sandbox holds the command asks, ADR-039), `push.rs` with `push/{git,range,scan}.rs` (the push check: git run read-only, which commits a push sends, what they add), `trust.rs` (trusted repository policies), `upgrade.rs` (`openmoat policy upgrade`: the default a policy started from, `merge.rs` the three-way merge), `terminal.rs` (terminal check; `terminal/ancestry.rs` whether an agent is among the parent processes, `terminal/own_binary.rs` whether the running executable is the one the lock in `MOAT_HOME` and in `~/.moat` records, started as `openmoat` or `moat`), `install/trust_note.rs` (a host's trust step after `init` writes its hook), `hangs.rs` (the guard-hangs side file and the phase a slow call reached), `heartbeat.rs` (a plugin's report that its host loaded it, `guard --heartbeat`, and whether the host has loaded it since it last changed, for `status`, `doctor` and the protection level, ADR-042), `render.rs`, `exit.rs` |
| `crates/openmoat-core/policies/default-v1.yaml` | shipped default policy |
| `tests/conformance/{attacks,benign,ask}.yaml` | executable security claims |
| `crates/openmoat-hosts/src/host/<module>/fixtures/*.json` | real host payloads |
| `tests/fixtures/sandbox/` | generated host sandbox settings and Seatbelt profile for the default policy |
| `crates/*/tests/` | end-to-end tests of the binary in one target, `crates/openmoat-cli/tests/e2e/` (one module per area: `cli`, `alias`, `guard`, `cursor`, `cursor_sandbox`, `copilot_cli`, `openclaw`, `pi`, `gemini_cli`, `opencode`, `hermes`, `config_change`, `lock`, `lock_settings`, `install_path`, `binary_path`, `approvals`, `allow`, `allow_files`, `anchor`, `edit`, `escapes`, `home_screen`, `human_only`, `listings`, `mcp`, `mcp_gateway`, `packs`, `permission_mode`, `protection`, `provenance`, `audit`, `export`, `team`, `paths`, `policy_upgrade`, `push`, `replay_report`, `moatbench`, `sandbox`, `sandbox_sync`, `sandbox_exec`, `run`, `run_guard`, `uninstall`, `canary`, `closed_pipe`, `codex`, `continue_cli`, `host_failures`, `proxy`, `repo_policy`, `secret`, `session_code`, `taint`, `taint_answered`, `trust`, and `differential/` for the same scenarios against every enforcement layer, with `differential/agents` running the pinned real Claude Code against a scripted fake API; `common` is the shared helper module), conformance runner, the README and USAGE verdict tables checked against the default policy (`openmoat-core/tests/doc_tables.rs`), architecture invariants |
| `docs/` | INSTALL, USAGE, DEMO, SANDBOX, POLICY, ARCHITECTURE, THREAT_MODEL, ROADMAP, ADDING_AN_AGENT, MOATBENCH, COVERAGE and EVIDENCE (generated), `adr/` |
| `scripts/ci/quality-gate.sh` | the one gate |
| `scripts/smoke-real-agents.sh` | a person's check of the protections with their own Claude Code, Codex, Gemini CLI, pi and GitHub Copilot CLI in a throwaway home (CONTRIBUTING "Testing with real agents") |
| `scripts/ci/latest-agents.sh`, `scripts/ci/latest-agents/` | the weekly check of each agent's latest release in a throwaway home; `agents.json` records each agent's install, the release its adapter was checked against and its golden shell payload; `README.md` says what each agent's run proves |
| `scripts/ci/clean-install.sh` | the published release installed with Homebrew, the shell installer and `cargo install`, then the README quick start, `init` and `uninstall` in a throwaway home |

## 11. Testing layers

| Layer | Where | Runs |
|---|---|---|
| Unit | next to the code (`#[cfg(test)]`, `tests.rs` modules) | every PR, all OS |
| Architecture invariants | `crates/openmoat-core/tests/architecture.rs` | every PR |
| Conformance (decide) | `tests/conformance/` through `crates/openmoat-core/tests/conformance.rs`; generates `docs/COVERAGE.md` and fails on a threat class without an attack fixture | every PR, all OS |
| Policy compiler | `crates/openmoat-core/tests/ir_consistency.rs` (IR against the engine on the conformance fixtures), `ir_never_widens.rs` (generated policies) | every PR, all OS |
| Golden host payloads | `crates/openmoat-hosts/src/host/<module>/fixtures` | every PR |
| End to end | `crates/openmoat-cli/tests/e2e/` (real binary, isolated `HOME`/`MOAT_HOME`) | every PR, all OS |
| Differential (ADR-019) | `crates/openmoat-cli/tests/e2e/differential/` runs `tests/differential/scenarios.yaml` (attacks, benign work, CVE replays) against every enforcement point: the hook decision, and each host sandbox whose binary is present. A layer that disagrees with a scenario's recorded verdict fails the suite; a missing host binary skips that layer visibly. `scripts/ci/differential.sh` points it at the host binaries for the full run. Its `scripts` list runs hostile project scripts as `npm test` under `openmoat run`, Claude Code's sandbox and `codex sandbox -P moat` and asserts the OS outcome; `docs/EVIDENCE.md` is generated from it (`OPENMOAT_TEST_UPDATE_EVIDENCE=1`) | every PR: hook layer and `openmoat run` (macOS, Linux) in the gate, where the host layers skip visibly; in the `standard tier` job, every scenario under the host sandboxes plus `sandbox_exec` on macOS and Linux, with Claude Code and Codex pinned by `scripts/ci/host-binaries.sh`, where a missing host binary fails the test (`MOAT_REQUIRE_HOST_BINARIES`) |
| Proxy | `crates/openmoat-proxy/tests/proxy/`: a real listener and a local upstream on loopback, names mapped by a test resolver, no external network | every PR, all OS |
| `wasm32` purity build | CI job | every PR |
| Fuzz | `fuzz/`, one minute per target on PRs, ten minutes weekly | CI |
| Guard latency | `scripts/ci/guard-latency.py`: one process per call, end to end and as recorded by guard; warns above the 15 ms p95 budget, fails above 45 ms. On the CI runners (#674, 2026-10-28) the median and p95 end to end are 12 / 14 ms on Linux (`ubuntu-latest`) and 25–28 / 33–40 ms on macOS (`macos-14`), of which the guard itself records 10 / 11 ms and 18–21 / 25–31 ms; macOS runs above the warning budget | every PR, `latency` job (not required) |
| Guard latency in long sessions | `scripts/ci/guard-session-latency.py`: one session grown to 100, 1,000 and 5,000 earlier calls, each a distinct file read, timed in three batches with the batches' median p95 reported beside the `latency_us` p95; warns above the 15 ms p95 budget at 5,000 and fails above 45 ms, so a return to folding the whole session fails the job. With the session cache (#570), CI runners measure p95 12 / 10 / 10 ms on Linux and 15 / 12 / 18 ms on macOS 14; before it, 18 / 40 / 158 ms and 41 / 110 / 370 ms, nearly all of it the session's taint worked out again from the audit log on every call (#559) | every PR, `latency` job (not required) |

| Latest agents | `scripts/ci/latest-agents.sh` per agent of `scripts/ci/latest-agents/agents.json`: the agent's latest release, `openmoat init`, `status` and `doctor`, the real agent loading the hook against a local fake model API where it runs without an account, and guard payloads in its format; a newer release than the adapter was checked against is reported, a failure opens one issue per agent | weekly and by hand, `latest agents` workflow (not required) |
| Clean install | `scripts/ci/clean-install.sh`: the published release from Homebrew, the shell installer and crates.io; the README quick start as written; `init` with no agent and with Claude Code; `uninstall` giving every file back byte for byte; the README's links and images | weekly, after each release and by hand, `clean install` workflow (not required) |

CI runs `scripts/ci/quality-gate.sh` on macOS (arm64, x64), Linux and Windows, plus
`cargo-deny`, the crate packaging check, `actionlint`/`zizmor` on workflows and CodeQL
(Actions, JavaScript, Python and Rust, pull requests from forks included).

## 12. Egress proxy

`openmoat proxy [--listen 127.0.0.1:<port>]` is the default-deny network exit from ADR-020.
Without `--listen` it binds `127.0.0.1` and the policy's `sandbox.proxy_port` when that
is set, the port the host sandboxes then send their commands' traffic to (§13; run it as
a user service), and `127.0.0.1:18080` otherwise. `openmoat run` serves the same proxy, brokered secrets included, from a thread
on an ephemeral loopback port and makes it the agent's only way out (§14). It is our own code on
`std::net` and `httparse` rather than `codex-network-proxy` or `sandbox-runtime` (#171):
the first is not on crates.io and would add over a hundred crates, the second would put
Node.js in the trusted base, and neither checks the ClientHello's SNI against the CONNECT
host outside TLS termination.

- **Start-up.** It refuses a non-loopback listen address, a missing installation and a
  drifted policy lock (exit 64). It compiles the policy once, so restart it after a policy
  change. It writes to the audit log under one session id per run (`proxy-<ms>`).
- **Sessions only** (ADR-027, ADR-044). Every request must carry a session credential,
  `Proxy-Authorization: Basic base64(<user>:<password>)` (the agent's proxy URL holds it as
  userinfo), and is recorded under that session (`openmoat-proxy/src/session.rs`).
  `openmoat run` holds its run's one credential. The standalone `openmoat proxy` checks
  credentials it never saw through the `Verify` trait the CLI implements
  (`proxy_session.rs`): Claude Code's `SessionStart` hook issues each session
  `v1.<host>.<expires>.<session>` with its HMAC-SHA-256 under `~/.moat/proxy.key`
  (`commands/guard/session_start.rs`, written to `CLAUDE_ENV_FILE`), and the proxy
  recomputes it. `sandbox.proxy_serve_without_credential` also serves a request that
  carries none, with no session; the stderr note at start-up says which applies.
- **Brokered secrets** (POLICY.md §2.1). `commands/proxy.rs` has `secrets/` read each
  source (a file, an env var, or a keychain item through the OS tool by absolute path)
  into a zeroed-on-drop buffer and hand it to `openmoat_proxy::Broker`. A source that cannot
  be read stops start-up. Only ids, hosts, headers and placeholders are printed.
- **Per connection,** in this order:
  1. Read the request head, at most 16 KiB within 10 s. Two forms are served:
     - `CONNECT host:port`
     - one absolute-form `http://` request

     In session mode, verify the credential next (constant-time comparison; two
     `Proxy-Authorization` headers are malformed). A missing, malformed or wrong one gets
     `407` with `Proxy-Authenticate: Basic realm="moat"` and a `proxy-session` row without
     a session; nothing else happens. Then take the session's share of the connections
     (below), or answer `503`.

     Refuse (`proxy-secret`) a request whose head, or body bytes read with it, carries a
     brokered secret's placeholder or value when the host is not that secret's own.
  2. Decide the host as a `fetch` atom through `CompiledPolicy` (POLICY.md §4). Only
     `allow` passes. An `ask` or a `defer` is refused, because the proxy cannot prompt.
     `metadata.google.internal` and `metadata.goog` are refused by name whatever the
     policy says. Then the port (`decide/ports.rs`): a host allowed by a pattern without
     a port passes on 443 and 80 only; `host:port` as a `fetch` atom, against a second
     policy compiled at start-up from the deny rules and the allow rules' `host:port`
     patterns, allows that port or refuses it; any other port is `proxy-port`.
     `openmoat run` decides with the user policy plus the project's repository deny rules
     (`repo::with_repo_denies`), never its ask or allow rules. In session mode, the session's taint applies next
     (`decide::tainted`, through `CompiledPolicy::with_taint`). After the session read
     secret material, a host other than that secret's own is refused (`session-taint`),
     because the proxy cannot ask. The taint is the fold of every agent session linked to
     the run (§14), read through the `TaintLookup` the CLI passes in
     (`taint/run.rs`); at the standalone proxy, the fold of the session itself, with the
     effective policy of the directory its credential was issued in (`taint/issued.rs`).
     A history that cannot be read refuses (`proxy-session`).
  3. Resolve the name with the system resolver (IP literals skip it), as a fully
     qualified name (`name.`) so no search domain is tried first; on Windows as written
     (`upstream::resolver_name`). Refuse the
     connection when any resolved address is loopback, link-local, a cloud metadata
     address (`100.100.100.200`, `fd00:ec2::254`; NAT64, IPv4-mapped, IPv4-translated,
     6to4 and Teredo forms included)
     or not unicast. Also refuse it when an address is private, CGNAT, benchmarking or
     unique-local and no allow rule names that address (POLICY.md §5.2). Those rules are
     compiled once at start-up into a second policy that holds only address patterns.
     Each resolved address is also matched against the policy's deny rules (in canonical
     text form, and a NAT64, IPv4-translated, 6to4 or Teredo address also as the IPv4 addresses it
     carries); a match refuses
     the connection (`proxy-address`, the deny rule's id in the reasons), while allow rules
     on addresses never open more here. Connect only to an address that was checked. A
     connection whose own end has the address it reached went to this machine (its LAN
     or public address, where services on every interface answer) and is closed before
     a byte is sent (`proxy-address`).
  4. For CONNECT:
     - answer `200`, then read the TLS `ClientHello` (up to 64 KiB, reassembled across
       records);
     - its SNI must equal the CONNECT host. For an IP-literal host there must be no SNI.
     - Anything else, including non-TLS bytes, closes the tunnel before one byte is
       forwarded.
  5. For plain HTTP:
     - rewrite to origin form;
     - the `Host` header must match the target;
     - drop hop-by-hop headers (`Connection` and the headers it names, `Proxy-*`, `TE`,
       `Trailer`, `Upgrade`, `Keep-Alive`) and add `Connection: close`;
     - refuse `Content-Length` with `Transfer-Encoding`, more than one `Content-Length`,
       one over 2^31 - 1, a framing header spelled with `_` (`Transfer_Encoding`), and a
       port with anything but digits;
     - refuse an HTTP/1.0 request that carries `Transfer-Encoding` (RFC 9112 §6.1);
     - forward one request: its head and its body, delimited by `Content-Length` or
       `chunked` framing (a request with neither has no body). Whatever the client sends
       after that body, such as a pipelined request for another host, is read and
       dropped, never forwarded. Chunked framing the proxy cannot follow, including a
       chunk size over 2^31 - 1, is refused (`proxy-request`); when the relay finds it
       after the head, the connection closes and a second row records why;
     - after the row is recorded, put the value of each brokered secret the host owns
       and that sets `plain_http` into the head of a request to its port (`port`, or 80;
       POLICY.md §2.1), except into a `TRACE`
       or `TRACK`, whose answer echoes the request. The head is zeroed once
       it is written. A secret without `plain_http` is not injected, and the row's reasons
       say so.
  6. Record one audit row: host `proxy`, the method as the tool, the action
     `net` `connect://host:port` or `http://host:port` (never the path), and the verdict
     and rules. If the row cannot be written, the connection is refused.
  7. Relay bytes both ways. A connection is closed after 120 s with no bytes in either
     direction. A plain-HTTP client stream keeps being checked for brokered secrets,
     across read boundaries. A chunk that completes one is not forwarded: the
     connection closes and a second row (`proxy-secret`) is recorded. In session mode
     the relay asks every second, between reads, whether the session's taint (looked up
     at most a second ago, once per session, `Sessions::taint_within`) still allows the
     host; when it no longer does, a `session-taint` row is recorded and the connection
     closes (`server/recheck.rs`, `tunnel::Recheck`).
- **Rule ids of its own:**
  - `proxy-address`: refused destination
  - `proxy-sni`: SNI missing or mismatched, or not TLS
  - `proxy-request`: unparseable or unsupported request
  - `proxy-upstream`: DNS or connect failure
  - `proxy-secret`: a brokered secret sent towards a host other than its own
  - `proxy-port`: an allowed host on a port no rule names
  - `proxy-capacity`: connections answered `503` at accept, before a head was read;
    one row at once, then one per 10 s with the count (`server/capacity.rs`)
  - `proxy-session`: in session mode, no valid credential, the session's share of the
    connections used up, or its history unreadable
  - `proxy-audit`: written to stderr only, since the audit log is what failed
- **Limits:**
  - 256 concurrent connections; the next is answered `503`.
  - At most half of them per session, and half for the connections that have not
    presented a credential yet, counted together (`slots.rs`, #555); with
    `sandbox.proxy_serve_without_credential`, half for the requests served without one,
    counted together too (ADR-044).
  - 10 s to connect upstream.
  - One thread per direction of each connection.
- **Not yet:** TLS termination for per-host method and path rules and for injecting
  secrets into HTTPS (opt-in, ADR-020), a session credential for Codex's traffic through
  the standalone `openmoat proxy` (Codex's upstream cannot carry one, ADR-044), and a
  policy reload without restart.

## 13. Standard tier: host sandboxes

ADR-018's default tier configures each host's own sandbox from the policy, through the
one IR of ADR-019 (`openmoat_core::ir`, `crates/openmoat-cli/src/sandbox/`).

```
policy.yaml ─► ir::lower (project = placeholder) ─► Enforcement ─┬─► claude::generate ─► settings.json "sandbox"
                                                                 ├─► codex::generate  ─► config.toml [permissions.moat]
                                                                 └─► cursor::generate ─► sandbox.json
```

- **One host-wide lowering.** Host settings are per user, not per session, so the IR
  is lowered once with a placeholder project. Each backend maps project patterns to
  the host's own workspace: Claude Code's working directories (implicit), Codex
  `:workspace_roots`, the workspace Cursor opened (implicit).
- **Reads.** `sandbox.read_roots` lowers to an `Allowance`, kept apart from the IR's
  read rules so the IR's own verdicts stay the hook's or stricter.
  `Checker::check_os` is the reference for OS layers: deny rules, then allowances,
  then the IR's rules. Claude Code gets `allowRead` plus
  `permissions.blockReadsOutsideWorkingDirectories`; Codex gets an explicit profile
  (`:minimal`, the roots, the workspace) that does not extend `:workspace`, which reads
  the whole disk; Cursor gets `readBoundary: "workspace"` and `additionalReadPaths`.
  Cursor's `sandbox.json` has no deny key, so a root with a denied path below it is
  left out (loss) and patterns denied inside the workspace stay open (allowance).
- **Writes** stay in the project, the temp directory and paths an allow rule names as
  a literal tree. Deny rules become `denyWrite` (Claude Code) or `deny`/`read` entries
  (Codex, which has no write-only glob).
- **Network** has two modes. Neither leaves a direct route out.
  - *Default (no `sandbox.proxy_port`): each host's own proxy.* The `net` rules'
    domain names become `allowedDomains` with `strictAllowlist` (Claude Code) and
    `network.domains` behind `features.network_proxy` (Codex). Hosts that are not
    domain names (`169.254.*`) stay unlisted, so they stay denied. Codex's profile also
    states `allow_local_binding = false` (its default), and `doctor` names it when on.
    Claude Code `httpProxyPort`/`socksProxyPort` set by hand are reported, because
    they replace the allowlist.
  - *Opt-in (`sandbox.proxy_port` set): through `openmoat proxy` (§12).* This adds
    OpenMoat's audit rows, brokered secrets and private-address checks. The cost is
    that the proxy must be running: a stopped proxy leaves commands without network,
    never with direct network. It stays opt-in until `openmoat init` can install the proxy
    as a user service (#272). `openmoat doctor` and `openmoat status` warn when nothing listens
    on the port. They check by trying to bind it, so the proxy records nothing.
  - *Claude Code, opt-in:* `httpProxyPort` and `socksProxyPort` both name the port, so
    Claude Code runs no proxy of its own and sandboxed commands have no other route out
    (verified on 2.1.292; the sandboxing docs, "Custom proxy configuration").
    - Its `allowedDomains`, `deniedDomains` and local-address check then no longer
      apply to that traffic. `openmoat proxy` decides by the same policy.
    - The lists are still written. They apply again if the ports are removed, which
      `doctor` reports. `strictAllowlist` in user settings keeps a repository's
      settings from changing the ports or adding domains.
    - Loss: SOCKS5-only programs (`ALL_PROXY`, ssh through it) have no network, since
      `openmoat proxy` speaks HTTP.
  - *Codex has no setting for an external proxy.*
    - `codex sandbox` always starts its own proxy on an ephemeral loopback port and
      enforces `network.domains` there. The profile allows commands no other connection
      (`curl --noproxy '*'` fails; codex-cli 0.160.1).
    - That proxy hands what it allows to an upstream only when the Codex process has
      `HTTP_PROXY`/`HTTPS_PROXY` and `allow_upstream_proxy` is on
      (`network-proxy/src/upstream.rs`). No `config.toml` key names the upstream.
    - Opt-in adds `allow_upstream_proxy = true`, which `doctor` names when it is
      turned off.
    - Starting Codex with both variables set to `http://127.0.0.1:<port>` is the
      user's step (allowance `codex.upstream`). It routes Codex's own API requests
      through `openmoat proxy` too.
- **Losses and allowances.** A backend narrows what it cannot express and reports it
  as a loss. It may widen only where the host cannot run otherwise (the read roots,
  Codex `:minimal` and `:tmpdir`, Claude Code's working directories and unblocked
  system paths, directory nodes left out of `denyWrite`, `.git` outside its
  code-execution paths so `git commit` works), and each of those is
  listed. `openmoat sandbox show` and `sandbox sync` print both; `doctor` counts them
  and prints them with `--verbose`.
- **Traps the generators handle** (found in the spike, re-verified on Claude Code
  2.1.290 and codex-cli 0.160.1): a relative pattern in Claude Code user settings
  resolves against `~/.claude`, so every pattern is absolute (`/**/.env`); a directory
  in `denyWrite` covers its subtree, so `**/.claude` (a directory-node rule) is left
  out and `.claude/worktrees/*` stays writable; Claude Code's `allowRead` of a `**/`
  exception re-opens it everywhere, so exceptions are dropped; Codex accepts globs
  only for `deny` and not under `:tmpdir`, and keeps `.git` read-only.
- **Writing and pinning.** `openmoat init` and `openmoat sandbox sync` merge the generated
  keys into the files, keeping every other key (JSON values; TOML through `toml_edit`,
  comments included), and back each file up first. `policy.lock` pins Claude Code's
  `settings.json` whole except the cosmetic `theme` key (§6) and Codex's `config.toml` by the canonical text of the part
  OpenMoat owns (`default_permissions`, `[permissions.moat]`, `features.network_proxy`),
  because Codex writes trusted projects into that file itself, and Cursor's
  `sandbox.json` whole. Drift is
  `kernel-integrity`. `doctor` also fails on a weakened or out-of-date setting,
  including a Claude Code proxy port that does not match `sandbox.proxy_port` (missing
  when it is set, present when it is not).
- **Asking and undoing.** Before writing anything, `openmoat init` lists the agents whose
  configuration directory exists and asks per agent at a terminal; `--hosts` and
  `--yes` skip the questions, and without a terminal no agent's files change.
  `openmoat uninstall` (`commands/uninstall.rs`, a person at a terminal; `kernel-self`
  denies it to agents) is the inverse: it removes exactly the hook entries
  (`hook_file::remove`) and sandbox keys (`claude::remove`, `codex::remove`,
  `cursor::remove`) init
  writes. When what is left equals a backup that holds none of OpenMoat's entries, it
  writes that backup's bytes back; when nothing is left and no such backup exists, init
  created the file and it is deleted; otherwise the user's later changes stay with the
  backups. The lock then drops those files (`integrity::unpin`) without re-pinning
  anything else.

## 14. Lightweight tier: `openmoat run`

ADR-018's tier for machines without a container or VM runtime puts the whole agent in
one sandbox generated from the policy. The code is in `crates/openmoat-cli/src/commands/run.rs`
(with `run/{macos,linux,unsupported}.rs`, chosen by `cfg` in one place) and
`crates/openmoat-cli/src/sandbox/{seatbelt,landlock,seccomp}.rs`.

```
policy.yaml ─► ir::lower (this project) ─► Enforcement + Grants ─┬─► seatbelt::generate ─► sandbox-exec -p <profile> <agent>
                                                                 └─► landlock::generate + seccomp ─► restricted thread ─► <agent>
openmoat run ─► openmoat proxy (thread, 127.0.0.1:<ephemeral>, session mode) ◄── HTTP(S)_PROXY (with credential) ── agent and its commands
         └► hook decisions (same port, MOAT-GUARD/1) ─► openmoat guard (outside) ◄── MOAT_GUARD_SOCKET + MOAT_GUARD_TOKEN ── openmoat guard (agent's hook, inside)
```

- **Start-up.** `openmoat run` refuses a missing installation and a drifted policy lock
  (§6), and a session without a project: the home directory, an ancestor of it or a
  filesystem root. It resolves the agent's executable through `PATH` and its symlinks,
  binds a loopback port, and generates the sandbox. It then prints what the user must
  know: the proxy address and audit session; that the agent's own sandbox must be
  off, because sandboxes do not nest (Seatbelt refuses a second profile); and every
  loss and allowance. Then it starts the agent. SIGINT is caught (`signal-hook`) so
  that Ctrl-C reaches the agent without taking down the proxy under it. The agent
  exiting non-zero makes `openmoat run` exit 1.
- **One lowering per session.** Unlike §13, the IR is lowered for the real project and
  home in both their spellings. `Grants` adds what the session needs: the proxy port, the
  temp directory, the agent's executable (a process cannot start from a file it cannot
  read) and `--write` paths (the agent's state). Each grant is an allowance, and deny
  rules still win over it.
- **Network.** Neither sandbox can name a host. The sandbox allows only the proxy's
  loopback port, and the proxy decides each host by the policy (§12) and refuses
  loopback destinations, so the open port reaches no other local service.
  `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` (both cases) point at it, and `NO_PROXY`
  is removed. A program that ignores them has no network; that is the one loss for the
  default policy.
- **Session credential** (ADR-027). `openmoat run` makes one credential per run: session
  `run-<ms>-<8 hex>` and a 256-bit token from `/dev/urandom`. The proxy variables hold
  `http://<session>:<token>@127.0.0.1:<port>`, and the proxy serves that session alone
  (§12), so a program that drops the URL's userinfo gets `407`. The session is the audit
  session of every proxy row and is printed in the banner. `MOAT_RUN_SESSION` names it
  for the agent, so `openmoat guard`, started by the agent, records one link row per agent
  session in the run's session (host `moat-run`, `taint/run.rs`). The proxy folds the
  linked sessions' taint from those rows. The port is ephemeral and the proxy private
  to the session, unlike the Standard tier's opt-in long-running `openmoat proxy` on
  `sandbox.proxy_port` (§13).
- **Hook decisions** (ADR-028, `crates/openmoat-cli/src/guard_relay/`). The agent's
  hooks run `openmoat guard` inside the sandbox, which can neither read nor write the
  OpenMoat state directory. `openmoat run` sets `MOAT_GUARD_SOCKET` (the proxy's address)
  and `MOAT_GUARD_TOKEN` (256 bits from `/dev/urandom`, made per run). A guard with
  both sends its raw payload, `--host`, working directory, a random nonce and the token
  over the proxy's port, behind the prefix `MOAT-GUARD/1\n`, which the proxy hands to
  the service (`openmoat_proxy::LocalService`) instead of reading HTTP. The service
  compares the token in constant time. A wrong one is recorded in the run's session
  (rule `run-guard-token`) and gets no answer. The right one starts `openmoat guard` outside
  the sandbox with the payload and `MOAT_RUN_SESSION`; that guard checks the lock,
  decides, and writes the audit and link rows as anywhere else. The inside guard prints
  the reply (standard output, standard error, exit 0 or 2) only when it repeats the
  nonce; a missing variable, a non-loopback address, a failed connection, the guard's
  10 s budget, a payload over 1 MiB or a malformed reply each deny (`kernel-error`).
  The sandbox profiles are unchanged: no Unix socket and no second port.
- **Seatbelt (macOS).** `(deny default)`, then:
  - process basics (exec, fork, signals and process info in the same sandbox,
    pseudo-terminals, POSIX shm, the two directory-service lookups
    `opendirectoryd.libinfo` and `.membership`). Not the keychain, not DNS, not `trustd`.
  - `file-read-metadata` everywhere.
  - `/`, the devices and `/private/var/select`; of the terminals only `/dev/tty` and
    the ones `openmoat run`'s standard streams are on (`seatbelt.terminal`, found by
    device number in `/dev` by `run/macos.rs`), never the person's other `/dev/ttys*`.
  - the IR's allow rules and the grants. The write allow rules keep their
    exclusions of an agent's own configuration in the project (`AGENT_CONFIG` in
    `sandbox/patterns.rs`: `.claude/hooks/`, `.mcp.json`, …), and a deny of the same
    comes after every grant (`seatbelt.agent-config`, a loss), together with the
    folders directly in the project that hold them (`.github`, `.pi`, `.openclaw`, `.opencode`),
    which cannot be created, renamed or removed; the other `runs-later`
    exclusions (CI, commit-hook managers) are dropped, since installs write them
    (`seatbelt.runs-later`).
  - last, the IR's deny rules, because Seatbelt applies the last match. Their `!`
    exceptions become `require-all`/`require-not`, so a deny with exceptions is exact.
    A read deny covers `file-read-data` and `file-read-xattr` and leaves `stat`
    working.
  - a fixed deny of `com.apple.SecurityServer` and `securityd`.

  Globs become `subpath`/`literal` where they name one place, else anchored regexes
  with the engine's semantics. Seatbelt compares the resolved, on-disk spelling, so
  `/tmp` patterns name `/private/tmp`. A path that does not exist yet has the spelling
  it is created with, so on a case-insensitive disk a deny rule's patterns are written
  as regexes in which each letter matches either case (`sandbox/seatbelt/filter.rs`):
  creating `.MCP.json` or `.Claude` is denied like `.mcp.json` and `.claude`. Allow
  rules and every `!` exception stay as written, which can only narrow them. The golden
  for the default policy, on a case-insensitive disk, is
  `tests/fixtures/sandbox/seatbelt-default.sb`. Found on macOS 26: the dynamic
  loader needs to read `/`, a process cannot start from a file it cannot read, and
  `getconf DARWIN_USER_TEMP_DIR` needs the two directory-service lookups.
- **Landlock (Linux 6.7+).** Read+execute below the IR's literal allow trees, the read
  roots, the devices and the agent's executable; of the terminals only `/dev/tty` and
  the ones the standard streams are on (`/proc/self/fd`, `landlock.terminal`), not
  `/dev/pts`. Full access below the project's write
  trees, the temp directory and `--write` paths. `ConnectTcp` to the proxy's port
  only. File access and TCP are hard requirements at ABI 4; abstract-socket and signal
  scoping (ABI 6) are added where the kernel has them. The rules are applied to a
  thread that then starts the agent: Landlock restricts the calling thread and its
  children, so the proxy thread keeps its audit log and network. Landlock only grants.
  A deny rule or `!` exception inside a granted tree and the proxy's port on other
  hosts stay open. Each is listed as an allowance (`landlock.inside-grants`,
  `landlock.tcp-port`). A grant inside a denied path is not made, and a glob cannot be
  granted (losses). Without a network namespace, whose mounts could cover them, a
  `--write` path holding an absolute `kernel-self` path or lying inside a tree one
  denies (`~/.codex/sessions`), and every `--write` path outside the project, which can
  hold a `**/` one (another repository's `.claude/settings.json`), refuses the run
  (`sandbox::kernel_self_in_writes`, `exposure::kernel_self_refusal`).
- **seccomp (Linux).** Landlock does not restrict UDP, raw or Unix sockets, so the same
  thread applies a seccomp filter after the Landlock rules (`seccompiler`, built in
  `run/linux.rs` from `sandbox/seccomp.rs`). `socket()` is allowed only for an IPv4 or
  IPv6 stream with protocol 0 or TCP (with or without `SOCK_NONBLOCK`/`SOCK_CLOEXEC`);
  every other `socket()` fails with `EPERM`: Unix (the user's D-Bus session bus, nscd,
  systemd-resolved), netlink, packet, raw, UDP, SCTP and MPTCP. `socketpair()` stays
  allowed: its sockets are connected only to each other, and Node uses them for its
  children's pipes. `io_uring_setup`, `io_uring_enter` and `io_uring_register` fail too,
  because a ring creates sockets (`IORING_OP_SOCKET`) without a `socket()` call the
  filter sees; so do `ptrace` and `process_vm_readv`/`writev`, so that a command cannot
  read or change the agent's memory (its tokens), and debuggers do not work. So do
  `keyctl`, `add_key` and `request_key` (the person's kernel keyrings), `unshare` with
  any namespace flag and `clone` with one of them (a new user namespace would give a
  command every capability inside it), and `setns` (joining a namespace that exists
  already). `clone3` passes its flags in memory, which a
  filter cannot read: a second filter answers it `ENOSYS`, so glibc falls back to
  `clone`. `sendto`, `sendmsg` and `sendmmsg` with `MSG_FASTOPEN` fail too: TCP Fast Open
  connects an unconnected socket inside the send, without the `connect()` whose LSM
  hook Landlock's port rule checks. x32 calls of the same are refused, and a call under another architecture (32-bit `int 0x80`,
  which has `socketcall`) kills the process. Name resolution needs a Unix socket or UDP,
  so only the proxy resolves names, as on macOS: a tool that ignores `HTTP(S)_PROXY`
  cannot resolve them. Programs that list network interfaces (`getifaddrs`, netlink)
  get an error.
- **Network namespace (Linux, without `--isolate`).** Landlock restricts TCP by port
  only and seccomp cannot read `connect()`'s address, so `run/linux/netns.rs` probes the
  system's `bwrap` and, where it can create the namespaces, starts the agent under
  `/bin/sh -c "trap '' INT; exec …" bwrap --unshare-user --unshare-net
  --die-with-parent --dev-bind / /` (the shell keeps Ctrl-C from ending bubblewrap's
  monitor), running `openmoat isolated` as under `--isolate`: the proxy's port is relayed
  into a namespace with only loopback, and the same Landlock rules and seccomp filter
  apply inside; the Landlock rules are also built outside first, so a kernel without
  ABI 4 is refused before anything starts. `landlock.tcp-port` is dropped from the
  report there. Where `bwrap` is missing or the probe fails, the agent starts as before
  and `openmoat run` prints that the network is restricted by port only; `openmoat doctor`
  warns. In the namespace, `bwrap::project_masks` binds read-only the agent
  configuration (`patterns::AGENT_CONFIG`) and the files `**/` write denies name below a
  folder (`.claude/settings.json`, `.copilot/hooks`) that exist directly in the project,
  and binds onto itself each folder holding them (`.github`, `.pi`, `.claude`), so it
  cannot be renamed away and back.
- **`--isolate` (Isolated tier, Linux).** `run/linux/isolate.rs` starts the agent under
  `bwrap --unshare-all --unshare-user --die-with-parent` with the mounts
  `sandbox/bwrap.rs` generates from the same Landlock rules: each read path read-only,
  each write path read-write, the temp directory as `tmpfs`, then the masks. The project
  is walked (symlinks not followed) and each entry checked with `Checker::check_os`: a
  denied read is covered by a mode-`000` placeholder, a denied write bound read-only, a
  directory whose node alone is denied bound onto itself so it cannot be renamed, as is
  each folder directly in the project that holds agent configuration (`.github`, `.pi`,
  `.openclaw`, `.opencode`). The

  literal paths deny rules name elsewhere are masked the same way, under every spelling
  of the project. Inside, `openmoat isolated` (hidden) binds the proxy's port on the
  namespace's loopback, relays each connection to a Unix socket bound in from a private
  `0700` directory (`openmoat run` relays it on to the proxy), then applies the Landlock
  rules and seccomp filter to the thread that starts the agent. Missing or unusable
  `bwrap` (a probe runs first) refuses with exit 64; macOS refuses (#175).
- **Windows** refuses with exit 64; the Standard tier is the answer there.
- `openmoat sandbox show` prints both lightweight outputs for the current directory, before
  the session's grants are added. The executing tests in `tests/e2e/run.rs` run
  `/bin/sh` payloads under the real sandbox on macOS and Linux; on Linux they show Unix
  and UDP sockets and `io_uring` failing with `EPERM` while TCP to the proxy works, and
  `run/linux.rs` applies the filter to a test thread. `tests/e2e/run_guard.rs` runs a
  hook inside `openmoat run` and checks its decision, audit row, link row and the egress
  taint that follows, and that a wrong token or a forged reply denies.
