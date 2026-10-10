# Architecture

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
| `openmoat-core` | Policy model and lint, POSIX lexer (`lexer/`), shell classifier (`shell/`), URL host parser (`host.rs`), patterns, path normalisation, the engine, the policy compiler (`ir/`), the repository policy merge (`repo.rs`), `ProgramResolver` and `PathResolver` traits | Pure: no I/O, no `unsafe`, depends only on `serde`, `serde_yaml_ng`, `globset`, `thiserror`. Builds for `wasm32-unknown-unknown` in CI; `tests/architecture.rs` enforces the dependency allowlist and the 500-line file budget |
| `openmoat-hosts` | Host adapters: `pre_tool_use.rs` (Claude Code and Codex `PreToolUse`), `config_change.rs` (Claude Code `ConfigChange`), `cursor.rs`, `mcp.rs` (MCP arguments to paths and URLs), `patch.rs` (Codex `apply_patch` file list) | Translate payload to `Action` and `Decision` to response. Never decide |
| `openmoat-audit` | SQLite store, time-window and session queries, redaction | Redact before persisting. Typed `thiserror` errors |
| `openmoat-proxy` | The egress proxy behind `moat proxy` (§12): request and `ClientHello` parsers, host decisions through openmoat-core, the address guard, connection relay, the `Recorder` trait the CLI implements over `openmoat-audit` | Network I/O only through `std::net`; no async runtime; no storage. Depends on `openmoat-core`, `httparse`, `thiserror` |
| `openmoat` (`crates/openmoat-cli`) | The `moat` binary: commands, hook installation, the policy lock, approvals, the repository policy file, the environment snapshot, the filesystem resolvers, the sandbox backends generated from the IR (§13, §14), rendering, exit codes | The only crate that touches files, the environment and the terminal; the only one that starts processes |

No crate depends on `openmoat`.

## 2. One tool call, end to end

```
host payload (stdin)
  └─► adapter (openmoat-hosts)             Action, or none for an ungoverned tool
        └─► policy lock check              drift ⇒ deny [kernel-integrity]
              └─► load policy + overlay    ~/.moat/policy.yaml + policy.d/approved.yaml
                    + repository policy    <project>/.moat/policy.yaml, tightening only
                    └─► classify (openmoat-core)  Action ⇒ atomic actions
                          └─► engine            per atom: deny → allow → ask → defaults
                                └─► combine     strictest wins ⇒ Decision
                                      └─► session grant   ask on a granted shell command ⇒ allow
                                            └─► session taint     earlier calls in the audit log ⇒ allow may become ask
                                                  └─► audit record      failure ⇒ deny [kernel-error]
                                                        └─► hook response (stdout) + exit code
```

`moat guard --host <id>` (`commands/guard.rs`) runs this once per tool call and
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
4. **Lock.** `integrity::violation` recomputes every digest in `policy.lock`. Any drift
   denies the call with `kernel-integrity` before the policy is read. Otherwise a tool
   the adapter does not govern (no action) is allowed with rule `ungoverned` and
   recorded.
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
8. **Grant.** An `ask` for a shell command whose exact text was granted for this host
   session with `moat allow` becomes `allow` with rule `approved-session`. A grant
   never touches a `deny` and expires 24 h after it was given; expired grants are
   ignored and pruned.
9. **Taint.** `taint::of_session` (`taint.rs`) reads this host session's earlier events
   from the audit log. It folds `CompiledPolicy::exposure` over the calls that may have
   run: allowed calls, and asks on a host that can ask. Each call is resolved from its
   own recorded working directory. `CompiledPolicy::with_taint` then tightens the
   decision (POLICY.md §4.1). This runs after the grant, so a grant cannot lift a taint
   ask. A log or session event that cannot be read is a `kernel-error` deny. An edited
   or deleted event is found by the hash chain (`moat doctor`), not on every call.
10. **Record.** The event is appended to the audit log's hash chain (§7). If it cannot
   be written, the decision becomes a `kernel-error` deny: an unrecorded call is not
   allowed.
11. **Respond.** The adapter renders the host's response document. `deny` also prints
    the reason line on stderr and exits 2.

A panic inside steps 1–10 is caught and answered with a deny and exit 2, because
Claude Code treats exit 101 as a non-blocking error. A `guard` with no answer after
10 s (`GUARD_BUDGET_S`, below every hook timeout `moat init` sets) writes a deny,
unrecorded, and exits 2, since a host that times the hook out runs the call
(THREAT_MODEL §5, "When the hook fails"). Only one response is ever written.

## 3. Classification

`openmoat-core` turns an `Action` into atomic actions (`AtomicAction`): `Shell`,
`Pipeline`, `FsRead`, `FsWrite`, `Net`, `Fetch`, `EnvRead`, `EnvSet`, `McpTool`.

- **Shell** (ADR-005). The lexer (`lexer/`) reads words, quotes, escapes, operators,
  redirections, `$( … )`, backticks, here-documents and here-strings, up to 64 KB, and
  makes the words bash makes of unquoted braces (`lexer/brace.rs`). The
  classifier (`shell/`) emits one `Shell` atom per simple command and one `Pipeline`
  atom per pipeline suffix. It recurses into `sh -c`, `eval`, substitutions and
  wrappers (`sudo`, `env`, `xargs`, `timeout`, …) to depth 4. It adds `fs.read`/`fs.write`
  atoms for redirections and file operands (`operands.rs`), relative paths resolved
  through `cd`/`pushd` (`cwd.rs`), `net` atoms for URLs and hosts, and `env.*` atoms
  for assignments and `$VAR` reads. Shell options are read per shell
  (`invocation.rs`), git's global options are unwrapped (`git.rs`), `make` arguments
  that run code (`make.rs`), options that run programs (`options.rs`) and decoder
  pipelines (`decoders.rs`) are surfaced. Inline interpreter code (`python -c`,
  `node -e`) is scanned for paths, hosts and variable names, not parsed. Output is
  capped at 2048 atoms.
- **ForeignShell** (Claude Code `PowerShell`). Always `ask` with rule `unparseable`;
  there is no PowerShell parser.
- **ReadFiles** (Claude Code `SendFile`, absolute Glob patterns). One `fs.read` per
  path; an empty list asks.
- **Patch** (Codex `apply_patch`, a write-shaped Cursor tool naming several paths). One
  `fs.write` per added, updated, deleted or moved-to file; a patch naming no file asks.
  A header line is matched trimmed and in any case, as Codex reads it, wherever it is.
- **McpTool.** An `mcp` atom for the tool name, plus `fs.*` and `net` atoms for path-
  and URL-shaped arguments found down to 8 levels of nesting (`openmoat-hosts/src/mcp.rs`).
  When deeper nesting stops the search, the adapter names the limit in `unchecked`, and
  the engine adds an `unparseable` ask to the decision.
- **Fetch** (Claude Code `WebFetch`). A `fetch` atom for the URL's host (ADR-017).

Anything the lexer or classifier cannot make sense of is `unparseable`, which the
engine turns into `ask`, never `allow`. `ParseOutcome::Unparseable` carries the atoms
classified around the part that failed (other simple commands, other MCP arguments), and
the engine merges its `ask` with their decisions, so the failing part cannot hide a deny.

### Host tool mapping

| Host tool | Field read | Action |
|---|---|---|
| Claude Code, Codex `Bash`; Cursor `beforeShellExecution` | `command` | `Shell` |
| Claude Code `Monitor` | `command`, or `ws.url` (exactly one) | `Shell`, or `Net` |
| Claude Code `PowerShell` | `command` | `ForeignShell` |
| Claude Code `Read`; Cursor `beforeReadFile`, `preToolUse` `Read` | `file_path` | `FsRead` |
| Claude Code `LSP` | `filePath` | `FsRead` |
| Claude Code `Glob`, `Grep` | `path`, else the working directory; an absolute or `~` Glob `pattern` also reads its directory part (Claude Code searches that instead of `path`) | `FsRead`, `ReadFiles` |
| Cursor `preToolUse` `Grep`, `Glob` | every path in `path`, `file_path`, `target_file`, `target_directory`, `target_directories`, else the working directory | `FsRead`, `ReadFiles` |
| Cursor `preToolUse`, any other write-shaped tool (name contains `write`, `edit`, `create`, `move`, `rename`, `delete`, `remove`, `append`, `mkdir`, `copy`, `save`, `patch` or `update`) that names a path under those keys | every such path | `FsWrite`, `Patch` |
| Cursor `preToolUse`, any other tool that names a path under those keys | every such path | `FsRead`, `ReadFiles` |
| Claude Code `SendFile` | every path in `files` (the contents go to another session; an empty or non-string list is an adapter error, so `deny`) | `ReadFiles` |
| Claude Code `Edit`, `Write`, `MultiEdit`; `NotebookEdit` | `file_path`; `notebook_path` | `FsWrite` |
| Cursor `preToolUse` `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete` | `file_path` | `FsWrite` |
| Claude Code `WebFetch` | `url` | `Fetch` |
| Codex `apply_patch` | `command` (the patch envelope) | `Patch` |
| `mcp__<server>__<tool>` (Claude Code, Codex); Cursor `beforeMCPExecution` | tool name and arguments (Cursor: `mcp_server_name`, `tool_name`, `tool_input`) | `McpTool` |
| anything else (Claude Code `Task`, Codex `update_plan`, Cursor `preToolUse` `Shell`, `Task`, `MCP:<tool>`, and tools that name no path) | — | none: `ungoverned` |

Claude Code calls only reach OpenMoat for tools in the installed matcher
(`crates/openmoat-cli/src/install.rs`); a tool outside it is never seen.
Cursor's hook matcher is empty, so every tool reaches `preToolUse`. Cursor's hook
documentation names `Grep` but not `Glob` and gives no file tool's arguments. A
third-party capture shows `Grep` and `Read` send `file_path`; the rest is unverified
(`tests/fixtures/hosts/cursor/README.md`, #138).

## 4. Decision

For each atomic action, the lists are tried in order `deny → allow → ask`; the first
list with a match decides that atom. A repository policy's ask groups (`repo_ask`) are
tried between `deny` and `allow`. If none matches, `defaults` decides (rule id
`default.<kind>` or `default`). The verdict for the tool call is the strictest across
its atoms: `deny > ask > allow`. Deny is absolute (ADR-002). A `fetch` atom also
matches `net` patterns and falls back to the `net` default (ADR-017). The decision
carries the rule ids that produced the final verdict and weaker matches as context.

### Resolvers

The engine needs two facts that live on the filesystem. `openmoat-core` defines a trait
for each and the CLI implements it:

| Trait | ADR | Implementation | What it adds |
|---|---|---|---|
| `ProgramResolver` | ADR-008 | `environment.rs` (`Snapshot`) | The first word of each command is resolved through the search path recorded at `moat init` (`environment.json`), not the hook's inherited `PATH`. A pinned program (policy `executables:` or the snapshot) that now resolves elsewhere is a deny with rule `executables` |
| `PathResolver` | ADR-009 | `realpath.rs` (`FsPathResolver`) | Every `fs.read`/`fs.write` path is also checked at its symlink-resolved location; both are evaluated and the strictest wins. New files resolve through their deepest existing ancestor. `read_dir` lists the directories an unquoted glob operand searches, so every path it names is checked too (`expand.rs`, POLICY.md §4) |

Patterns naming `${project}` or `~` are compiled for both the written and the resolved
spelling of the root, so a project under macOS `/tmp` → `/private/tmp` matches either
way. `moat policy check` uses the same resolvers (the snapshot only when an
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
| `decide_only` | rule ids per kind the IR cannot carry: `shell`, `env.read`, `env.set`, `mcp`, and `executables` program names |
| `losses` | every place the IR is stricter than the hook, with a message |
| `allowances` | where OS layers may be wider than the hook: `sandbox.read_roots` (ADR-021). Kept out of `fs.read`, so the IR's own verdicts never widen; `Checker::check_os` applies them after the deny rules |

Per access the IR applies deny rules, then allow rules, then the default.
`ir::Checker` is that reference evaluation.

**Lowering never widens.** An `ask` default lowers to deny. An `ask` rule disappears
under a deny default, where the outcome is the same. Under an allow default it becomes a
deny rule, which also denies where an allow matches. Each case is a loss.

Two tests prove agreement with the engine:
- `tests/ir_consistency.rs` checks every fs, net, fetch and patch conformance fixture.
  The IR verdict on the engine's own atoms (`CompiledPolicy::atoms`, symlinks included)
  must equal the engine verdict, with `ask` read as deny.
- `tests/ir_never_widens.rs` lowers generated policies and checks that an IR allow is
  always an engine allow.

`moat policy compile` prints the IR.

## 5. Hook responses and exit codes

| Host event | Response | Exit |
|---|---|---|
| Claude Code, Codex, Continue CLI `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":…,"permissionDecisionReason":…}}` | 0, or 2 on deny |
| Cursor `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` | `{"permission":…,"user_message":…,"agent_message":…}` | 0, or 2 on deny |
| Claude Code `ConfigChange` | `{}` or `{"decision":"block","reason":…}` | 0, or 2 on block |

`ask` is the host's own prompt; OpenMoat has no prompt of its own. Codex cannot ask:
its `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and then runs the
call. So for Codex an `ask` is sent as a `deny` (exit 2) whose reason says to approve
it with `moat` or `moat allow --last`. Cursor's `preToolUse` and `beforeReadFile` get the
same treatment. The audit log keeps the `ask`, which is what `--last` finds
(`Host::answer`); it approves a shell command or the exact files of a file action.

The Continue CLI (`cn`) cannot ask either, and it runs the Claude Code hook: it merges
hooks from `~/.claude/settings.json` and `.claude/settings.json` with its own files.
Its runner (`extensions/cli/src/hooks/hookRunner.ts` in continuedev/continue) blocks
only on exit 2, `decision: "block"` or `permissionDecision: "deny"`, so an `ask` would
run the call. `guard --host claude-code` treats a call as host `continue` when
`CONTINUE_PROJECT_DIR` is set (`cn` sets it for every command hook; Claude Code never
does) or when the payload's `transcript_path` is empty (`cn` keeps no transcript file;
Claude Code always sends a path). Either sign is enough, because a Claude Code call
mistaken for `cn` only turns an ask into a deny. For `continue` an `ask` is sent as a
`deny` with the same `moat allow --last` instruction as for Codex, and the audit log
records host `continue` with the `ask`. Everything else is decided as for Claude Code
(`Host::sender`, `tests/fixtures/hosts/continue/`, built from `cn`'s hook source).
`continue` is not in `Host::ALL`: it has no hook file of its own to install.

Cursor prompts on `ask` for `beforeShellExecution` and `beforeMCPExecution` only
(<https://cursor.com/docs/hooks>: `ask` is an output of both, and its shell example asks
for permission with it). For `preToolUse` the same page says `ask` is "accepted by the
schema but not enforced", so the call runs, and `beforeReadFile` takes only allow or
deny. The Cursor adapter marks those two events `HookEvent::PreToolUseNoAsk`, and an
`ask` there is sent as a `deny` (exit 2) whose reason says to approve it with `moat` or
`moat allow --last`, which approve the exact file. The audit log keeps the `ask`.

Codex's `PermissionRequest` hook does not change this (#178, checked against
openai/codex `ff9ab4a` and codex-cli 0.160.1). Codex runs it only from
`Session::request_approval` (`core/src/tools/approvals.rs`), after its own approval
policy and sandbox have decided to prompt. The hook can answer allow, deny or nothing;
nothing shows Codex's prompt. No hook can send a call into that path, so a `PreToolUse`
`ask` that let the call through would run unprompted whenever Codex itself does not
prompt. `moat init` therefore does not install `PermissionRequest`. `guard` refuses that
event as a wrong event (deny, exit 2, reason on stderr), which Codex reads as a deny
(`tests/fixtures/hosts/codex/permission-request-shell.json`, built from Codex's
`permission-request.command.input.schema.json`). Exit codes follow
ADR-004 and ADR-015: 0 allow or ask, 2 deny, 3 unresolved ask from `moat policy
check`, 64 usage or configuration error. `moat run` exits 1 when the agent it started
exits non-zero; never 2 or 3. `guard` never exits 64: an argument it cannot
parse is a deny with exit 2, because Claude Code and Codex proceed on any other
non-zero exit. Cursor is fail-open unless a hook sets `failClosed: true`, so
`moat init` sets it on every Cursor hook.

## 6. Self-protection

- **Policy lock** (ADR-006). `~/.moat/policy.lock` pins SHA-256 digests of the policy,
  `environment.json`, `approvals.json`, `policy.d/approved.yaml`, `trust.json` and every
  hook file OpenMoat installed, keyed by location so a swap for a symlink is a
  modification. Claude Code's `settings.json` is pinned by the canonical JSON without
  its top-level `theme` key, which Claude Code writes itself on first run (#287); a
  file that does not parse is drift, and a whole-file digest from an older lock still
  verifies until the next re-pin. The lock also pins the part of Codex's `config.toml` that holds OpenMoat's sandbox profile
  (§13). It is verified on every `guard` call. For each pinned JSON or TOML file the
  lock also records a digest per top-level key, so drift (in `guard` reasons, `doctor`,
  and `doctor --accept` before it re-pins) names the keys that were changed, added or
  removed: `settings.json was modified: changed hooks; added theme`. A lock written
  before that, or a file that no longer parses, gives the plain `was modified`. Only a person re-pins: `moat init`, or
  `moat doctor --accept`, `moat allow`, `moat edit`, `moat trust` and `moat sandbox sync` from an
  interactive terminal.
- **ConfigChange veto.** Claude Code reports settings changes; while any pinned file
  no longer matches the lock, every change is blocked for the session. Codex and Cursor have no such
  event, so there the next tool call is denied instead. A `/settings-review` accept
  writes the new contents to `<file>.proposed-<8 hex>`, fires `ConfigChange` for that
  copy and renames it over the file only if no hook blocks; when `<file>` is pinned,
  the copy is blocked unless the file still matches the lock and the copy's bytes equal
  the pinned ones, so a reviewed edit of a pinned file cannot pass the hook.
- **`kernel-self` rules.** The default policy denies agent writes to the state and
  host directories (also where `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or
  `CURSOR_CONFIG_DIR` moved them, and where `moat init` recorded them in `hosts.json`), hook
  files and any `bin/moat`, and denies `moat
  allow|doctor|edit|init|policy|trust|uninstall` and `moat sandbox sync` from an agent, including under pseudo-terminal
  wrappers (ADR-011, ADR-014).
- **Terminal check.** `moat allow`, `moat edit`, `moat trust`, `moat uninstall` and `moat doctor --accept` refuse to
  run without a terminal (`terminal.rs`). The debug-only `MOAT_ASSUME_TTY` override exists for tests.
- **Stable hook path** (ADR-016). Hooks run the package manager's stable link to
  `moat`, not a versioned file an upgrade deletes; `doctor` and `status` name a hook
  whose binary is missing or is a different `moat`.

## 7. Audit log

`~/.moat/audit.db` is SQLite in WAL mode, created with mode 0600, with one `events`
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
   proxy masks every value it holds. `moat guard` masks, in every call the policy
   decides, the values it can read, those with a `file` or `env` source; it does not
   start the keychain tool per call, and it skips a source it cannot read. Rows of an
   ungoverned tool, a settings change or a call refused for lock drift are written
   before or without loading the policy and get the patterns only.
2. **Patterns.** Bearer and basic auth, `key=value` credentials, common token shapes,
   URL passwords.

The policy has no other declaration of secret environment variables: `env-secrets` is
a list of names the agent may not read (it includes `AWS_REGION`-style names), not of
values to mask. `show`, `replay` and `report` read the log; nothing leaves the machine
unless a person runs `moat audit export`.

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
transaction adds about 0.1 ms to a guard call. `moat doctor` re-hashes the whole log
oldest first (about 0.15 s per 100 000 events) and reports the first event that was
edited (contents do not match its hash), unlinked (an event before it was deleted or
inserted, or events were reordered) or unhashed, and exits 64.

**Export** (`moat audit export`, `crates/openmoat-audit/src/store/export.rs`). JSON Lines,
oldest first, one object per chained event with the filters `--since`, `--host` and
`--session`. Every line has `"format": "moat-audit-export-v1"` and the fields `id`
(hex), `ts_ms`, `host`, `session_id`, `call_id`, `cwd`, `tool`, `action`, `verdict`,
`rules`, `reasons`, `latency_us`, `prev_hash` and `hash`. `action`, `rules` and
`reasons` are the stored JSON text embedded byte for byte, not re-serialised, so the
line holds exactly the cells the chain hashed; a field outside this list makes the
line invalid. Cells are already redacted in the store and are not touched again, so
an export holds no more than the database. Events from before the chain have no hash
and are left out. A new line format gets a new `format` value.

**Verify** (`moat audit verify`, `store/export_verify.rs`). It works without the
database. Every line must hash to its `hash`, ids must rise, and a line whose id
follows the previous line's id must carry that line's hash as `prev_hash`. A jump in
ids is a gap, which is counted and not failed: a filtered export has gaps, and so
does deleting events. The first failing line is named and the command exits 64. The
head is the last line's `hash`. `moat doctor` prints the database head. With
`--anchor <hash>`, verify also fails unless a verified line carries that hash.

**Team report** (`moat audit report <file>…`, `crates/openmoat-cli/src/commands/team.rs`).
It verifies every file first and refuses (exit 64) if one fails. Events with the
same `hash` are counted once, so overlapping exports do not double-count. The report
starts with the `moat report` summary (`Summary::of`), then shows each file's head,
verdicts per host, asks and denies per rule, and the most frequent asked and denied
actions. False-positive candidates are actions that asked and were also allowed by
an `approved-…` rule (`moat allow`), which suggests the asking rule is too broad.
`--format json` gives the same data.

The upgrade from schema 1 adds the two columns and records the last existing id as
`legacy_last_id` in a `meta` table. Existing events are not hashed: they were written
unprotected, and hashing them during the migration would vouch for whatever they hold
at that moment. `doctor` counts them as not covered; an event without a hash after
`legacy_last_id` is a break. What the chain does not detect is in [THREAT_MODEL.md](THREAT_MODEL.md) §5.

## 8. Files on disk

```
~/.moat/                       ($MOAT_HOME overrides; directory 0700, files 0600)
  policy.yaml                  user policy (moat init writes the default once)
  policy.yaml.bak              the policy before the last `moat edit` applied a change
  policy.d/approved.yaml       permanent rules from `moat allow --always/--site/--dir`
  approvals.json               session grants from `moat allow` (24 h each)
  trust.json                   repository policies trusted with `moat trust`: root → SHA-256
  environment.json             search path and program locations recorded at init
  policy.lock                  digests of the files above and of installed hook files
  audit.db                     audit log
~/.claude/settings.json        Claude Code hooks and sandbox block ($CLAUDE_CONFIG_DIR overrides)
~/.codex/hooks.json            Codex hooks ($CODEX_HOME overrides)
~/.codex/config.toml           Codex [permissions.moat] profile, default_permissions
<file>.moat-backup             each hook file before OpenMoat's first hook edit
<file>.moat-sandbox-backup     each host file before OpenMoat's first sandbox edit
~/.cursor/hooks.json           Cursor hooks ($CURSOR_CONFIG_DIR overrides)
~/.cursor/sandbox.json         Cursor sandbox keys, next to hooks.json
<project>/.moat/policy.yaml    repository policy, committed by the team (ADR-022)
```

Host sandboxes and `moat proxy` are generated from the user policy only. Repository
rules apply in the hook.

## 9. Invariants

The full list, with the tests that hold each one, is AGENTS.md §3. In short: deny is
absolute; strictest wins; unparseable is `ask`; every error path in `guard` is a deny
with exit 2; exit codes 2 and 3 mean nothing else; nothing persisted skips
redaction; the core stays pure; `moat init` never overwrites a policy or duplicates a
hook; the lock is checked before any decision.

## 10. Repository layout

```
crates/openmoat-core/          decision core; policies/default-v1.yaml is the shipped policy
crates/openmoat-hosts/         host adapters
crates/openmoat-audit/         audit store
crates/openmoat-proxy/         egress proxy; tests/proxy/ runs it on loopback
crates/openmoat-cli/           the moat binary; tests/e2e/ runs it in isolated homes;
                               moatbench/ holds the MoatBench scenarios `moat bench` bundles
tests/conformance/             attacks.yaml, ask.yaml, benign.yaml: one tool call each,
                               with the verdict the default policy must give
tests/fixtures/hosts/          real host payloads (claude-code, codex, cursor)
tests/differential/            differential scenarios and hostile scripts (EVIDENCE.md)
fuzz/                          cargo-fuzz targets: decide_shell, policy_parse,
                               host_payload, literal_pattern, proxy_parse
                               (separate workspace)
docs/                          this document, INSTALL, USAGE, SANDBOX, POLICY,
                               THREAT_MODEL, ROADMAP, COVERAGE and EVIDENCE
                               (generated), adr/
scripts/ci/quality-gate.sh     the one gate CI and the pre-push hook run
scripts/ci/guard-latency.py    times `moat guard` per process in CI (the `latency` job)
scripts/ci/sync-labels.sh      the repository's label set
```

## 11. Testing layers

| Layer | Where | Runs |
|---|---|---|
| Unit | next to the code (`#[cfg(test)]`, `tests.rs` modules) | every PR, all OS |
| Architecture invariants | `crates/openmoat-core/tests/architecture.rs` | every PR |
| Conformance (decide) | `tests/conformance/` through `crates/openmoat-core/tests/conformance.rs`; generates `docs/COVERAGE.md` and fails on a threat class without an attack fixture | every PR, all OS |
| Policy compiler | `crates/openmoat-core/tests/ir_consistency.rs` (IR against the engine on the conformance fixtures), `ir_never_widens.rs` (generated policies) | every PR, all OS |
| Golden host payloads | `tests/fixtures/hosts/` | every PR |
| End to end | `crates/openmoat-cli/tests/e2e/` (real binary, isolated `HOME`/`MOAT_HOME`) | every PR, all OS |
| Differential (ADR-019) | `crates/openmoat-cli/tests/e2e/differential/` runs `tests/differential/scenarios.yaml` (attacks, benign work, CVE replays) against every enforcement point: the hook decision, and each host sandbox whose binary is present. A layer that disagrees with a scenario's recorded verdict fails the suite; a missing host binary skips that layer visibly. `scripts/ci/differential.sh` points it at the host binaries for the full run. Its `scripts` list runs hostile project scripts as `npm test` under `moat run`, Claude Code's sandbox and `codex sandbox -P moat` and asserts the OS outcome; `docs/EVIDENCE.md` is generated from it (`MOAT_UPDATE_EVIDENCE=1`) | every PR: hook layer and `moat run` (macOS, Linux) in the gate, where the host layers skip visibly; in the `standard tier` job, every scenario under the host sandboxes plus `sandbox_exec` on macOS and Linux, with Claude Code and Codex pinned by `scripts/ci/host-binaries.sh`, where a missing host binary fails the test (`MOAT_REQUIRE_HOST_BINARIES`) |
| Proxy | `crates/openmoat-proxy/tests/proxy/`: a real listener and a local upstream on loopback, names mapped by a test resolver, no external network | every PR, all OS |
| `wasm32` purity build | CI job | every PR |
| Fuzz | `fuzz/`, one minute per target on PRs, ten minutes weekly | CI |
| Guard latency | `scripts/ci/guard-latency.py`: one process per call, end to end and as recorded by guard; warns above the 15 ms p95 budget, fails above 45 ms (about 3 ms deciding and 8 ms end to end on Apple silicon) | every PR, `latency` job (not required) |

CI runs `scripts/ci/quality-gate.sh` on macOS (arm64, x64), Linux and Windows, plus
`cargo-deny`, the crate packaging check and `actionlint`/`zizmor` on workflows.

## 12. Egress proxy

`moat proxy [--listen 127.0.0.1:<port>]` is the default-deny network exit from ADR-020.
Without `--listen` it binds `127.0.0.1` and the policy's `sandbox.proxy_port` when that
is set, the port the host sandboxes then send their commands' traffic to (§13; run it as
a user service), and `127.0.0.1:18080` otherwise. `moat run` serves the same proxy, brokered secrets included, from a thread
on an ephemeral loopback port and makes it the agent's only way out (§14). It is our own code on
`std::net` and `httparse` rather than `codex-network-proxy` or `sandbox-runtime` (#171):
the first is not on crates.io and would add over a hundred crates, the second would put
Node.js in the trusted base, and neither checks the ClientHello's SNI against the CONNECT
host outside TLS termination.

- **Start-up.** It refuses a non-loopback listen address, a missing installation and a
  drifted policy lock (exit 64). It compiles the policy once, so restart it after a policy
  change. It writes to the audit log under one session id per run (`proxy-<ms>`).
- **Brokered secrets** (POLICY.md §2.1). `commands/proxy.rs` has `secrets/` read each
  source (a file, an env var, or a keychain item through the OS tool by absolute path)
  into a zeroed-on-drop buffer and hand it to `openmoat_proxy::Broker`. A source that cannot
  be read stops start-up. Only ids, hosts, headers and placeholders are printed.
- **Per connection,** in this order:
  1. Read the request head, at most 16 KiB within 10 s. Two forms are served:
     - `CONNECT host:port`
     - one absolute-form `http://` request

     Refuse (`proxy-secret`) a request whose head, or body bytes read with it, carries a
     brokered secret's placeholder or value when the host is not that secret's own.
  2. Decide the host as a `fetch` atom through `CompiledPolicy` (POLICY.md §4). Only
     `allow` passes. An `ask` is refused, because the proxy cannot prompt.
     `metadata.google.internal` and `metadata.goog` are refused by name whatever the
     policy says.
  3. Resolve the name with the system resolver (IP literals skip it). Refuse the
     connection when any resolved address is loopback, link-local, a cloud metadata
     address (`100.100.100.200`, `fd00:ec2::254`, NAT64 and IPv4-mapped forms included)
     or not unicast. Also refuse it when an address is private, CGNAT, benchmarking or
     unique-local and no allow rule names that address (POLICY.md §5.2). Those rules are
     compiled once at start-up into a second policy that holds only address patterns.
     Connect only to an address that was checked.
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
     - refuse `Content-Length` with `Transfer-Encoding`, or more than one `Content-Length`;
     - after the row is recorded, put the value of each brokered secret the host owns
       and that sets `plain_http` into the head (POLICY.md §2.1). The head is zeroed once
       it is written. A secret without `plain_http` is not injected, and the row's reasons
       say so.
  6. Record one audit row: host `proxy`, the method as the tool, the action
     `net` `connect://host:port` or `http://host:port` (never the path), and the verdict
     and rules. If the row cannot be written, the connection is refused.
  7. Relay bytes both ways. A connection is closed after 120 s with no bytes in either
     direction. A plain-HTTP client stream keeps being checked for brokered secrets,
     across read boundaries. A chunk that completes one is not forwarded: the
     connection closes and a second row (`proxy-secret`) is recorded.
- **Rule ids of its own:**
  - `proxy-address`: refused destination
  - `proxy-sni`: SNI missing or mismatched, or not TLS
  - `proxy-request`: unparseable or unsupported request
  - `proxy-upstream`: DNS or connect failure
  - `proxy-secret`: a brokered secret sent towards a host other than its own
  - `proxy-audit`: written to stderr only, since the audit log is what failed
- **Limits:**
  - 256 concurrent connections; the next is answered `503`.
  - 10 s to connect upstream.
  - One thread per direction of each connection.
- **Not yet:** TLS termination for per-host method and path rules and for injecting
  secrets into HTTPS (opt-in, ADR-020), session taint for proxied connections (they carry
  no host session; the hook applies taint, §2 step 9), and a policy reload without
  restart.

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
  - *Opt-in (`sandbox.proxy_port` set): through `moat proxy` (§12).* This adds
    OpenMoat's audit rows, brokered secrets and private-address checks. The cost is
    that the proxy must be running: a stopped proxy leaves commands without network,
    never with direct network. It stays opt-in until `moat init` can install the proxy
    as a user service (#272). `moat doctor` and `moat status` warn when nothing listens
    on the port. They check by trying to bind it, so the proxy records nothing.
  - *Claude Code, opt-in:* `httpProxyPort` and `socksProxyPort` both name the port, so
    Claude Code runs no proxy of its own and sandboxed commands have no other route out
    (verified on 2.1.292; the sandboxing docs, "Custom proxy configuration").
    - Its `allowedDomains`, `deniedDomains` and local-address check then no longer
      apply to that traffic. `moat proxy` decides by the same policy.
    - The lists are still written. They apply again if the ports are removed, which
      `doctor` reports. `strictAllowlist` in user settings keeps a repository's
      settings from changing the ports or adding domains.
    - Loss: SOCKS5-only programs (`ALL_PROXY`, ssh through it) have no network, since
      `moat proxy` speaks HTTP.
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
      through `moat proxy` too.
- **Losses and allowances.** A backend narrows what it cannot express and reports it
  as a loss. It may widen only where the host cannot run otherwise (the read roots,
  Codex `:minimal` and `:tmpdir`, Claude Code's working directories and unblocked
  system paths, directory nodes left out of `denyWrite`, `.git` outside its
  code-execution paths so `git commit` works), and each of those is
  listed. `moat sandbox show` and `sandbox sync` print both; `doctor` counts them
  and prints them with `--verbose`.
- **Traps the generators handle** (found in the spike, re-verified on Claude Code
  2.1.290 and codex-cli 0.160.1): a relative pattern in Claude Code user settings
  resolves against `~/.claude`, so every pattern is absolute (`/**/.env`); a directory
  in `denyWrite` covers its subtree, so `**/.claude` (a directory-node rule) is left
  out and `.claude/worktrees/*` stays writable; Claude Code's `allowRead` of a `**/`
  exception re-opens it everywhere, so exceptions are dropped; Codex accepts globs
  only for `deny` and not under `:tmpdir`, and keeps `.git` read-only.
- **Writing and pinning.** `moat init` and `moat sandbox sync` merge the generated
  keys into the files, keeping every other key (JSON values; TOML through `toml_edit`,
  comments included), and back each file up first. `policy.lock` pins Claude Code's
  `settings.json` whole except the cosmetic `theme` key (§6) and Codex's `config.toml` by the canonical text of the part
  OpenMoat owns (`default_permissions`, `[permissions.moat]`, `features.network_proxy`),
  because Codex writes trusted projects into that file itself, and Cursor's
  `sandbox.json` whole. Drift is
  `kernel-integrity`. `doctor` also fails on a weakened or out-of-date setting,
  including a Claude Code proxy port that does not match `sandbox.proxy_port` (missing
  when it is set, present when it is not).
- **Asking and undoing.** Before writing anything, `moat init` lists the agents whose
  configuration directory exists and asks per agent at a terminal; `--hosts` and
  `--yes` skip the questions, and without a terminal no agent's files change.
  `moat uninstall` (`commands/uninstall.rs`, a person at a terminal; `kernel-self`
  denies it to agents) is the inverse: it removes exactly the hook entries
  (`hook_file::remove`) and sandbox keys (`claude::remove`, `codex::remove`,
  `cursor::remove`) init
  writes. When what is left equals a backup that holds none of OpenMoat's entries, it
  writes that backup's bytes back; when nothing is left and no such backup exists, init
  created the file and it is deleted; otherwise the user's later changes stay with the
  backups. The lock then drops those files (`integrity::unpin`) without re-pinning
  anything else.

## 14. Lightweight tier: `moat run`

ADR-018's tier for machines without a container or VM runtime puts the whole agent in
one sandbox generated from the policy. The code is in `crates/openmoat-cli/src/commands/run.rs`
(with `run/{macos,linux,unsupported}.rs`, chosen by `cfg` in one place) and
`crates/openmoat-cli/src/sandbox/{seatbelt,landlock,seccomp}.rs`.

```
policy.yaml ─► ir::lower (this project) ─► Enforcement + Grants ─┬─► seatbelt::generate ─► sandbox-exec -p <profile> <agent>
                                                                 └─► landlock::generate + seccomp ─► restricted thread ─► <agent>
moat run ─► moat proxy (thread, 127.0.0.1:<ephemeral>) ◄── HTTP(S)_PROXY ── agent and its commands
```

- **Start-up.** `moat run` refuses a missing installation and a drifted policy lock
  (§6), and a session without a project: the home directory, an ancestor of it or a
  filesystem root. It resolves the agent's executable through `PATH` and its symlinks,
  binds a loopback port, and generates the sandbox. It then prints what the user must
  know: the proxy address and audit session; that the agent's own sandbox must be
  off, because sandboxes do not nest (Seatbelt refuses a second profile); and every
  loss and allowance. Then it starts the agent. SIGINT is caught (`signal-hook`) so
  that Ctrl-C reaches the agent without taking down the proxy under it. The agent
  exiting non-zero makes `moat run` exit 1.
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
  default policy. The port is ephemeral and the proxy private to the session, unlike
  the Standard tier's opt-in long-running `moat proxy` on `sandbox.proxy_port` (§13).
- **Seatbelt (macOS).** `(deny default)`, then:
  - process basics (exec, fork, signals and process info in the same sandbox, ttys,
    POSIX shm, the two directory-service lookups `opendirectoryd.libinfo` and
    `.membership`). Not the keychain, not DNS, not `trustd`.
  - `file-read-metadata` everywhere.
  - `/`, the devices and `/private/var/select`.
  - the IR's allow rules and the grants.
  - last, the IR's deny rules, because Seatbelt applies the last match. Their `!`
    exceptions become `require-all`/`require-not`, so a deny with exceptions is exact.
    A read deny covers `file-read-data` and `file-read-xattr` and leaves `stat`
    working.
  - a fixed deny of `com.apple.SecurityServer` and `securityd`.

  Globs become `subpath`/`literal` where they name one place, else anchored regexes
  with the engine's semantics. Seatbelt compares the resolved, on-disk spelling, so
  `/tmp` patterns name `/private/tmp`, and a pattern spelled in another case than the
  disk does not match (listed as `seatbelt.case`). The golden for the default policy
  is `tests/fixtures/sandbox/seatbelt-default.sb`. Found on macOS 26: the dynamic
  loader needs to read `/`, a process cannot start from a file it cannot read, and
  `getconf DARWIN_USER_TEMP_DIR` needs the two directory-service lookups.
- **Landlock (Linux 6.7+).** Read+execute below the IR's literal allow trees, the read
  roots, the devices and the agent's executable. Full access below the project's write
  trees, the temp directory and `--write` paths. `ConnectTcp` to the proxy's port
  only. File access and TCP are hard requirements at ABI 4; abstract-socket and signal
  scoping (ABI 6) are added where the kernel has them. The rules are applied to a
  thread that then starts the agent: Landlock restricts the calling thread and its
  children, so the proxy thread keeps its audit log and network. Landlock only grants.
  A deny rule or `!` exception inside a granted tree and the proxy's port on other
  hosts stay open. Each is listed as an allowance (`landlock.inside-grants`,
  `landlock.tcp-port`). A grant inside a denied path is not made, and a glob cannot be
  granted (losses).
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
  read or change the agent's memory (its tokens), and debuggers do not work. x32 calls
  of the same are refused, and a call under another architecture (32-bit `int 0x80`,
  which has `socketcall`) kills the process. Name resolution needs a Unix socket or UDP,
  so only the proxy resolves names, as on macOS: a tool that ignores `HTTP(S)_PROXY`
  cannot resolve them. Programs that list network interfaces (`getifaddrs`, netlink)
  get an error.
- **`--isolate` (Isolated tier, Linux).** `run/linux/isolate.rs` starts the agent under
  `bwrap --unshare-all --unshare-user --die-with-parent` with the mounts
  `sandbox/bwrap.rs` generates from the same Landlock rules: each read path read-only,
  each write path read-write, the temp directory as `tmpfs`, then the masks. The project
  is walked (symlinks not followed) and each entry checked with `Checker::check_os`: a
  denied read is covered by a mode-`000` placeholder, a denied write bound read-only, a
  directory whose node alone is denied bound onto itself so it cannot be renamed. The
  literal paths deny rules name elsewhere are masked the same way, under every spelling
  of the project. Inside, `moat isolated` (hidden) binds the proxy's port on the
  namespace's loopback, relays each connection to a Unix socket bound in from a private
  `0700` directory (`moat run` relays it on to the proxy), then applies the Landlock
  rules and seccomp filter to the thread that starts the agent. Missing or unusable
  `bwrap` (a probe runs first) refuses with exit 64; macOS refuses (#175).
- **Windows** refuses with exit 64; the Standard tier is the answer there.
- `moat sandbox show` prints both lightweight outputs for the current directory, before
  the session's grants are added. The executing tests in `tests/e2e/run.rs` run
  `/bin/sh` payloads under the real sandbox on macOS and Linux; on Linux they show Unix
  and UDP sockets and `io_uring` failing with `EPERM` while TCP to the proxy works, and
  `run/linux.rs` applies the filter to a test thread.
