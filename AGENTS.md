# Working in this repository

The contract for everyone who changes this code, human or coding agent. Short on
purpose; each section links to the detail. `CLAUDE.md` points here.

## 1. What this is

OpenMoat (command `openmoat`; `moat` still runs it for a few releases) is a security layer for AI coding agents. It sits between an agent (Claude Code,
Codex, …) and the machine, decides whether each tool call may run, and records it.
The operating system enforces the policy only where a host sandbox or `openmoat run`
applies (ADR-018, `docs/SANDBOX.md`); elsewhere the hook's decision is the only check.
Correctness and fail-closed behaviour outrank features.
If a change makes you choose, choose `ask` over `allow` and `deny` over a crash.

Specs: `docs/ARCHITECTURE.md` (crates, data flow, hooks, self-protection),
`docs/POLICY.md` (policy semantics), `docs/THREAT_MODEL.md` (threats, known limitations),
`docs/ROADMAP.md` (stages; live order in issue #562), `docs/adr/README.md` (decisions).

## 2. Layout

Each `crates/openmoat-<name>` directory holds the package `openmoat-<name>`; `crates/openmoat-cli` holds `openmoat`, which builds the `openmoat` binary and `moat` (`src/bin/moat.rs`), the old name that starts the `openmoat` beside it.

The module-by-module map is in [`docs/ARCHITECTURE.md` §10](docs/ARCHITECTURE.md#10-repository-layout); keep it current when you add, move or split a module.

| Path | Contents | Rules |
|---|---|---|
| `crates/openmoat-core` | policy model, lexer, classifier, patterns, engine, policy compiler | **pure**: no I/O, no `unsafe`, no internal deps; builds for `wasm32`; architecture tests enforce it |
| `crates/openmoat-hosts` | host adapters (`host/<module>.rs` with its `SPEC`, `host/<module>/HOST.md`), `registry.rs`, `contract.rs` | translate payload ⇄ `Action`/`Decision`; never decide |
| `crates/openmoat-audit` | SQLite audit store, queries, redaction | typed `thiserror` errors; redact before persisting; never log secrets |
| `crates/openmoat-proxy` | egress proxy behind `openmoat proxy` | network through `std::net` only; no async runtime, no storage; a connection that cannot be recorded is refused |
| `crates/openmoat-cli` | the `openmoat` binary: grammar, commands, files, sandboxes, integrity | the only crate that touches files, env, terminal; `anyhow` allowed; all user output goes through `render.rs` or the command module |
| `crates/openmoat-core/policies/default-v1.yaml` | shipped default policy | every change needs a conformance fixture and a CHANGELOG line |
| `tests/conformance/{attacks,benign,ask}.yaml` | executable security claims | ids unique, one action each, `rules` must appear in the decision; attacks and asks carry `threat: T1…T12`; `docs/COVERAGE.md` is generated from them (`OPENMOAT_TEST_UPDATE_COVERAGE=1 cargo test -p openmoat-core --test conformance`) and every threat needs an attack |
| `crates/openmoat-hosts/src/host/<module>/fixtures/*.json` | real host payloads | golden inputs; never include real tokens or personal paths |
| `tests/fixtures/sandbox/` | generated host sandbox settings and Seatbelt profile for the default policy | golden outputs; `OPENMOAT_TEST_UPDATE_GOLDEN=1` rewrites them, review the diff |
| `crates/*/tests/` | end-to-end tests of the binary in one target, `crates/openmoat-cli/tests/e2e/` (one module per area: `cli`, `alias`, `guard`, `cursor`, `cursor_sandbox`, `hosts` (one table-driven suite over every host), `copilot_cli`, `openclaw`, `pi`, `gemini_cli`, `opencode`, `hermes`, `heartbeat`, `config_change`, `lock`, `lock_settings`, `install_path`, `binary_path`, `approvals`, `allow`, `allow_files`, `anchor`, `edit`, `escapes`, `home_screen`, `human_only`, `listings`, `mcp`, `mcp_gateway`, `packs`, `permission_mode`, `protection`, `provenance`, `audit`, `export`, `team`, `paths`, `policy_upgrade`, `push`, `replay_report`, `moatbench`, `sandbox`, `sandbox_sync`, `sandbox_exec`, `run`, `run_guard`, `uninstall`, `canary`, `closed_pipe`, `codex`, `continue_cli`, `host_failures`, `proxy`, `proxy_session`, `repo_policy`, `secret`, `session_code`, `taint`, `taint_answered`, `trust`, and `differential/` for the same scenarios against every enforcement layer, with `differential/agents` running the pinned real Claude Code against a scripted fake API; `common` is the shared helper module), conformance runner, the README and USAGE verdict tables checked against the default policy (`openmoat-core/tests/doc_tables.rs`), architecture invariants | isolated `HOME`/`MOAT_HOME`; no network |
| `docs/` | INSTALL, USAGE, SANDBOX, POLICY, ARCHITECTURE, THREAT_MODEL, ROADMAP, ADDING_AN_AGENT, MOATBENCH, DEMO, COVERAGE and EVIDENCE (generated), `adr/` | describe what the code does today; ADRs are immutable, superseded by new ADRs |
| `scripts/ci/quality-gate.sh` | the one gate | CI and the pre-push hook run exactly this |
| `scripts/ci/latest-agents.sh`, `scripts/ci/clean-install.sh` | CI's weekly checks of each agent's latest release and of the published install paths, each in a throwaway home it refuses to leave | CI only: they install unreviewed agent releases and run `openmoat init` and `uninstall`; never run them on a machine whose agents you use |
| `scripts/smoke-real-agents.sh` | a person's check of the protections with their own Claude Code, Codex, Gemini CLI, pi and GitHub Copilot CLI in a throwaway home (CONTRIBUTING "Testing with real agents") | refuses to run when a variable points at a real config directory; makes real, billed model calls; never in CI |

## 3. Invariants (never break; add a test if you touch one)

1. **Deny is absolute.** An allow rule can never override a deny rule. Kind-wide denial is `defaults: {kind: deny}` (ADR-002).
2. **Strictest wins** across every atomic action one tool call produces.
3. **Unparseable is never allow.** Anything the lexer or classifier cannot understand gets rule `unparseable`: `ask` when the policy's catch-all (`"*"`) is `ask` or `deny`, `defer` when it is `allow` or `defer` (ADR-025), never `allow`.
4. **Fail closed.** Every error path in `openmoat guard` yields a `deny` response and exit 2 (ADR-004).
5. **Exit codes:** 0 allow, defer or ok, 1 the agent `openmoat run` started failed, 2 deny, 3 unresolved ask (`policy check`), 64 usage/config. Nothing else may use 2 or 3.
6. **No secrets in the audit log.** Everything persisted passes `openmoat_audit::redact`.
7. **Pure core.** `openmoat-core` depends only on `serde`, `serde-saphyr`, `globset`, `thiserror`. Anything that needs the filesystem (program resolution, hashing) is injected from the CLI through a trait (`ProgramResolver`, `PathResolver`).
8. **Idempotent install.** `openmoat init` never overwrites a policy, never duplicates a hook, always backs up before editing a host file.
9. **Lock before decide.** `openmoat guard` verifies `policy.lock` first; drift ⇒ `deny` (`kernel-integrity`). The one exception is a change in a pinned Claude Code `settings.json` limited to the allowlisted toggles, permission lists and model choice in `integrity/relaxed.rs`: calls are still decided and the drift is recorded (`settings-drift`). A Claude Code `ConfigChange` for a pinned file that no longer matches the lock is blocked for the session. Only a person may re-pin: `openmoat init`, or from an interactive terminal `openmoat doctor --accept`, `openmoat allow`, `openmoat edit`, `openmoat secret`, `openmoat trust`, `openmoat mcp accept`, `openmoat sandbox sync` and `openmoat policy trust-key`/`install`/`remove` (which alone add the pins of the signing files, ADR-031). MCP server definitions are pinned in the lock too, but their drift denies only that server's tool calls (`mcp-server-changed`) until a person runs `openmoat mcp accept` or `openmoat doctor --accept` (ADR-026). `openmoat mcp proxy` holds every tool of a server it has no pins for until a person accepts them; `mcp: { trust_first_sight: true }` restores pinning on first sight, honoured only while the lock is intact (ADR-032).

## 4. Engineering rules

- **Errors:** `thiserror` enums in library crates; `anyhow` with `bail!`/`ensure!`/`.context()` in the CLI. `anyhow!` is banned by clippy. No `unwrap`, `expect`, `panic!` or `unreachable!` outside tests: the gate's second clippy run (`--lib --bins`) denies them. Restructure so the case cannot happen (a typed input, a total constructor) rather than asserting it.
- **Size:** files ≤ 500 lines of code (architecture test; blank and comment lines, fixtures, goldens and generated files not counted; the cap only goes down), functions ≤ 200 lines, cognitive complexity ≤ 30 (clippy). Split by concern: `foo.rs` + a `foo/` directory with one file per responsibility + `tests.rs`; never `mod.rs`, never `#[path]` (architecture test).
- **Comments** explain *why* and *what the host/OS does*; names and types explain *what the code does*. No commented-out code, no TODO/FIXME on `main` (open an issue).
- **Platform code** lives in dedicated files/modules selected by `cfg` in one place (`#[cfg(unix)]` helpers in `home.rs`, `commands/run/{macos,linux,unsupported}.rs` chosen in `run.rs`); never scatter `cfg` through business logic. Paths are handled in slash-separated canonical form everywhere (`paths.rs`).
- **Dependencies:** adding one needs a sentence in the PR on why std or an existing dep does not cover it; `cargo-deny` must stay green; `openmoat-core` additions need an ADR.
- **Lints:** workspace `clippy::pedantic`, `unsafe_code = "forbid"`, rustdoc `-D warnings`. Every public item of a library crate has a doc comment (`missing_docs`, enforced in all four library crates: `openmoat-core`, `openmoat-hosts`, `openmoat-audit`, `openmoat-proxy`). Do not `#[allow]` to get green; fix or justify in the PR. `clippy::allow_attributes` rejects `#[allow]` outright: a justified exception is `#[expect(lint, reason = "…")]`, which fails once it is no longer needed. `dbg!`, `todo!` and `unimplemented!` are lint errors. Library crates never print (`print_stdout`/`print_stderr` in each `lib.rs`); they return errors or report through a trait the CLI implements, as `openmoat-proxy::Recorder::unrecorded` does.
- **Formatting:** `cargo fmt` (max width 100). `.editorconfig` for everything else.
- **PR-only:** nothing is pushed to `main` directly. Branch `<type>/<topic>`, open a PR, let `pr-standards` label it (`type: …`, `area: …`, `size: …`, `risk: …`), keep it ≤ 500 lines, squash-merge. Conventional Commits title (`feat`, `fix`, `sec`, `policy`, `host(codex)`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`), lowercase subject. PR body sections **Testing** and **Security impact** are required (`pr-standards` fails without them); **Release note** is recommended and feeds `CHANGELOG.md`.
- **Docs are code:** behaviour change ⇒ same PR updates `docs/POLICY.md` / `ARCHITECTURE.md` / `THREAT_MODEL.md` / `CHANGELOG.md` as applicable.
- **Test data:** made-up tokens are built so they never look real in the source: write the `-` after a vendor prefix as `\x2d`, and generate test credentials at run time. GitHub secret scanning and CodeQL reject literal ones. A deliberate misspelling in a test or doc (a near-miss package name) goes in `_typos.toml`.

## 5. Skills (how to do the common jobs)

### Run the gate
```bash
scripts/ci/quality-gate.sh        # fmt, clippy -D warnings, doc, tests, policy lint
```
It also runs the checks of CONTRIBUTING "Checks beyond the Rust gate" (shellcheck,
Markdown links, typos in British English, unused dependencies) when their tools are
installed.
Claim "done" only after it passes locally. CI runs the same script on macOS (arm64, x64), Linux and Windows.

### Add or change a policy rule
1. Edit `crates/openmoat-core/policies/default-v1.yaml` (keep rule ids stable; they appear in audit logs and user output).
2. Add fixtures: at least one attack that must be denied/asked and one benign action that must still be allowed, in `tests/conformance/`.
3. If the semantics change (not just a pattern), update `docs/POLICY.md`, and add an ADR if an invariant moves.
4. Add a `changelog.d/<pr>-<slug>.md` fragment under `### Security` or `### Changed` (CONTRIBUTING "Changelog").

A change to the popular-package lists (`crates/openmoat-core/data/top-packages/*.txt`, refreshed with `scripts/refresh-top-packages.py`) needs a CHANGELOG line and a review of the diff.

### Teach the classifier something new (new wrapper, interpreter, write-program, builtin)
The shell classifier is a triage layer, not the security boundary (ADR-013); OS
enforcement is. Under the parser freeze, a newly found bypass gets an attack fixture
and the smallest change that makes it `ask`, not a new grammar or an ADR, unless an
invariant moves. Since ADR-025 `unparseable` defers under the default policy, so a
bypass is not closed by making it unparseable: emit an atom a default `ask` or `deny`
rule names (`<program> @<argument>`, `<shell> @stdin`, `@other-home`, a `Net`), or a
real `fs`/`net` atom a deny rule matches. Never emit an atom no rule names for every
call of a common command: it falls to the catch-all and, strictest winning, makes an
allowed command ask. Put the saved time into enforcement (`docs/SANDBOX.md`).
1. Data goes in `crates/openmoat-core/src/shell/tables.rs`; behaviour in `commands.rs` or `tokens.rs`.
2. Unit test in `shell/tests/` asserting the atomic actions produced.
3. Conformance fixture showing the end-to-end verdict.
4. Never widen `looks_like_path` or `host_of` without a negative test for the false positive you might introduce.

### Add a host adapter
The full guide is `docs/ADDING_AN_AGENT.md`.
1. New module in `crates/openmoat-hosts/src/host/<module>.rs` with its `SPEC` and `ADAPTER` (`HostAdapter`: `parse`, `render`), and `host/<module>/doc.rs` with its README row and tool mapping rows; add one line `Variant => module,` to the host list in `crates/openmoat-hosts/src/host.rs`.
2. Golden payloads in `crates/openmoat-hosts/src/host/<module>/fixtures/`; tests cover every tool kind the host exposes, a malformed payload, and an ungoverned tool.
3. Hook entries (`InstallSpec.hooks`, `hook_file`: a `HookLayout`), the config directory and its variable in the host's `SPEC`; `crates/openmoat-cli/src/install.rs` needs code only for a new hook-file layout. If the host is fail-open by default, its entries must set its fail-closed flag. A host without a command hook gets a plugin that runs `openmoat guard --host <id>` and blocks on every failure (OpenClaw, ADR-033; pi, whose hook file is the extension itself); the script goes in `host/<module>/integration/` as an `OwnedFile`.
4. End-to-end tests in a module per agent (`crates/openmoat-cli/tests/e2e/cursor.rs` is the model, registered in `e2e/main.rs`) running the real binary against the fixture.
5. Document the coverage honestly: the README, INSTALL, ARCHITECTURE §3 and THREAT_MODEL §5 rows are generated from `doc.rs` and the spec (`OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test docs`); write `host/<module>/HOST.md` and the agent's "When the hook fails" entry in `docs/THREAT_MODEL.md` §5 by hand.

### Add a CLI command
1. Grammar in `cli.rs` (clap derive, `///` doc on every arg), dispatch in `commands.rs`, implementation in `commands/<name>.rs`.
2. Output through `render.rs`; machine-readable `--format json` for anything a script might consume.
3. Exit codes via `exit::Code` only.
4. End-to-end test in `crates/openmoat-cli/tests/e2e/cli.rs` using an isolated `HOME`.

### Change the audit schema
Bump `SCHEMA_VERSION` in `store/schema.rs`, add a migration step, keep `Event` deserialisation backward compatible, and add a test that opens a database written by the previous version.

### Record a decision
Copy the shape of `docs/adr/ADR-004-exit-code-contract.md`: Context, Decision, Consequences, status, date. Number sequentially. Never edit an accepted ADR; supersede it.

## 6. Definition of done

- Gate passes locally; CI green on all platforms.
- Tests exist at the level that proves the change (unit, fixture, e2e, architecture).
- Docs and CHANGELOG updated in the same PR.
- PR describes Testing and Security impact.
- No new `allow` outcome was introduced without a fixture that shows it is intended.

## 7. For coding agents specifically

- Do not edit the default policy, a fixture's `expect`, or a test to make a failing check pass; fix the classifier or explain why the expectation was wrong.
- Do not disable lints, delete tests, or add `#[allow]`/`#[ignore]` to get green.
- `openmoat allow`, `openmoat edit`, `openmoat trust`, `openmoat secret add`, `openmoat mcp accept`/`wrap`/`unwrap`, `openmoat sandbox sync`, `openmoat policy upgrade`, `openmoat policy install`/`trust-key`/`remove`, `openmoat audit anchor`, `openmoat proxy install`/`uninstall`, `openmoat uninstall` and `openmoat doctor --accept` refuse to run without a terminal or when an agent is among their parent processes; `openmoat doctor --bundle` refuses when an agent is among its parent processes; `openmoat init` over an existing policy lock refuses when an agent is among its parent processes, and over drift or an unreadable lock without a terminal; without a person at a terminal it leaves new and changed MCP server definitions unpinned for `openmoat mcp accept`. End-to-end tests set `MOAT_ASSUME_TTY=1`, which only debug builds honour (`crates/openmoat-cli/src/terminal.rs`); never add another way around the terminal check.
- Do not run `openmoat init` against the real `~/.claude` of a machine where a Claude Code session is active; use `MOAT_HOME`, `CLAUDE_CONFIG_DIR` and a scratch project, and run every `openmoat` command with the same `CLAUDE_CONFIG_DIR` (docs/INSTALL.md "Non-default config directories").
- Never run `scripts/smoke-real-agents.sh` as an agent: it starts real agents with real model keys.
- Never commit credentials, real host payloads with tokens, or personal absolute paths.
- Prefer small PRs: one concern, one title, ≤ 500 lines. Never push to `main`; never merge your own PR while a required check is red.
- `moat-reviewer` posts an automated first-pass review on every PR (inline `🔴/🟠/🟡/💡` comments and a summary). Resolve or answer each 🔴 and 🟠 item before asking a maintainer to review; it is advisory and does not replace that review.
