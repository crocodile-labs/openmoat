# openmoat-cli

The `openmoat` binary (and `moat`, `src/bin/moat.rs`): grammar (`cli.rs`), commands (`commands/`), install and uninstall, the policy lock and integrity checks, sandboxes, MCP pinning, taint, approvals, rendering. The only crate that touches files, the environment and the terminal. Root rules: [AGENTS.md](../../AGENTS.md).

## Rules
- `guard` fails closed: every error path is a `deny` with exit 2 (invariant 4). It verifies `policy.lock` before deciding (invariant 9).
- Exit codes only through `exit::Code` (0, 1, 2, 3, 64); nothing else uses 2 or 3.
- `anyhow` with `bail!`/`ensure!`/`.context()`; `anyhow!` is banned. No `unwrap`/`expect`/`panic!`/`unreachable!` in `--lib --bins`.
- All user output through `render.rs` or the command module; `--format json` for anything a script may read.
- `init` is idempotent: never overwrites a policy, never duplicates a hook, always backs up before editing a host file.
- Commands that re-pin or widen trust refuse without a terminal or with an agent among their parents (AGENTS §7). Never add another way around the terminal check; `MOAT_ASSUME_TTY=1` works only in debug builds.
- Everything persisted to the audit log passes `openmoat_audit::redact`.
- Platform code lives in `cfg`-selected files (`commands/run/{macos,linux,unsupported}.rs`), never scattered `cfg`. Paths are slash-separated canonical (`paths.rs`).
- Per-host facts come from the host's spec in `openmoat-hosts`; do not branch on `Host::<Variant>` here.

## Test
- `cargo test -p openmoat --all-features`: unit tests and one e2e target, `tests/e2e/` (one module per area, registered in `e2e/main.rs`; `common` is the shared helper; `hosts/` is the suite every host runs, one row per host in `hosts/rows/`).
- E2e tests run the real binary with an isolated `HOME` and `MOAT_HOME`, no network. Run with `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GEMINI_CLI_HOME`, `COPILOT_HOME`, `PI_CODING_AGENT_DIR`, `MOAT_HOME` unset.
- `OPENMOAT_TEST_UPDATE_GOLDEN=1` rewrites `tests/fixtures/sandbox/`; review the diff.

## Do not
- Run `openmoat init` against a real `~/.claude` (or any real agent directory) where a session is active.
- Run `scripts/smoke-real-agents.sh` as an agent.
- Add `#[allow]`/`#[ignore]` or delete tests to get green.
