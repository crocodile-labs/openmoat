# openmoat-hosts

Host adapters: each supported agent's `HostSpec` (`host/<module>.rs`) and `HostAdapter` (payload → `HookRequest`, `Decision` → response), its docs rows (`host/<module>/doc.rs`), hook-file layout (`HookLayout`: a `HookFile`, or an `OwnedFile` in `host/<module>/integration/`), MCP readers, project-settings readers and protected paths (`protect.rs`), the one host list (`host.rs`), `registry.rs` and `contract.rs`. Each host's `host/<module>/HOST.md` describes it for people. The full guide is [docs/ADDING_AN_AGENT.md](../../docs/ADDING_AN_AGENT.md).

## Rules
- Translate, never decide: verdicts come from `openmoat-core`.
- No file, environment or process access outside tests; the CLI reads and writes host files.
- What differs per host goes in its spec or its folder. `tests/architecture.rs` keeps shrink-only allowlists of lines naming `Host::<Variant>`, a host id or a host's directory outside the host modules; never raise an entry.
- A new spec field gets a default in `HostSpec::BASE` / `InstallSpec::BASE`; specs end with `..HostSpec::BASE`.
- An adapter error is a deny in `guard`. A malformed or unknown payload never becomes an `allow`.
- Every tool name an adapter matches has a `ToolRow` in its `doc.rs` (the docs test fails otherwise); ungoverned tools are listed, and `gaps` and `on_hook_failure` say what the host does not cover.
- If the host fails open by default, its hook entries set its fail-closed flag.

## Test
- `cargo test -p openmoat-hosts`: unit tests in `host/<module>/tests.rs`, `tests/contract.rs`, `tests/docs.rs`, `tests/protect.rs`, `tests/architecture.rs`.
- `OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test docs` regenerates the README, INSTALL, ARCHITECTURE §3 and THREAT_MODEL §5 blocks from the specs; `OPENMOAT_TEST_UPDATE_PROTECT=1 cargo test -p openmoat-hosts --test protect` regenerates the policy and taint blocks. Review the diff.
- Payloads come from `host/<module>/fixtures/` with a README naming each one's source. End-to-end tests are in `crates/openmoat-cli/tests/e2e/` (`hosts/` runs one table-driven suite over every host).

## Do not
- Name a host by `Host::<Variant>` in CLI code to special-case it; add a spec fact or a trait method.
- Claim coverage the adapter does not have, in docs or in HOST.md.
- Commit real payloads with tokens or personal paths.
