# openmoat-core

The trusted core: the policy model and lint, the POSIX lexer (`lexer/`), the shell classifier (`shell/`), patterns, path normalisation, the engine, the policy compiler (`ir/`), the repository policy merge (`repo.rs`), the popular-package lists (`data/top-packages/`), the content checks of `policy check-diff` (`diffscan/`, one rule table in `diffscan.rs`) and the shipped default policy (`policies/default-v1.yaml`). Every decision OpenMoat makes is made here. Root rules: [AGENTS.md](../../AGENTS.md).

## Rules
- Pure: no I/O. `std::fs`, `std::env`, `std::process`, `std::net`, `println!`/`eprintln!`/`dbg!` are rejected by `tests/architecture.rs`. Anything that needs the filesystem comes in through a trait the CLI implements (`ProgramResolver`, `PathResolver`).
- Dependencies are only `serde`, `serde-saphyr`, `globset`, `thiserror`; a new one needs an ADR. No `unsafe`. Builds for `wasm32-unknown-unknown`.
- Invariants 1–3 live here: deny is absolute, strictest wins, unparseable is never `allow` (ADR-002, ADR-025).
- The classifier is triage, not the boundary (ADR-013). A bypass gets an attack fixture and the smallest change that makes it `review`: emit an atom a default `review`/`deny` rule names, never an atom no rule names for a common command.
- Rule ids in `default-v1.yaml` are stable: they appear in audit logs and user output. The agents' lines in `kernel-self` and `agent-credentials` and the taint list are generated from each host's spec (`crates/openmoat-hosts/tests/protect.rs`).
- `thiserror` errors; no `unwrap`/`expect`/`panic!` outside tests.

## Test
- `cargo test -p openmoat-core`: unit tests, `tests/conformance/main.rs` (and `owasp.rs` beside it, the OWASP agentic table, and `evidence.rs`, the end-to-end tests marked `// coverage: ASI<nn>` that count for a risk, ADR-079) over `tests/conformance/*.yaml`, `doc_tables.rs` (README and USAGE verdict tables), `ir_consistency.rs`, `ir_never_widens.rs`, `lexer_vs_bash.rs`, `architecture.rs`.
- `OPENMOAT_TEST_UPDATE_COVERAGE=1 cargo test -p openmoat-core --test conformance` regenerates `docs/COVERAGE.md`.
- A policy change carries one attack that must be denied or held for review and one benign action that must stay allowed.

## Do not
- Edit the default policy, a fixture's `expect` or a test to make a check pass.
- Widen `looks_like_path` or `host_of` without a negative test for the false positive.
- Add a grammar or an ADR for a newly found bypass unless an invariant moves (parser freeze).
