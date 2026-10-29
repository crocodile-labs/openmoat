# openmoat-sdk

The stable façade over `openmoat-core` for other agent products (ADR-046, [docs/SDK.md](../../docs/SDK.md)): `Policy`, `Context`, `Facts`, `Session`, `Engine`, and the SDK's own `Action`, `Decision` and `Verdict`. Root rules: [AGENTS.md](../../AGENTS.md).

## Rules
- The SDK decides; the caller enforces. Never add anything that starts, stops or confines a process, and never word a doc as if the SDK protected anything by itself.
- The public surface is a contract (ADR-046 §4): the action shapes and their JSON form, the verdicts and their order, the decision shape, the rule ids, `POLICY_SCHEMA_VERSION`. Add kinds and optional fields; never change or remove one outside a major version (before 1.0, a minor one with a CHANGELOG line under `### Changed`).
- Never expose a core type: convert at the boundary (`to_core`, `from_core`), so the core stays free to change.
- Wire types reject unknown fields (`deny_unknown_fields`); a verdict the SDK does not know maps to `Deny`.
- No I/O outside the `fs` feature (`fs.rs`). Dependencies stay `openmoat-core`, `serde`, `thiserror`; a new one needs an ADR.
- Every decision must equal the engine's: `tests/conformance.rs` runs every fixture both ways.

## Test
- `cargo test -p openmoat-sdk --all-features`: unit tests, `tests/conformance.rs`, and `examples/agent_loop.rs`'s tests.
- `OPENMOAT_SDK_VECTORS=<file> cargo test -p openmoat-sdk --test conformance` writes the vectors `sdk/js/test/conformance.test.js` checks (`scripts/ci/sdk-js.sh` does both).

## Do not
- Add a decision path that bypasses `CompiledPolicy::decide_with` and `with_taint`.
- Change a fixture or the default policy to make SDK conformance pass.
