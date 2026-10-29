# openmoat-wasm

`openmoat-sdk` as a WebAssembly module behind a plain C ABI, for the JavaScript package in `sdk/js` (ADR-046 §7). Root rules: [AGENTS.md](../../AGENTS.md).

## Rules
- The module imports nothing: no WASI, no host functions. `sdk/js` refuses a module that imports anything; keep it that way (no `std::time`, no randomness, no I/O).
- No `unsafe` block. `unsafe_code` is `deny` here only so the three exports can `#[expect]` it for `#[unsafe(no_mangle)]`; the crate's `[lints]` table is otherwise the workspace's, kept in step by hand.
- No binding generator and no JSON crate: requests are read by `openmoat_core::yaml`, answers written by `json.rs`. Characters YAML 1.2 forbids raw are escaped on both sides (`json.rs`, `sdk/js/src/index.js`).
- The request protocol is versioned by `ABI_VERSION`; a new `op` or optional field keeps it, anything else bumps it and the JS wrapper's `ABI` together.
- Engine handles are never reused.

## Test
- `cargo test -p openmoat-wasm`: the protocol natively.
- `scripts/ci/sdk-js.sh`: the module built for `wasm32-unknown-unknown`, under Node, against every conformance fixture.
