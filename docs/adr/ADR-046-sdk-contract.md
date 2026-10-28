# ADR-046: The SDK contract: OpenMoat's decisions for other agent products

Status: accepted · Date: 2026-10-28

## Context

People building their own agent products want OpenMoat's policy decisions without the
`openmoat` binary and its hooks: their agent loop already knows each tool call before it
runs, and can ask. `openmoat-core` is pure (no I/O, no `unsafe`, four dependencies) and
already builds for `wasm32-unknown-unknown`, so the decision engine can be embedded as is.
What is missing is a surface we can keep stable while the core keeps changing: the core's
`Action` has host-specific variants, `CompiledPolicy` borrows its policy, and nothing says
which parts a caller may rely on.

Issue #136 plans a stable policy schema for 1.0. This ADR does not freeze the schema; it
fixes how a caller learns which schema an SDK reads.

## Decision

### 1. The SDK decides; enforcement is the caller's

`openmoat-sdk` (Rust) and `@openmoat/sdk` (JavaScript, `sdk/js`) answer one question:
*may this tool call run?* They start, stop and confine nothing. **This is not a sandbox.**
The caller's agent loop is the enforcement point, and the contract it must keep is:

| Verdict | The caller |
|---|---|
| `deny` | does not run the call. No approval, setting or retry may lift a deny (ADR-002). |
| `ask` | runs the call only after a person approves *that exact call* |
| `defer` | applies its own permission flow; OpenMoat neither objects nor vouches (ADR-025). A product without one treats `defer` as `ask` |
| `allow` | may run the call |

A caller that holds no decision for a call (an error building the engine, a malformed
action, a module that failed) does not run it. Every SDK error is an error, never a
verdict. Where an OS boundary is needed (a hostile project script, a tool that names more
than its arguments show), the caller adds one: `openmoat run`, a container, a VM.

### 2. Approvals differ from denials

An `ask` is a request for a person, not a soft deny and not a default allow:

- The approval binds to the action decided, byte for byte. A changed argument is a new
  call and is decided again.
- An approval is for one call. The SDK keeps no approvals; a product that remembers them
  ("always allow `npm test` here") owns that store and must scope it at least as tightly
  as the CLI's grants (one rule id, one project).
- A `deny` is never offered for approval. The approver is not asked.
- The approver is a person. An agent, a model or a script answering its own `ask` is no
  approval.

### 3. Time of check and time of use

A decision is about the action value it was given. Between deciding and running, nothing
may change what runs:

- **Run the decided value.** The JavaScript `decide` returns `action`, a frozen copy of
  exactly what was decided; run that, never the model's object or a value rebuilt from
  it. In Rust, decide and run the same `Action` value.
- **Same environment.** A shell command runs with `sh -c` (or the shell its rules were
  written for), in the context's `cwd`, with `HOME` the context's `home`. A command run
  elsewhere is a different command.
- **Facts are a snapshot.** The engine never reads a disk; the caller reports where
  programs resolve and where symlinks lead (`Facts`), and the decision holds for that
  state. `Engine::paths` lists the paths an action names so the caller can resolve them.
  The caller narrows the window: resolve just before deciding, decide just before running,
  open files without following a link that appeared since (`O_NOFOLLOW` where the platform
  has it), and run programs by the path it reported.
- **Sessions.** Record a call in the `Session` only after it ran; later decisions are only
  ever stricter for it (session taint, ADR-020).

### 4. What is stable

Within a major version of the SDK, these keep their meaning and shape:

- The decision API: Rust `Policy::parse`, `Policy::with_repository`, `Engine::new`,
  `Engine::decide`, `Engine::decide_with`, `Engine::paths`, `Session::new`,
  `Session::record`, `Facts`, `Context` and their builders; JavaScript `load`,
  `OpenMoat.compile`, `Engine.decide`, `Engine.paths`, `Engine.free`, `Session`.
- The action shapes and their JSON form, tagged by `type`: `shell`, `foreign_shell`,
  `fs_read`, `fs_write`, `read_files`, `patch`, `net`, `fetch`, `web_search`, `mcp_tool`,
  `unknown_tool`, `unchecked`. New kinds may be added (the Rust enum is
  `#[non_exhaustive]`); existing ones do not change. Unknown fields are errors.
- The verdicts `allow`, `defer`, `ask`, `deny` and their strictness order. A verdict an
  older caller does not know must be handled as `deny` (the Rust enum is
  `#[non_exhaustive]` for this reason).
- The decision shape `{verdict, rules, reasons, context}`. `rules` holds the ids of the
  rule groups that decided; ids of the shipped default policy are stable (they are in
  audit logs and user output), and so are the engine's own ids: `default.<kind>`,
  `default`, `unparseable`, `unchecked`, `executables`, `session-taint`,
  `protected-contents`, and the `repo:` prefix of repository rules.
- `POLICY_SCHEMA_VERSION`, the `version:` a policy must declare. A policy for another
  version is an error, never read approximately.
- The JavaScript module's request protocol, `ABI_VERSION` 1 (`crates/openmoat-wasm`).

### 5. What is not stable

- The wording of `reasons` and `context`: for people, not for parsing.
- Which verdict a given action gets under the default policy: the policy tightens and
  loosens between releases, each change with a CHANGELOG line and conformance fixtures.
  A product that needs a fixed answer ships its own policy.
- The serialised form of a `Session`: opaque, valid only with the same SDK major version.
- Everything in `openmoat-core` that the SDK does not re-export. The SDK is the stable
  façade; the core stays free to change.

### 6. Versioning, and keeping in step with the CLI

The SDK has no release train of its own. `openmoat-sdk`, `@openmoat/sdk` and the
WebAssembly module carry the workspace version and are cut from the same commit as the
`openmoat` binary, so an SDK at version X decides exactly as `openmoat guard` X with the
same policy and facts. `scripts/ci/check-versions.py` fails when `sdk/js/package.json`
names another version. Before 1.0 a minor release may change the stable surface above,
with a CHANGELOG entry under `### Changed`; from 1.0 only a major release may.
Conformance holds them together: every fixture of `tests/conformance/` is decided through
the Rust SDK and through the JavaScript package, and both must equal the engine's decision
exactly, rules, reasons and context included (`crates/openmoat-sdk/tests/conformance.rs`,
`scripts/ci/sdk-js.sh`).

### 7. The JavaScript package: the core as WebAssembly behind a plain C ABI

- `crates/openmoat-wasm` exports three functions (`openmoat_input`, `openmoat_call`,
  `openmoat_output`) and its memory. A request is one JSON object written into the
  module's memory; the answer is JSON read back. The module **imports nothing**: no
  WASI, no host functions, so it cannot reach a network, a clock, randomness or a file in
  any runtime. `load()` refuses a module that imports anything. There is no telemetry.
- No `wasm-bindgen`. It would add a crate family, a CLI tool whose version must match it,
  and generated glue to review; the protocol is seven requests and fits in one file.
  The build is `cargo build` with the pinned toolchain and `Cargo.lock`, with source paths
  remapped, so a commit gives the same module bytes anywhere.
- No JSON crate. Requests are read by `openmoat_core::yaml` (JSON is YAML 1.2), answers
  are written by a 60-line writer. YAML 1.2 forbids a few characters raw that JSON allows
  (DEL, C1 controls, U+FEFF, U+FFFE, U+FFFF); both sides escape them.
- Exporting a function under a fixed name (`#[unsafe(no_mangle)]`) counts as `unsafe_code`.
  `openmoat-wasm` therefore sets that lint to `deny` instead of the workspace's `forbid`,
  and each of its three exports carries `#[expect(unsafe_code, reason = …)]`. The crate
  has no `unsafe` block; the host's write into the input buffer happens while no Rust
  reference to it is live.
- Engines are held in the module by handle. Handles are never reused, so a stale handle
  names no engine rather than another policy. A trap disables the wrapper for good: a
  module in an unknown state never decides again.

### 8. A change to the core

`CompiledPolicy` gains `compile_owned(Policy, &EvalContext) -> CompiledPolicy<'static>`,
which keeps the policy instead of borrowing it, so an engine can live as long as its
caller wants (in the SDK, and by handle in the module). Its rule groups keep their id and
reason rather than a reference. `compile` and every decision are unchanged; a unit test
holds owned and borrowed compilation to the same decisions. No dependency is added to the
core or the SDK: `openmoat-sdk` depends on `openmoat-core`, `serde` and `thiserror`, all
of which the core already uses.

## Consequences

- A product can embed the same decisions `openmoat guard` makes, in Rust or JavaScript,
  without the binary, the hooks or a network.
- Every SDK decision is only as strong as the caller's enforcement. docs/SDK.md says so
  first, and the examples (`crates/openmoat-sdk/examples/agent_loop.rs`,
  `sdk/js/examples/agent-loop.js`) show the loop that keeps the contract, with tests that
  a denied call never reaches its tool or the approver.
- The SDK does not carry the CLI's state: the policy lock, approvals, the audit log, MCP
  server pins, OS sandboxes and the egress proxy stay with `openmoat`. A product that
  needs them runs `openmoat`.
- The SDK's public surface is checked like the other library crates (`missing_docs`,
  `cargo semver-checks` once CI lists it). The npm and crates.io packages are publishable;
  publishing is a maintainer's release step.
