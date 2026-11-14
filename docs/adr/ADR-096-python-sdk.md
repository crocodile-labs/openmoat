# ADR-096: A Python SDK and its framework adapters (design)

Status: proposed · Date: 2026-11-14 · Builds on ADR-046 (the SDK contract) · Numbered
096: 095 is taken by a branch open at the time of writing

## Context

`@openmoat/sdk` gives a JavaScript agent OpenMoat's decisions in-process, and from this
release one wrap line per framework (`docs/SDK.md` "Framework adapters"). Most agents built
on Google ADK, CrewAI, PydanticAI, LangGraph and the OpenAI Agents SDK are Python, and
have no such path: the only way today is `openmoat run` (an OS sandbox around the whole
process) or calling the CLI by hand.

Two ways to reach the engine from Python exist without new Rust:

1. **The WebAssembly module** (`crates/openmoat-wasm`, the same `.wasm` the npm package
   ships). It imports nothing and speaks JSON over three exports (ADR-046). Python has no
   WebAssembly runtime in its standard library; running it needs `wasmtime` (a native
   wheel of about 20 MB per platform) or `wasmer`, a runtime dependency on a third-party
   native extension in a package whose point is trust.
2. **The CLI's guard over stdio** (`openmoat guard --host <id>`). It reads one host hook
   payload per process, verifies `policy.lock`, writes the audit log and answers in that
   host's format. It is a hook for agents OpenMoat installs into, not a decision API:
   there is no host id for "a Python app", a process per call costs a start-up and a lock
   check, and it needs `openmoat init` on the machine, which a deployed service does not
   have.

Neither makes a minimal `openmoat` package on PyPI straightforward with tests: (1) adds a
heavy native dependency, (2) is the wrong contract and needs a machine where `openmoat init` ran.

## Decision 1: a native extension built from `openmoat-sdk`, not the wasm or the CLI

The Python package is a PyO3 extension over `openmoat-sdk`, built with maturin as
`abi3` wheels (one per platform for every CPython from 3.10), from the same commit and
with the same version as the CLI (ADR-046 §5). It speaks the module's request protocol
internally (`openmoat-wasm/src/protocol.rs` moves to a crate both use), so Python, Rust
and JavaScript decide every conformance fixture identically and the Python tests run the
same vectors as `sdk/js/test/conformance.test.js`.

- **Name:** `openmoat` on PyPI, import `openmoat`; to be reserved before the first
  release (not checked here: PyPI was not reachable from the build sandbox).
- **Surface:** `openmoat.load()`, `Engine.decide(action, facts=, session=)`, `Session`,
  `OpenMoatError`, the same action dicts as `docs/SDK.md` "Actions". No I/O beyond
  `Policy.read`, as the Rust `fs` feature.
- **Dependencies:** none at run time. Framework adapters import their framework lazily
  and are extras (`openmoat[adk]`, `openmoat[crewai]`, …) that pull nothing themselves.
- **Release:** a `python` job in the release workflow builds the wheels (maturin's
  action), publishes with PyPI trusted publishing and attestations, after `cargo test
  -p openmoat-sdk` and the Python conformance run. A `.github/` change, so it lands in its
  own reviewed PR.

Rejected: `wasmtime` (native dependency, larger, a second runtime to trust); the CLI
over stdio (wrong contract, needs `openmoat init`); a pure-Python port (a second engine
would drift from the conformance fixtures).

## Decision 2: one shared guard, five adapters

A `openmoat.guard.Guard` mirrors `sdk/js/src/adapters/guard.js`: one engine per working
directory, one session, `deny` never runs, `review` runs only on a reviewer's `True`
(none by default, so it does not run), `defer` passes to the framework's own approval
unless `defer="review"`, every error is a refusal, each decision's time is recorded and
passed to `on_decision`. Undescribed tools are `unknown_tool`s whose path-like strings
are reads, as in JavaScript.

| Framework | Hook point (docs, 2026-11-14) | Blocked call |
|---|---|---|
| OpenAI Agents (Python) | `@tool_input_guardrail` on `@function_tool(tool_input_guardrails=[...])` and on local MCP servers | `ToolGuardrailFunctionOutput.reject_content(message)`; hosted tools, `ShellTool`, `ApplyPatchTool`, `LocalShellTool`, `ComputerTool`, handoffs and `Agent.as_tool()` are not covered |
| Google ADK | a `BasePlugin` with `before_tool_callback(tool, tool_args, tool_context)` in `App(plugins=[...])`, or `adk web --extra_plugins=openmoat.adk.OpenMoatPlugin` | return a dict (the tool result); plugins run in list order and the first non-`None` wins, so it goes first |
| CrewAI | `@on(InterceptionPoint.PRE_TOOL_CALL)` (legacy `@before_tool_call`), global | raise `HookAborted(reason)`; CrewAI swallows other exceptions (fail-open), so the adapter catches its own errors and raises `HookAborted` for them |
| PydanticAI | a wrapper toolset that decides before calling the wrapped tool | `deny`: return OpenMoat's message as the result; `review`: raise `ApprovalRequired`, so the run ends with `DeferredToolRequests` and the app answers with `ToolApproved`/`ToolDenied(message)` |
| LangGraph / LangChain v1 | `AgentMiddleware.wrap_tool_call(request, handler)` in `create_agent(middleware=[...])` | return a `ToolMessage` without calling `handler`; `review` may map to `HumanInTheLoopMiddleware`'s interrupt when a checkpointer is set |

Sources: [OpenAI Agents guardrails](https://openai.github.io/openai-agents-python/guardrails/),
[ADK plugins](https://adk.dev/plugins/), [CrewAI tool hooks](https://docs.crewai.com/en/learn/tool-hooks),
[PydanticAI deferred tools](https://pydantic.dev/docs/ai/tools-toolsets/deferred-tools/),
[LangChain custom middleware](https://docs.langchain.com/oss/python/langchain/middleware/custom).
Each adapter's exact types are checked against its framework's released package before it
is built, as the JavaScript adapters were; where an API cannot be checked, that adapter
waits.

## Consequences

- Python agents get the same decisions as `openmoat guard` with no runtime dependency and
  one line per framework, once built.
- The release gains a wheel matrix and a PyPI publisher; the request protocol becomes a
  shared crate (no change to its JSON).
- Until then, Python agents use `openmoat run`, and the docs say so.
- Like every SDK adapter, these decide and the framework enforces: a tool that bypasses
  the framework's tool pipeline is not seen, and each adapter's page lists its blind spots.
