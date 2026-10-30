# OpenMoat SDK

[README](../README.md) · [Docs index](README.md) · [ADR-046](adr/ADR-046-sdk-contract.md)

> [!NOTE]
> **Read this when** you build your own agent product and want OpenMoat to decide, before each tool call runs, whether it may.

**On this page:** [What it does](#what-it-does) · [Rust](#rust) · [JavaScript](#javascript) · [Handling a verdict](#handling-a-verdict) · [Actions](#actions) · [Context](#context) · [Facts](#facts) · [Sessions](#sessions) · [Repository policies](#repository-policies) · [Run what you decided](#run-what-you-decided) · [What stays with the CLI](#what-stays-with-the-cli) · [Versions](#versions) · [Building and testing](#building-and-testing)

## What it does

The SDK is OpenMoat's decision engine as a library: you compile a policy once, then pass
it each tool call your agent wants to make (a shell command, a file read or write, a
network host, an MCP tool call). It answers `allow`, `defer`, `ask` or `deny`, with the
rule ids and reasons that decided. It makes the same decision `openmoat guard` makes for
the same policy, from the same code (`openmoat-core`).

**The SDK decides; you enforce.** It starts, stops and confines nothing; it is not a
sandbox. A call it denies must not run, and a call it asks about must not run until a
person approves that exact call. If your code runs a call anyway, nothing stops it. Where
you need an operating-system boundary as well (a project script you do not trust, a tool
that does more than its arguments show), run the agent under `openmoat run`, a container
or a VM ([SANDBOX.md](SANDBOX.md)).

It does no I/O and sends nothing anywhere: no network, no telemetry. The JavaScript
package's WebAssembly module imports nothing from its host, so it cannot.

## Rust

The crate is `openmoat-sdk` in `crates/openmoat-sdk`.

```toml
[dependencies]
openmoat-sdk = { git = "https://github.com/crocodile-labs/openmoat" }   # on crates.io from 0.12.0
```

```rust
use openmoat_sdk::{Action, Context, DEFAULT_POLICY, Engine, Facts, Policy, Session, Verdict};

let context = Context::new("/home/me", "/home/me/app").project("/home/me/app");
let engine = Engine::new(Policy::parse(DEFAULT_POLICY)?, &context)?;

let action = Action::shell("cat ~/.ssh/id_rsa");
let decision = engine.decide(&action);
assert_eq!(decision.verdict, Verdict::Deny);
assert_eq!(decision.rules, ["secrets-paths"]);
println!("{}", decision.reason()); // secret material: read /home/me/.ssh/id_rsa
```

With the `fs` feature, `Policy::read(path)` reads a policy file; nothing else touches a
disk. A full agent loop with tests is `crates/openmoat-sdk/examples/agent_loop.rs`:

```bash
cargo run -p openmoat-sdk --example agent_loop
cargo test -p openmoat-sdk --example agent_loop
```

## JavaScript

The package is `@openmoat/sdk` in `sdk/js`: no dependencies, Node 20 or later, or any
runtime with WebAssembly. Types are in `src/index.d.ts`.

```js
import { load, Session } from "@openmoat/sdk";

const openmoat = await load(); // in a browser: load({ wasm: bytes })
const engine = openmoat.compile({
  policy: openmoat.defaultPolicy,
  context: { home: "/home/me", cwd: "/home/me/app", project: "/home/me/app" },
});

const d = engine.decide({ type: "shell", command: "cat ~/.ssh/id_rsa" });
// { verdict: "deny", rules: ["secrets-paths"], reasons: [...], reason: "...", context: [], action: {...} }
```

A full agent loop that checks every call before it runs it, with real shell, file and
fetch tools, is `sdk/js/examples/agent-loop.js`; its tests are
`sdk/js/test/agent-loop.test.js`.

```bash
scripts/ci/sdk-js.sh                        # build the module, run every JS test
node sdk/js/examples/agent-loop.js          # after a build
```

## Handling a verdict

| Verdict | What your loop does |
|---|---|
| `deny` | Does not run the call, and tells the model why (`reason`). Never offers it for approval: no person, setting or retry lifts a deny. |
| `ask` | Shows a person the call and `reason`, and runs it only if they approve *this* call. A changed argument is a new call, decided again. |
| `defer` | Runs its own permission flow. OpenMoat neither objects nor vouches. A product without one treats `defer` as `ask`. |
| `allow` | Runs the call. |

An approval is for one call; the SDK stores none. If your product remembers approvals,
scope each to one rule id and one project. The approver must be a person: a model
answering its own `ask` is no approval. A verdict your code does not know is a `deny`.

Errors (`Error` in Rust, `OpenMoatError` in JavaScript) are never verdicts: a call you
hold no decision for does not run.

## Actions

One action per tool call, in Rust as `openmoat_sdk::Action` and in JavaScript as an
object tagged by `type`. Paths are absolute or relative to the context's `cwd`. An
unknown field is an error, so a misspelt key never decides an empty call.

| `type` | Fields | Rust |
|---|---|---|
| `shell` | `command` | `Action::shell(cmd)` |
| `fs_read` | `path` | `Action::read(path)` |
| `fs_write` | `path` | `Action::write(path)` |
| `read_files` | `paths` | `Action::ReadFiles { paths }` |
| `patch` | `writes` | `Action::Patch { writes }` |
| `net` | `url` (a URL, or a host with an optional port) | `Action::net(url)` |
| `fetch` | `url`, read with no request body | `Action::fetch(url)` |
| `web_search` | `query` | `Action::WebSearch { query }` |
| `mcp_tool` | `name` (`mcp__<server>__<tool>`), `reads`, `writes`, `hosts`, `commands`, `opens`, `unchecked` | `Action::mcp(McpCall::new(name).reads(…))` |
| `unknown_tool` | `host`, `tool`, `reads`, `writes`, `hosts`, `commands` | `Action::UnknownTool(UnknownToolCall::new(host, tool))` |
| `foreign_shell` | `shell`, `command`: a shell OpenMoat cannot read, never `allow` | `Action::ForeignShell { shell, command }` |
| `unchecked` | `action`, `reason`: a call you see only in part, at least `ask` | `Action::unchecked(action, reason)` |

For an MCP or unknown tool, list in `reads`, `writes`, `hosts` and `commands` what its
arguments name, so the file, network and shell rules apply to them too. An MCP call
that only opens or reads one web page (a browser's `navigate`) names that URL in
`opens`: it is decided like a fetch of the page, not as a connection that may send
data (ADR-047). A tool you cannot describe is still decided (`unknown_tool`), never
skipped.

## Context

Where the agent runs; every path absolute and slash-separated (`C:/Users/me` on Windows).

| Field | Meaning |
|---|---|
| `home` | The user's home directory, for `~` |
| `cwd` | The directory relative paths and shell commands run in |
| `project` | The trusted project root, for `${project}`. Never the home directory, one of its ancestors or a filesystem root. Without it, project-scoped allows do not apply |
| `real_home`, `real_project` | Those roots with their symlinks resolved, when that differs (macOS `/var` → `/private/var`) |
| `moved_dirs` | `{default: moved}`: a directory an environment variable moved (`~/.claude` to `/srv/claude`) |
| `case_insensitive_paths` | File names compare ignoring case, as on default macOS and Windows disks |

## Facts

The engine never looks at a disk. Three checks need facts from one; you observe them and
pass them in (`Facts`):

| Field | Check |
|---|---|
| `programs` | Program name → where it resolves on the search path the call uses |
| `pinned` | Program name → where it was when you set up. A pinned program that now resolves elsewhere is a deny (rule `executables`); so is one the policy's `executables:` pins |
| `links` | Symlink → target. Every read and write is also checked where it really leads |
| `files` | Files that exist, so an unquoted glob operand (`cat .en*`) is checked as the files it names |

`engine.paths(action)` lists the absolute paths an action reads or writes; resolve each
and report the ones that differ in `links`. Both examples do this.

## Sessions

After a session reads secret material, network to any other host asks; after it reads
untrusted content (a fetch, a web search, an MCP result), a write to a protected path
asks (session taint, [POLICY.md](POLICY.md)). Record each call after it ran and pass the
session to the next decision. Taint only ever makes a decision stricter.

```js
const session = new Session();
const d = engine.decide(action, { facts, session });
// ... run d.action ...
session.record(engine, d.action, facts);
const saved = session.save();        // opaque text; new Session(saved) continues it
```

## Repository policies

A project's `.moat/policy.yaml` can only add restrictions: its deny and ask rules always
apply, under `repo:` ids; its allow rules only when a person trusted that exact file
([POLICY.md](POLICY.md)). Read the file yourself and merge it:

```rust
let policy = Policy::parse(DEFAULT_POLICY)?.with_repository(&repo_yaml, trusted)?;
```

```js
openmoat.compile({ policy, context, repository: { policy: repoYaml, trusted: false } });
```

## Run what you decided

A decision is about the exact action it was given (ADR-046 §3):

- Run the decided value. In JavaScript, run `decision.action`, a frozen copy of what was
  decided, never the model's object or a value rebuilt from it.
- Run a shell command with `sh -c`, in the context's `cwd`, with `HOME` set to its `home`.
- Resolve facts just before deciding, and run just after. Open files without following
  a link that appeared since, and run programs by the path you reported.
- Record a call in the session only after it ran.

## What stays with the CLI

The SDK is the decision only. These stay with `openmoat`: the policy lock and drift
checks, approvals (`openmoat allow`), the audit log, MCP server pins, host hooks, the OS
sandboxes and the egress proxy. A product that needs them runs `openmoat`.

## Versions

| Constant | Rust | JavaScript |
|---|---|---|
| Release | `openmoat_sdk::VERSION` | `openmoat.version` |
| Policy schema the release reads | `POLICY_SCHEMA_VERSION` | `openmoat.policySchemaVersion` |

The SDK is released with the CLI, from the same commit and with the same version, and
decides exactly as `openmoat guard` of that version. What is stable (the decision API,
action and verdict shapes, rule ids, the schema version) and what is not (reason wording,
which verdict the default policy gives an action, a saved session's form) is ADR-046.
Before 1.0 a minor release may change the stable surface, with a CHANGELOG entry.

Publishing to crates.io and npm is a maintainer's release step; both packages are ready
for it (`cargo package -p openmoat-sdk`, `npm pack` in `sdk/js` after a build).

## Building and testing

```bash
cargo test -p openmoat-sdk               # unit tests, the example, conformance
cargo test -p openmoat-wasm              # the module's request protocol, natively
scripts/ci/sdk-js.sh                     # the module for wasm32, then the JS tests under Node
```

`scripts/ci/sdk-js.sh` builds the module from `Cargo.lock` with the pinned toolchain and
source paths remapped, so a commit gives the same bytes on any machine, and writes its
SHA-256 beside it (`sdk/js/dist/openmoat.wasm.sha256`). It then decides every fixture of
`tests/conformance/` through the module and requires the engine's decision exactly:
verdict, rules, reasons and context. `crates/openmoat-sdk/tests/conformance.rs` does the
same for the Rust SDK.
