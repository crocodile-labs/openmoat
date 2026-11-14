# OpenMoat SDK

[README](../README.md) · [Docs index](README.md) · [ADR-046](adr/ADR-046-sdk-contract.md)

> [!NOTE]
> **Read this when** you build your own agent product and want OpenMoat to decide, before each tool call runs, whether it may.

**On this page:** [What it does](#what-it-does) · [Rust](#rust) · [JavaScript](#javascript) · [Framework adapters](#framework-adapters) · [Claude Agent SDK apps and `openmoat init`](#claude-agent-sdk-apps-and-openmoat-init) · [Python](#python) · [Handling a verdict](#handling-a-verdict) · [Actions](#actions) · [Context](#context) · [Facts](#facts) · [Sessions](#sessions) · [Repository policies](#repository-policies) · [Run what you decided](#run-what-you-decided) · [What stays with the CLI](#what-stays-with-the-cli) · [Versions](#versions) · [Building and testing](#building-and-testing)

## What it does

The SDK is OpenMoat's decision engine as a library: you compile a policy once, then pass
it each tool call your agent wants to make (a shell command, a file read or write, a
network host, an MCP tool call). It answers `allow`, `defer`, `review` or `deny`, with the
rule ids and reasons that decided. It makes the same decision `openmoat guard` makes for
the same policy, from the same code (`openmoat-core`).

**The SDK decides; you enforce.** It starts, stops and confines nothing; it is not a
sandbox. A call it denies must not run, and a call it holds for review must not run until a
person approves that exact call. If your code runs a call anyway, nothing stops it. Where
you need an operating-system boundary as well (a project script you do not trust, a tool
that does more than its arguments show), run the agent under `openmoat run`, a container
or a VM ([SANDBOX.md](SANDBOX.md)).

It does no I/O and sends nothing anywhere: no network, no telemetry. The JavaScript
package's WebAssembly module imports nothing from its host, so it cannot.

## Rust

The crate is `openmoat-sdk` in `crates/openmoat-sdk`.

```bash
cargo add openmoat-sdk
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

Install it from npm: `npm install @openmoat/sdk`. Releases are published from the release
workflow with npm's provenance, so `npm audit signatures` checks where a version was built.

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

## Framework adapters

If your agent runs on an agent framework, `@openmoat/sdk` hooks into the framework's own
tool-call hook, so you add one line and keep the rest of your code. Install the one
package (`npm install @openmoat/sdk`); each adapter is a subpath of it. The package does
not import or depend on any framework, and its types match each framework's types
structurally, so you need no peer dependency.

| Framework | Import | One line | Checked against | A blocked call |
|---|---|---|---|---|
| Claude Agent SDK | `@openmoat/sdk/claude-agent-sdk` | `query({ prompt, options: { hooks: openmoatHooks() } })` | `@anthropic-ai/claude-agent-sdk` 0.3.325 | `PreToolUse` returns `permissionDecision: "deny"`; the reason is Claude's tool result |
| OpenAI Agents SDK (JS) | `@openmoat/sdk/openai-agents` | `tools: withOpenMoat([...])`, or `inputGuardrails: [openmoatGuardrail()]` on one `tool()` or `toolInputGuardrails` on a local MCP server | `@openai/agents-core` 0.22.0 | `rejectContent`: the model gets the message as the call's output (`block: "throw"` ends the run) |
| Vercel AI SDK | `@openmoat/sdk/ai-sdk` | `generateText({ model, tools: withOpenMoat(tools) })` | `ai` 7.0.173 | `execute` throws `OpenMoatBlockedError`; the SDK sends the model a `tool-error` |
| Mastra | `@openmoat/sdk/mastra` | `new Agent({ ..., hooks: openmoatHooks() })` | `@mastra/core` 1.83.0 | `beforeToolCall` returns `{ proceed: false, output: { error } }`; `output` is the tool result |
| LangChain.js v1 | `@openmoat/sdk/langchain` | `middleware: [createMiddleware(openmoatMiddleware())]`, last in the list | `langchain` 1.6.6 | the tool node gets a stand-in tool that returns the message, in the `ToolMessage` the model sees |

"Checked against" means the adapter's types compile against that release's own type
definitions (TypeScript 5.9, `strict`), and its tests drive the adapter the way that
release's source calls the hook. No adapter test runs a framework or a model.

### What every adapter does

- **`deny`**: the tool does not run, and the model is told OpenMoat's reason and rule ids.
  Nothing asks a person.
- **`review`**: by default the call does not run, because nobody can approve it from
  inside an unattended agent. Pass `review: async (call) => boolean` to ask a person; only
  `true` lets the call run. With the Claude Agent SDK, `review: "ask"` returns
  `permissionDecision: "ask"`, so your app's `canUseTool` answers it (never in the
  `bypassPermissions` or `dontAsk` modes, where no person is asked: there it is denied).
- **`defer`** (no rule matched): the call goes to the framework's own approval, if you set
  one (`toolApproval` in the AI SDK, `requireApproval` in Mastra, `needsApproval` in the
  OpenAI Agents SDK, Claude's permission modes and `canUseTool`). That keeps everyday calls
  quiet. `defer: "review"` treats it as `review` instead, for a product with no approval
  flow of its own (see [Handling a verdict](#handling-a-verdict)).
- **`allow`**: the call runs. With the Claude Agent SDK the hook returns `{}`, so your own
  permission settings still apply.
- **Errors fail closed.** A module that does not load, a policy that does not compile, a
  tool input without the field it needs, a reviewer that throws: the call does not run, and
  the model is told OpenMoat could not decide it. The Claude matcher also sets
  `onFailure: "block"` (Agent SDK 0.3.317 or later), so a callback that fails or times out
  blocks the call.
- **Time is recorded.** Every outcome carries `decideMs` (the engine) and `ms` (the whole
  check, a reviewer's wait included); `onDecision(event)` receives each one, and
  `guard.stats` holds the counts, the total and the slowest.
- **The run gets the decided input.** The AI SDK and LangChain adapters run the tool with a
  copy of the input that was decided, not the model's object.
- **Sessions.** One session per adapter, so a secret read or untrusted content tightens
  later calls ([Sessions](#sessions)). A call is recorded when it is let through, before
  it runs: taint only tightens, so a call that then fails makes later calls stricter,
  never looser. Share one session and its stats across adapters with
  `guard: createGuard({...})` from `@openmoat/sdk/guard`.

### Telling OpenMoat what your tools do

The Claude Agent SDK's built-in tools are mapped with the field names `openmoat guard`
reads for Claude Code (`Bash` → `shell`, `Read` → `fs_read`, `Write`/`Edit` → `fs_write`,
`WebFetch` → `fetch`, `mcp__…` → `mcp_tool`, and so on). In the other frameworks every tool
is yours, so OpenMoat cannot know what it does. Describe the ones that run commands, touch
files or open connections:

```js
import { describe } from "@openmoat/sdk/guard";
import { withOpenMoat } from "@openmoat/sdk/ai-sdk";

const tools = withOpenMoat(
  { runShell, readFile, fetchPage, summarise },
  {
    tools: {
      runShell: describe.shell("command"),   // { command: "..." } → a shell action
      readFile: describe.read("path"),
      fetchPage: describe.fetch("url"),
      // any other shape: (input) => ({ type: "fs_write", path: input.target })
    },
  },
);
```

A tool you do not describe (`summarise`) is decided as an `unknown_tool` of that framework,
and every string in its input that starts at a root, a drive or `~` is checked as a read,
so `~/.ssh/id_ed25519` is denied whatever the tool is called. Under the default policy an
unknown tool otherwise defers. An input nested deeper than 32 levels or holding more than
1024 strings is not searched in full and needs review.

### Options

Every adapter takes the same options (types in `src/adapters/guard.d.ts`):

| Option | Default | Meaning |
|---|---|---|
| `tools` | none | Tool name → `(input) => Action` |
| `review` | none: a review does not run | A person's answer for one call; only `true` approves |
| `defer` | `"allow"` | `"review"` treats `defer` as `review` |
| `policy`, `repository` | the default policy | Policy YAML; a repository policy merged in |
| `context` | this process: home, working directory as the project unless it is the home directory, an ancestor of it or a root | Needed outside Node |
| `facts` | symlinks resolved on this disk | `false` outside Node |
| `onDecision` | none | Each outcome with its timing; its errors are ignored |
| `openmoat` | `load()` on the first call | A module you loaded yourself |
| `guard` | a new one | Share one guard between adapters |

The module loads and the policy compiles on the first tool call; `await guard.ready()`
does it earlier and rejects if it fails.

### Examples

```js
// Claude Agent SDK
import { query } from "@anthropic-ai/claude-agent-sdk";
import { openmoatHooks } from "@openmoat/sdk/claude-agent-sdk";

for await (const m of query({ prompt, options: { hooks: openmoatHooks() } })) { /* ... */ }
```

```js
// OpenAI Agents SDK
import { Agent, tool } from "@openai/agents";
import { describe } from "@openmoat/sdk/guard";
import { withOpenMoat } from "@openmoat/sdk/openai-agents";

const agent = new Agent({
  name: "ops",
  tools: withOpenMoat([runShell, readFile], {
    tools: { run_shell: describe.shell(), read_file: describe.read() },
  }),
});
```

```js
// Mastra
import { Agent } from "@mastra/core/agent";
import { openmoatHooks } from "@openmoat/sdk/mastra";

const agent = new Agent({ name, instructions, model, tools, hooks: openmoatHooks({ tools: { /* ... */ } }) });
```

```js
// LangChain.js
import { createAgent, createMiddleware } from "langchain";
import { openmoatMiddleware } from "@openmoat/sdk/langchain";

const agent = createAgent({ model, tools, middleware: [createMiddleware(openmoatMiddleware())] });
```

```js
// A person approves reviews, every decision is logged with its time
const hooks = openmoatHooks({
  review: async ({ tool, decision }) => askOnCall(`${tool}: ${decision.reason}`),
  onDecision: (e) => log.info({ tool: e.tool, verdict: e.verdict, rules: e.rules, ms: e.ms }),
});
```

### What each adapter cannot see

The adapter decides; the framework runs the tool. A call that does not go through the
framework's tool hook is never seen:

- **Claude Agent SDK**: none of its tools bypass `PreToolUse`. A tool your own MCP server
  runs is seen as `mcp__…`, but what the server does inside is not.
- **OpenAI Agents SDK**: tool input guardrails run only for function tools and local MCP
  servers' tools. Hosted tools (web and file search, code interpreter, hosted MCP),
  `ShellTool`, `ApplyPatchTool`, `LocalShellTool`, `ComputerTool` and handoffs are not
  guarded; `withOpenMoat` leaves them as they are.
- **Vercel AI SDK**: only tools with an `execute` are wrapped. Tools the client or the
  provider runs are not. A tool whose `execute` is not an `async function*` but returns a
  stream loses its preliminary results (it still runs only when allowed).
- **Mastra**: hooks given to one `generate` or `stream` call replace the agent's matching
  hooks for that call; pass `openmoatHooks()` there too.
- **LangChain.js**: put the middleware last in `middleware`, so no other middleware changes
  a call after OpenMoat decided it. A middleware's error ends the run unless the tool
  node's `handleToolErrors` is `true`.

For an operating-system boundary as well, run the agent under `openmoat run`
([SANDBOX.md](SANDBOX.md)).

## Claude Agent SDK apps and `openmoat init`

A Claude Agent SDK app that leaves `settingSources` out loads the same settings files as
Claude Code, hooks included, so on a machine where `openmoat init` set up Claude Code the
app already runs OpenMoat's `PreToolUse` hook (`openmoat guard --host claude-code`, with the
lock check and the audit log) without any code:

- The TypeScript SDK's type for `settingSources` says: "When omitted, all sources are
  loaded (matches CLI defaults). Pass `[]` to disable filesystem settings (SDK isolation
  mode)." In 0.3.325 `query()` passes `--setting-sources` to Claude Code only when the
  option is set (`sdk.mjs`), and resolves an unset option to `["user", "project",
  "local"]`.
- The docs: "When you omit `settingSources`, `query()` reads the same filesystem settings as
  the Claude Code CLI: user, project, and local settings" and "Omitting `settingSources` is
  equivalent to `["user", "project", "local"]`"
  ([Use Claude Code features](https://code.claude.com/docs/en/agent-sdk/claude-code-features));
  the SDK collects "shell command hooks from settings files when the corresponding
  `settingSources` … entry is enabled, which it is for default `query()` options"
  ([hooks](https://code.claude.com/docs/en/agent-sdk/hooks)). Python's `setting_sources`
  is the same.
- The default was briefly "no filesystem settings" in Agent SDK 0.1.0 and then reverted
  ([migration guide](https://code.claude.com/docs/en/agent-sdk/migration-guide)); Python SDK
  0.1.59 and earlier treated `setting_sources=[]` like leaving it out.

So the hook runs when all of these hold, and not otherwise:

| Condition | Why |
|---|---|
| `settingSources` is left out or includes `"user"` | `openmoat init` writes the hook into the user settings, `~/.claude/settings.json` |
| The app's Claude Code process sees the same config directory | a `CLAUDE_CONFIG_DIR` in the process environment or the `env` option moves it; `openmoat init` must have been run for that directory |
| The `openmoat` binary the hook names exists for that process | the hook runs the binary path `openmoat init` wrote; where it is missing (a container that shares the settings but not the binary), Claude Code 2.1.295 and later block the call, earlier versions run it |
| The settings set neither `disableAllHooks` nor `allowManagedHooksOnly` | the first turns settings-file hooks off, the second all but the managed ones |

`settingSources: []` turns it off, and so does a deployment with its own home or container
without OpenMoat. Managed policy settings load whatever `settingSources` says, so an
organisation that installs the hook there gets it in every SDK app on the machine. Where
the CLI is not installed, use the in-process adapter above; both can run together (each is
a `PreToolUse` hook, and a `deny` from either wins). Not checked here with a real app and
model: this section follows the SDK's documentation and its 0.3.325 source.

## Python

There is no Python package yet. ADR-096 designs one (`openmoat` on PyPI, a native
extension over the Rust SDK, adapters for Google ADK, CrewAI, PydanticAI, LangGraph and the
OpenAI Agents SDK). Until then, run a Python agent under `openmoat run`.

## Handling a verdict

| Verdict | What your loop does |
|---|---|
| `deny` | Does not run the call, and tells the model why (`reason`). Never offers it for approval: no person, setting or retry lifts a deny. |
| `review` | Shows a person the call and `reason`, and runs it only if they approve *this* call. A changed argument is a new call, decided again. |
| `defer` | Runs its own permission flow. OpenMoat neither objects nor vouches. A product without one treats `defer` as `review`. |
| `allow` | Runs the call. |

An approval is for one call; the SDK stores none. If your product remembers approvals,
scope each to one rule id and one project. The approver must be a person: a model
answering its own `review` is no approval. A verdict your code does not know is a `deny`.
Before 0.14.0 `review` was named `ask`: the SDK still reads `"ask"` in a policy or a
decision as `review`, and writes `"review"` (ADR-053).

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
| `unchecked` | `action`, `reason`: a call you see only in part, at least `review` | `Action::unchecked(action, reason)` |

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

The engine never looks at a disk. Three checks need facts from a disk (program pins,
symlinks, globs); you observe them and pass them in (`Facts`):

| Field | Check |
|---|---|
| `programs` | Program name → where it resolves on the search path the call uses |
| `pinned` | Program name → where it was when you set up. A pinned program that now resolves elsewhere is a deny (rule `executables`); so is one the policy's `executables:` pins |
| `links` | Symlink → target. Every read and write is also checked where it really leads |
| `files` | Files that exist, so an unquoted glob operand (`cat .en*`) is checked as the files it names |

`engine.paths(action)` lists the absolute paths an action reads or writes; resolve each
and report the ones that differ in `links`. Both examples do this.

## Sessions

After a session reads secret material, network to any other host needs review; after it reads
untrusted content (a fetch, a web search, an MCP result other than a browser's tab list), a
write to a protected path needs review (session taint, [POLICY.md](POLICY.md)). Record each call after it ran and pass the
session to the next decision. Taint only ever makes a decision stricter.

```js
const session = new Session();
const d = engine.decide(action, { facts, session });
// ... run d.action ...
session.record(engine, d.action, facts);
const saved = session.save();        // opaque text; new Session(saved) continues it
```

## Repository policies

A project's `.moat/policy.yaml` can only add restrictions: its deny and review rules always
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

A `Session` does not take what a call returned yet, so it has no injected-input check
(`injected-input`, POLICY.md §4.1.2, ADR-057). After untrusted content it tightens protected
writes and, after a secret read, network, as above; a later command that uses a host a page
named is not linked to the page. The conformance fixtures that give a call's output are the
CLI's claim and are skipped by the SDK's conformance test.

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

Both packages carry the release version: the Rust crate `openmoat-sdk` takes the
workspace version and goes to crates.io with each release, and `@openmoat/sdk` has the
same version in `sdk/js/package.json` and is published to npm by the release workflow
(npm trusted publishing, with provenance).

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
