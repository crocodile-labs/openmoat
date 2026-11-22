# Features: what works where

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know, for one feature, what it does, which agents and
> operating systems it works with, how to turn it on and where it is explained.

**On this page:** [Every feature](#every-feature) · [Each agent](#each-agent) ·
[Each operating system](#each-operating-system) · [How each agent is hooked](#how-each-agent-is-hooked)

The agent tables on this page are generated from the agents' facts in OpenMoat's code, so
they cannot drift from it. What runs on your machine now: `openmoat status`. The tests
behind each claim, agent by agent and OS by OS: [PROTECTION.md](PROTECTION.md).

## Every feature

| Feature | What it does | Works with | Turn it on | Read more |
|---|---|---|---|---|
| **Policy engine** (the hook) | Decides each tool call the agent's hook reports before it runs: `allow`, `defer` (the agent's own prompt decides), `review` or `deny`. | Every agent below with a hook (all but the Continue CLI); macOS, Linux and Windows. | `openmoat init` | [POLICY.md](POLICY.md), [USAGE.md](USAGE.md) |
| **The agents' own OS sandboxes** | `openmoat init` writes the agent's sandbox settings from the same policy, so the OS confines the commands the agent runs: no secrets, no writes outside the project, network only to listed hosts. | Claude Code (macOS, Linux, WSL2), Codex (every OS), Cursor (macOS, Linux); the [Own OS sandbox](#each-agent) column. | `openmoat init`; `openmoat sandbox show`, `openmoat sandbox sync` | [SANDBOX.md](SANDBOX.md#host-sandboxes-standard-tier) |
| **`openmoat run`** | Starts the whole agent and everything it starts in one sandbox, with network only through OpenMoat's proxy; with `--scrub-env` or `sandbox.env: scrubbed` they get only an allowlist of your environment, so a credential in your shell is not there to read. | macOS 13 or later (Seatbelt) and Linux (Landlock and seccomp; bubblewrap with `--isolate`); refuses on Windows and macOS 12. The agents in the [`openmoat run`](#each-agent) column. | `openmoat run -- <agent>` | [SANDBOX.md](SANDBOX.md#openmoat-run-lightweight-tier) |
| **Sandboxed start** | Typing a hook-only agent's command starts it in `openmoat run`'s sandbox, through a shim in `~/.moat/bin` and two lines in your shell's start-up file, both shown before they are written. | macOS 13 or later and Linux; the hook-only agents in the [`openmoat run`](#each-agent) column. | `openmoat init` asks (default no) | [INSTALL.md](INSTALL.md#two-choices-init-offers-decoy-keys-and-sandboxed-start) |
| **Egress proxy** | Lets network from the sandboxes reach only the hosts the policy lists; with its own CA it also applies a `requests:` entry's method and path rules inside HTTPS. | Network from `openmoat run`, and from the agents' own sandboxes when the policy sets `sandbox.proxy_port`. As a user service: macOS (launchd) and Linux (systemd), not Windows. | `openmoat proxy`, `openmoat proxy install`, `openmoat proxy ca init` | [POLICY.md §5.2](POLICY.md#52-openmoat-proxy), [INSTALL.md](INSTALL.md#keep-openmoat-proxy-running-as-a-user-service) |
| **Brokered secrets** | The agent holds a placeholder; the proxy puts the real token into requests to one host only. | Requests through OpenMoat's proxy. Into HTTPS only inside `openmoat run` with `--tls-terminate`; the standalone proxy and the agents' own sandboxes leave the placeholder in HTTPS. | `openmoat secret add` | [USAGE.md](USAGE.md#keep-a-token-from-the-agent), [BROKER_LOGINS.md](BROKER_LOGINS.md) |
| **MCP pins** | Pins every MCP server definition the agents load; a new or changed server's tool calls are refused until you accept it. | The agents whose servers OpenMoat reads: the [MCP servers](#each-agent) column. | `openmoat init`, then `openmoat mcp accept` | [INSTALL.md](INSTALL.md#set-up-with-openmoat-init) |
| **MCP gateway** | Starts only accepted stdio servers, sandboxed where `openmoat run` can sandbox, pins each tool's description, records every call and holds data one server returned that is sent into another's writing tool. | Stdio servers in the agents' user configuration ("can be wrapped" in the [MCP servers](#each-agent) column); a project's servers are never wrapped. | `openmoat mcp wrap`, or `openmoat init --mcp-proxy` | [USAGE.md](USAGE.md#mcp-servers-through-the-gateway) |
| **Decoy keys** | Fake AWS, GitHub and npm keys beside the real files, at names no program loads; any call that reads one or sends its value is denied (`canary`) and flagged. | Every agent with a hook, and requests through OpenMoat's proxy; every OS. | `openmoat init` asks (default no) | [INSTALL.md](INSTALL.md#two-choices-init-offers-decoy-keys-and-sandboxed-start), [POLICY.md §5.1](POLICY.md#51-rule-ids-that-are-not-in-your-policy) |
| **Session taint** | After a session read a secret, its network calls to other hosts, MCP calls and web searches need review; after it read untrusted content (a fetch, a search, an MCP result), its writes to protected paths do. | Every agent with a hook. | on by default | [POLICY.md §4.1](POLICY.md#41-session-taint) |
| **Injected input** | A command or write that uses a host, path or command a fetched page or tool result named waits for you, with the source named. | Claude Code, Codex, Gemini CLI, GitHub Copilot CLI and the Cline CLI (their after-call hook), and wrapped MCP servers. | on by default; `openmoat init` adds the after-call hook | [POLICY.md §4.1.2](POLICY.md#412-injected-input), [LIMITS.md](LIMITS.md#limits-of-single-checks) |
| **Unattended runs** | A call the agent's own prompt would decide waits for review when the agent runs with no one to ask. | Modes the agent's hook can see, as each agent's facts state them (Claude Code's `bypassPermissions` and `auto`, pi without a screen, an approvals-off mode). | `unattended: review` in your policy | [POLICY.md §5.4](POLICY.md#54-when-no-one-is-asked-unattended) |
| **Policy lock** | Pins the policy and hook files: an agent's call that changes the rules, approves its own block or switches OpenMoat off is denied, and a changed file blocks every call until you review it. | Every agent with a hook. | `openmoat init`; `openmoat doctor` | [POLICY.md §8](POLICY.md#8-the-policy-lock) |
| **Hooks a project cannot turn off** | Writes OpenMoat's hook where an administrator's hooks live. | The [Hook a project cannot turn off](#each-agent) column. | `openmoat init --managed` | [INSTALL.md](INSTALL.md#teams-managed-settings) |
| **Audit log** | Records every decision in a local, keyed, hash-chained log with secrets redacted; explains a block, follows calls live, exports and verifies. | Every agent with a hook, `openmoat run`, the proxy and the MCP gateway; every OS. | on by default; `openmoat watch`, `openmoat why --last`, `openmoat audit verify` | [USAGE.md](USAGE.md#review-what-the-agent-did) |
| **Live audit delivery** | Sends each decision, masked, to up to four OTLP/HTTP or signed HTTPS webhook sinks. | Every decision on this machine. Off until you configure it. | `~/.moat/delivery.yaml`; `openmoat audit deliver test` | [DELIVERY.md](DELIVERY.md) |
| **Remote approvals** | Sends each call held for review, redacted, to your phone; an approval lets that one call run once. | Telegram. Every agent with a hook; on an agent that cannot prompt the review is a deny you can retry. The listener as a service: macOS and Linux; on Windows in a terminal. | `openmoat approvals connect telegram`, `openmoat approvals listen` | [APPROVALS.md](APPROVALS.md) |
| **Repository rules and policy packs** | A committed `.moat/policy.yaml` adds deny and review rules for everyone who clones it (its allow rules only after `openmoat trust`); a signed pack shares a team's rules. | Every agent with a hook, and `openmoat policy check-diff`. | `.moat/policy.yaml`, `openmoat trust`, `openmoat policy trust-key`, `openmoat policy install` | [USAGE.md](USAGE.md#share-rules-with-your-team), [POLICY.md §10](POLICY.md#10-repository-policy) |
| **Merge check** | Flags a pull request's changes to CI, git hooks, agent settings, the policy or secret files, and look-alike dependencies, swapped lockfile hashes, keys and new hosts in added lines. | Any diff, whoever wrote it; no agent needed. The GitHub Action runs on Linux and macOS runners. | `openmoat policy check-diff`; the `crocodile-labs/openmoat` action | [MERGE_CHECK.md](MERGE_CHECK.md) |
| **Provenance** | Maps commits to the agent sessions that wrote each file and line, and what they had read first. | Sessions recorded in the audit log. | `openmoat provenance` | [PROVENANCE.md](PROVENANCE.md) |
| **Compliance evidence** | Maps a time window of the audit log to OWASP LLM Top 10, SOC 2 and ISO 27001 controls. Evidence, not a certification. | The audit log of this machine. | `openmoat audit evidence` | [COMPLIANCE.md](COMPLIANCE.md) |
| **SDK** | The same decisions for your own agent product; it decides, your code enforces. | Rust (`openmoat-sdk`), JavaScript (`@openmoat/sdk`: Node 20 or later, or any runtime with WebAssembly); adapters for the Claude Agent SDK, OpenAI Agents, the AI SDK, Mastra and LangChain.js. | `cargo add openmoat-sdk`, `npm install @openmoat/sdk` | [SDK.md](SDK.md) |
| **Plugin packages** (preview) | A package for an agent's own plugin channel that runs the `openmoat` your policy lock pins. | The [Plugin package](#each-agent) column. | the channel's install step | [INSTALL.md](INSTALL.md#install-from-an-agents-plugin-channel-preview) |
| **Editors** | Claude Code's VS Code extension and JetBrains plugin use the same hook as the CLI; Cursor's Tab is refused secret files. | VS Code, JetBrains, Cursor. | `openmoat init` | [IDE.md](IDE.md) |

## Each agent

What applies to each agent, from its facts in OpenMoat's code. "—" means the feature does
not apply to it. A `review` that is the agent's own prompt still becomes a deny where the
agent runs with no screen or approves unseen ([INSTALL.md](INSTALL.md#set-up-with-openmoat-init)
has each agent's case). What happens when the hook fails, case by case and with sources:
[LIMITS.md](LIMITS.md#if-the-hook-fails).

<!-- generated:features-agents -->
| Agent | Protection | Own OS sandbox (`openmoat init`) | `openmoat run` | A `review` becomes | MCP servers | Hook a project cannot turn off | Plugin package (preview) | When the hook fails, the agent |
|---|---|---|---|---|---|---|---|---|
| Claude Code | hook + OS sandbox (macOS, Linux, WSL2); hook only on native Windows | `settings.json`, not on native Windows | macOS 13+, Linux | the agent's own prompt | pinned; stdio servers can be wrapped | `openmoat init --managed` | Claude Code plugin marketplace | blocks it from 2.1.295; earlier versions run it |
| Codex | hook + OS sandbox | `config.toml` | macOS 13+, Linux | a deny you approve with `openmoat allow --last` | pinned; stdio servers can be wrapped | an administrator writes it | — | runs it when the hook times out |
| Cursor | hook + OS sandbox (macOS, Linux); hook only on Windows | `sandbox.json`, not on native Windows | macOS 13+, Linux | the agent's own prompt | pinned; stdio servers can be wrapped | `openmoat init --managed` | Cursor Marketplace | blocks it |
| OpenClaw | hook only | — | — | the agent's own prompt | pinned; stdio servers can be wrapped | — | ClawHub | blocks it |
| GitHub Copilot CLI | hook only | — | macOS 13+, Linux | the agent's own prompt | pinned; stdio servers can be wrapped | `openmoat init --managed` prints the root command | GitHub Copilot CLI plugins | runs it when the hook times out |
| pi | hook only | — | macOS 13+, Linux | the agent's own prompt | pinned; stdio servers can be wrapped | — | pi packages (npm, pi.dev gallery) | blocks it |
| Gemini CLI | hook only | — | macOS 13+, Linux | the agent's own prompt | pinned; stdio servers can be wrapped | an administrator writes it | Gemini CLI extensions gallery | runs it when the hook times out |
| OpenCode | hook only | — | macOS 13+, Linux | the agent's own prompt | pinned; stdio servers can be wrapped | an administrator writes it | OpenCode plugins (npm) | blocks it |
| Hermes Agent | hook only | — | macOS 13+, Linux | the agent's own prompt | pinned | — | Hermes Agent Plugin Catalog | blocks it |
| Cline CLI | hook only | — | macOS 13+, Linux | a deny you approve with `openmoat allow --last` | pinned; stdio servers can be wrapped | — | — | runs it when the hook cannot start, crashes or exits non-zero; or times out |
| goose | hook only | — | macOS 13+, Linux | a deny you approve with `openmoat allow --last` | pinned | — | — | blocks it |
| Antigravity CLI | hook only | — | macOS 13+, Linux | the agent's own prompt | pinned; stdio servers can be wrapped | — | Antigravity CLI plugins | runs it when the hook times out |
| Qwen Code | hook only | — | — | the agent's own prompt | pinned; stdio servers can be wrapped | an administrator writes it | — | runs it when the hook times out |
| Crush | hook only | — | — | a deny you approve with `openmoat allow --last` | pinned; stdio servers can be wrapped | an administrator writes it | — | runs it when the hook times out |
| Continue CLI | not checked yet; use `openmoat run` | — | — | — | — | — | — | — |
<!-- /generated -->

| Protection | What it means |
|---|---|
| **hook + OS sandbox** | Each tool call the hook reports is checked, and the agent's own sandbox, written from the same policy, confines the commands it runs there. Not every tool runs there: Claude Code's file tools, `WebFetch` and MCP servers run outside its sandbox, and Cursor runs some commands outside its own ([LIMITS.md](LIMITS.md#sandboxes-and-allowed-code)). |
| **hook only** | Every tool call the agent's hook reports is checked; the hook's decision is the only check. For OS confinement too, start the agent with `openmoat run` (macOS, Linux). |

## Each operating system

| | macOS | Linux | Windows |
|---|---|---|---|
| Hook and policy | yes | yes | yes |
| The agents' own sandboxes | Claude Code, Codex, Cursor | Claude Code, Codex, Cursor | Codex only; for Claude Code's, run it inside WSL2 |
| `openmoat run` | macOS 13 or later (Seatbelt) | Landlock and seccomp; bubblewrap with `--isolate` | refuses; run the agent and `openmoat` inside WSL2 |
| `openmoat proxy install` (user service) | yes | yes | no |
| Release builds | arm64, x64 | x64, arm64 (glibc and static musl) | x64 |

Sources: [INSTALL.md](INSTALL.md#install) (builds and the Windows note),
[SANDBOX.md](SANDBOX.md) (tiers). On Windows, Codex's `unelevated` sandbox mode does not
enforce the read denies OpenMoat writes; `openmoat doctor` warns and names the stronger
setting ([INSTALL.md](INSTALL.md#set-up-with-openmoat-init)).

## How each agent is hooked

The events and files `openmoat init` writes for each agent. What each hook sees, tool by
tool, is in [INSTALL.md](INSTALL.md#set-up-with-openmoat-init); the files and timeouts in
[INSTALL.md, "Non-default config directories"](INSTALL.md#non-default-config-directories).

<!-- generated:features-hooked -->
| Agent | How OpenMoat is hooked | Protection | `openmoat init --hosts` |
|---|---|---|---|
| Claude Code | `PreToolUse`, `PostToolUse`, `ConfigChange` and `SessionStart` hooks in `settings.json` | hook + OS sandbox (macOS, Linux, WSL2); hook only on native Windows | `claude-code` |
| Codex | `PreToolUse` and `PostToolUse` hooks in `hooks.json`; a `review` becomes a deny you approve with `openmoat allow --last` | hook + OS sandbox | `codex` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` and `beforeTabFileRead` hooks, fail-closed | hook + OS sandbox (macOS, Linux); hook only on Windows | `cursor` |
| OpenClaw | OpenMoat's plugin on OpenClaw's `before_tool_call` hook | hook only | `openclaw` |
| GitHub Copilot CLI | `preToolUse` and `postToolUse` hooks in a hook file of OpenMoat's own | hook only | `copilot-cli` |
| pi | OpenMoat's extension on pi's `tool_call` event | hook only | `pi` |
| Gemini CLI | `BeforeTool` and `AfterTool` hooks in `settings.json` | hook only | `gemini-cli` |
| OpenCode | OpenMoat's plugin on OpenCode 1's `tool.execute.before` (1.3.4 and later) and OpenCode 2's `execute.before` hook | hook only | `opencode` |
| Hermes Agent | `pre_tool_call` shell hook in `config.yaml`, allowlisted in `shell-hooks-allowlist.json` | hook only | `hermes` |
| Cline CLI | OpenMoat's `PreToolUse` and `PostToolUse` hook scripts in `~/.cline/hooks` | hook only | `cline` |
| goose | `PreToolUse` hook in OpenMoat's plugin, `~/.agents/plugins/openmoat/hooks/hooks.json`, with `on_failure: block` | hook only | `goose` |
| Antigravity CLI | `PreToolUse` hook in `~/.gemini/config/hooks.json` | hook only | `antigravity-cli` |
| Qwen Code | `PreToolUse` hook in `settings.json` (preview) | hook only | `qwen-code` |
| Crush | `PreToolUse` hook in `crush.json` (preview) | hook only | `crush` |
| Continue CLI | `cn` reads the Claude Code hook, but the released `cn` runs no hooks, and [Continue's repository](https://github.com/continuedev/continue) is no longer maintained | not checked yet; use `openmoat run` | none |
<!-- /generated -->

Set up one agent only with `openmoat init --hosts <id>`. Each week CI installs every
agent's latest release and checks that it still loads OpenMoat's hook
([what is checked per agent](../scripts/ci/latest-agents/README.md)). Your agent is not
listed? [ADDING_AN_AGENT.md](ADDING_AN_AGENT.md) shows how one is added.
