# OpenMoat documentation

[README](../README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/) · [Changelog](../CHANGELOG.md)

These documents are the full reference, and they describe the code on `main`.
Step-by-step guides for common situations (a blocked call, a site to allow, a token to
protect) are on [openmoat.dev/docs](https://openmoat.dev/docs/).

## Start

| Document | What it covers |
|---|---|
| [README](../README.md) | What OpenMoat is, the quick start, supported agents and the main limits |
| [FEATURES.md](FEATURES.md) | Every feature, what it does, which agents and operating systems it works with, how to turn it on and its page; per agent: own sandbox, `openmoat run`, reviews, MCP servers, managed hooks, plugin packages, what happens when the hook fails (agent tables generated) |
| [INSTALL.md](INSTALL.md) | Install and [upgrade](INSTALL.md#upgrading) on macOS, Linux and Windows, and [what 0.30.0 changes](INSTALL.md#from-0290-to-0300); `openmoat init`; what each agent's hook covers (Cursor's `beforeTabFileRead`, the Cline CLI's `PostToolUse` file); other config directories |
| [IDE.md](IDE.md) | Claude Code in VS Code and JetBrains, and Cursor's editor and Tab: what the hook covers there (`getDiagnostics`, `executeCode`, the editors' project files), the setup and checks, what is not covered (a repository's git configuration, the editor selection) |
| [DEMO.md](DEMO.md) | The launch demo, run in a throwaway home |

## Use

| Document | What it covers |
|---|---|
| [USAGE.md](USAGE.md) | Handling a deny or a review and reading the block message, reviewing what the agent did ([`openmoat watch`](USAGE.md#watch-the-agents-live), [`openmoat why`](USAGE.md#why-was-this-blocked), `openmoat report`), [the lethal trifecta](USAGE.md#private-data-untrusted-content-and-a-way-out-the-lethal-trifecta) and [staging](USAGE.md#data-packed-or-copied-before-it-is-sent-staging) reviews, [other hooks the agents run](USAGE.md#other-hooks-the-agents-run) (`openmoat hooks list`, `openmoat hooks accept`), [signed audit checkpoints](USAGE.md#check-that-the-audit-log-was-not-changed) (`openmoat audit checkpoint`, `audit verify --checkpoint --pubkey`), [MCP servers through the gateway](USAGE.md#mcp-servers-through-the-gateway) (MCP 2026-07-28, sampling and sign-in links a server asks for, package releases held at `openmoat mcp accept`), [whether an agent's own sandbox starts on Linux](USAGE.md#can-the-agents-own-sandbox-start-commands-here-linux) (each agent's AppArmor fix), changing the policy and checking an edit with `openmoat policy diff --widen`, team rules; every command and exit code |
| [POLICY.md](POLICY.md) | The policy file: schema, rule kinds and a rule's [`title` and `why`](POLICY.md#2-rule-groups), pattern syntax, evaluation order, the default policy (`managed-settings`, `container-host`, `system-files`, `stops-system`, `credential-egress` among its rules), [`hooks.foreign`](POLICY.md#55-other-hooks-the-agents-run-hooksforeign), [`sandbox.strict`](POLICY.md#97-strict-mode-sandboxstrict), the lock, [`policy upgrade`](POLICY.md#82-approvals)'s merge, [whether a change widens](POLICY.md#83-does-a-change-widen-openmoat-policy-diff---widen-adr-111); [argument conditions](POLICY.md#24-argument-conditions-when) (`when:`); [staging](POLICY.md#45-staging-data-sent-after-collection) (`staging-egress`, `staging:`); the [lethal trifecta](POLICY.md#46-the-lethal-trifecta) (`lethal-trifecta`, `taint.trifecta`, `taint.private_paths`); session taint and [injected input](POLICY.md#412-injected-input) (`injected-input`), MCP [cross-server data flow](POLICY.md#cross-server-data-flow-mcp-cross-server-adr-058) (`mcp-cross-server`, `mcp.flow_trusted`), `mcp.allow_sampling`, `check_diff.levels` |
| [SANDBOX.md](SANDBOX.md) | The OS sandboxes: the agents' own (Standard tier), `openmoat run` (Lightweight) and `openmoat run --isolate` (Isolated); [`openmoat run` on Windows](SANDBOX.md#openmoat-run-on-windows-preview) (preview: writes and the process tree only, at most 55/100); the [protection score and strict mode](SANDBOX.md#the-protection-score-and-strict-mode); agents' logins denied to the commands they run, and the running agent's own kept under `openmoat run` (`run.own-login`) |
| [APPROVALS.md](APPROVALS.md) | Approving a review from your phone over Telegram: setup, commands, what is sent, limits, threats, adding a channel |
| [BROKER_LOGINS.md](BROKER_LOGINS.md) | Keeping an agent's API key out of `openmoat run` with `openmoat secret add`: steps, providers' hosts and headers, limits |
| [MERGE_CHECK.md](MERGE_CHECK.md) | Checking pull requests before merge: `openmoat policy check-diff` and the GitHub Action, the content checks of added lines (supply chain, CI takeover, decoded or downloaded code, keys, new hosts) and `check_diff.levels`, a policy change that widens (`diff-widens`), with an example workflow, output and limits |
| [PROVENANCE.md](PROVENANCE.md) | Agent provenance for commits: which files and lines agent sessions wrote, after reading what, from the audit log; `openmoat provenance`, notes on `refs/notes/openmoat`, `--verify`, what check-diff shows, limits |
| [DELIVERY.md](DELIVERY.md) | Live audit delivery to a SIEM or log collector: OTLP/HTTP logs and a signed HTTPS webhook, `~/.moat/delivery.yaml`, what is sent and masked, retries and the backlog bound, collector examples, `openmoat audit deliver status`, `test`, `flush` |
| [COMPLIANCE.md](COMPLIANCE.md) | `openmoat audit evidence`: the audit log as evidence per control of OWASP LLM 2025, SOC 2 and ISO/IEC 27001; the rule → control map and its limits |
| [SDK.md](SDK.md) | The SDK for your own agent product: Rust and JavaScript, verdict handling, actions, facts, sessions, the stability contract |

## Understand

| Document | What it covers |
|---|---|
| [PROTECTION.md](PROTECTION.md) | What protects each agent on Linux, macOS and Windows (hook, what happens when it fails, its own sandbox, the `openmoat run` tier, MCP servers, what a command can read in a run) and the tests behind each claim (generated; do not edit) |
| [LIMITS.md](LIMITS.md) | What OpenMoat does not stop: approvals and prompts, sandboxes and allowed code (`openmoat run` on Windows holds no reads or network), what the hook does not see (remote MCP servers have a gateway only once a person names them), agents that skip or change the check, the limits of single checks |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What is defended, how the hook and the OS layers answer each threat class, and the known limits |
| [EVIDENCE.md](EVIDENCE.md) | What the OS layer stops in an allowed project script, per OS (generated; do not edit) |
| [COVERAGE.md](COVERAGE.md) | The conformance fixtures per threat class (generated; do not edit) |
| [MOATBENCH.md](MOATBENCH.md) | The attack and everyday scenarios per agent, and the scorecard |
| [BENCHMARKS.md](BENCHMARKS.md) | The default policy on outside benchmarks (RedCode-Exec, agent-egress-bench): method, results per category, what is not stopped, false positives, limits |
| [DISTURBANCE.md](DISTURBANCE.md) | What OpenMoat costs your work: `openmoat audit stats` (decision times, holds and denies per 100 calls, the guard's own failures, per agent) and the same figures `openmoat bench` measures in CI |
| [ROADMAP.md](ROADMAP.md) | What exists, what comes next and what is not planned; the live order is issue [#562](https://github.com/crocodile-labs/openmoat/issues/562) |

## Contribute

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Where code lives and how a tool call becomes a decision, a hook response and an audit record |
| [ADDING_AN_AGENT.md](ADDING_AN_AGENT.md) | Adding support for another AI coding agent: adapter, installer, fixtures, tests, docs |
| [adr/](adr/README.md) | The decisions that constrain the code |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Setup, the quality gate, CI, pull requests, releasing |
| [AGENTS.md](../AGENTS.md) | The working contract for people and coding agents |
| [SECURITY.md](../SECURITY.md) | How to report a bypass or vulnerability privately |
| [CHALLENGE.md](CHALLENGE.md) | Break OpenMoat: the public bypass challenge, what counts, how you are credited |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community standards |
| [CHANGELOG.md](../CHANGELOG.md) | Every user-visible change, per release |

Documents are updated in the same pull request as the behaviour they describe. ADRs
are superseded, not edited, except to rename a term a later ADR renames (ADR-053 §7).
