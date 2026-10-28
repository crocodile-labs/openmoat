# OpenMoat documentation

[README](../README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/) · [Changelog](../CHANGELOG.md)

These documents are the full reference, and they describe the code on `main`.
Step-by-step guides for common situations (a blocked call, a site to allow, a token to
protect) are on [openmoat.dev/docs](https://openmoat.dev/docs/).

## Start

| Document | What it covers |
|---|---|
| [README](../README.md) | What OpenMoat is, the quick start, supported agents and the main limits |
| [INSTALL.md](INSTALL.md) | Install and upgrade on macOS, Linux and Windows; `openmoat init`; what each agent's hook covers; other config directories |
| [DEMO.md](DEMO.md) | The launch demo, run in a throwaway home |

## Use

| Document | What it covers |
|---|---|
| [USAGE.md](USAGE.md) | Handling a deny or an ask, reviewing what the agent did, changing the policy, team rules; every command and exit code |
| [POLICY.md](POLICY.md) | The policy file: schema, rule kinds, pattern syntax, evaluation order, the default policy, the lock |
| [SANDBOX.md](SANDBOX.md) | The OS sandboxes: the agents' own (Standard tier), `openmoat run` (Lightweight) and `openmoat run --isolate` (Isolated) |
| [SDK.md](SDK.md) | The SDK for your own agent product: Rust and JavaScript, verdict handling, actions, facts, sessions, the stability contract |

## Understand

| Document | What it covers |
|---|---|
| [THREAT_MODEL.md](THREAT_MODEL.md) | What is defended, how the hook and the OS layers answer each threat class, and the known limits |
| [EVIDENCE.md](EVIDENCE.md) | What the OS layer stops in an allowed project script, per OS (generated; do not edit) |
| [COVERAGE.md](COVERAGE.md) | The conformance fixtures per threat class (generated; do not edit) |
| [MOATBENCH.md](MOATBENCH.md) | The attack and everyday scenarios per agent, the scorecard, and a comparison with other Claude Code guards |
| [ROADMAP.md](ROADMAP.md) | What exists, what comes next and what is not planned; the live order is issue [#562](https://github.com/crocodile-labs/openmoat/issues/562) |

## Contribute

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Where code lives and how a tool call becomes a decision, a hook response and an audit record |
| [ADDING_AN_AGENT.md](ADDING_AN_AGENT.md) | Adding support for another AI coding agent: adapter, installer, fixtures, tests, docs |
| [adr/](adr/README.md) | The decisions that constrain the code |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Setup, the quality gate, pull request standards, releasing |
| [AGENTS.md](../AGENTS.md) | The working contract for people and coding agents |
| [SECURITY.md](../SECURITY.md) | How to report a bypass or vulnerability privately |
| [CHALLENGE.md](CHALLENGE.md) | Break OpenMoat: the public bypass challenge, what counts, how you are credited |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community standards |
| [CHANGELOG.md](../CHANGELOG.md) | Every user-visible change, per release |

Documents are updated in the same pull request as the behaviour they describe. ADRs
are immutable and superseded, never edited.
