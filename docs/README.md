# OpenMoat documentation

[README](../README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/) · [Changelog](../CHANGELOG.md)

Start with the top-level [README](../README.md) for what OpenMoat is. Step-by-step
guides for common situations (a blocked call, a site to allow, a token to protect) are
on [openmoat.dev/docs](https://openmoat.dev/docs/). The documents here are the full
reference, and they describe the code on `main`.

## Use OpenMoat

| Goal | Start here |
|---|---|
| Install on macOS, Linux or Windows, run `moat init`, see what each agent's hook covers, use other config directories | [INSTALL.md](INSTALL.md) |
| Handle a deny or an ask, review what the agent did, change the policy, share rules with a team; every command and exit code | [USAGE.md](USAGE.md) |
| Write or read a policy file: schema, rule kinds, pattern syntax, evaluation order, the default policy | [POLICY.md](POLICY.md) |
| Make the OS enforce the policy: the agents' own sandboxes (Standard tier), `moat run` (Lightweight), `moat run --isolate` (Isolated) | [SANDBOX.md](SANDBOX.md) |
| Run the launch demo in a throwaway home | [DEMO.md](DEMO.md) |

## Understand the protection

| Goal | Start here |
|---|---|
| Know what is defended, how the hook and the OS layers answer each threat class, and the known limits | [THREAT_MODEL.md](THREAT_MODEL.md) |
| See what the OS layer stops in an allowed project script, per OS, and the known gaps (generated; do not edit) | [EVIDENCE.md](EVIDENCE.md) |
| See the conformance fixtures per threat class (generated; do not edit) | [COVERAGE.md](COVERAGE.md) |
| Run the attack and everyday scenarios per agent and read the scorecard | [MOATBENCH.md](MOATBENCH.md) |

## Contribute

| Goal | Start here |
|---|---|
| Find where code lives and how a tool call becomes a decision, a hook response and an audit record | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Add support for another AI coding agent: adapter, installer, fixtures, tests, docs | [ADDING_AN_AGENT.md](ADDING_AN_AGENT.md) |
| Read the decisions that constrain the code | [adr/](adr/README.md) |
| See what exists and what comes next; the live order is issue [#562](https://github.com/crocodile-labs/openmoat/issues/562) | [ROADMAP.md](ROADMAP.md) |

Contributor files live at the repository root: [AGENTS.md](../AGENTS.md) (working
contract), [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md),
[CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) and [CHANGELOG.md](../CHANGELOG.md).

Conventions: documents are updated in the same pull request as the behaviour they
describe. ADRs are immutable and superseded, never edited.
