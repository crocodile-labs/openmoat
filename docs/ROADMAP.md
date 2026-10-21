# Roadmap

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know what exists today and what comes next, in order.

**On this page:** [Where it is today](#where-it-is-today) · [Next](#next) · [Positioning](#positioning) · [Stages](#stages) · [The team wedge](#the-team-wedge) · [Not planned](#not-planned)

Where OpenMoat is, what comes next, and in which order. The release stages and their
exit criteria come from ADR-013. The live, ordered work list is the roadmap issue
[#562](https://github.com/crocodile-labs/openmoat/issues/562), and each stage is a
GitHub milestone. Neither carries dates.

## Where it is today

The latest release is `0.8.0` (stable), from GitHub Releases, the Homebrew tap and
crates.io (README, Install). What exists:

- One policy for Claude Code, Codex, Cursor and OpenClaw, checked through each host's own
  hooks (OpenClaw's through a `before_tool_call` plugin, ADR-033).
- Policy kinds `shell`, `fs.read`, `fs.write`, `net`, `fetch`, `env.read`, `env.set`, `mcp`,
  `web.search` and `tool.unknown`, and four verdicts: `allow`, `defer` (the agent's own
  prompt decides, the default for anything no rule names, ADR-025), `ask` and `deny`.
- An own POSIX lexer and shell classifier, executable pins (ADR-008) and symlink
  resolution (ADR-009).
- A redacted, hash-chained local audit log with `show`, `replay` and `report`, and
  `openmoat audit export`, `verify` and `report` for a team (#129).
- Approvals through `openmoat allow` (ADR-007).
- Self-protection: a policy lock checked on every call (ADR-006), `kernel-self`
  rules, the Claude Code `ConfigChange` veto, and stable hook binary paths (ADR-016).
- Session taint: after a secret read or untrusted content, risky follow-up calls ask
  (ADR-020), and it follows the files a tainted session writes (file provenance,
  ADR-029).
- Package installs: a name one typo away from a popular package asks
  (`package-near-miss`, ADR-030), and `openmoat run` keeps npm and uv off versions
  published in the last 7 days.
- MCP: the policy lock pins each MCP server definition the agents read, and
  `openmoat mcp proxy` runs a stdio server through OpenMoat with its tools pinned, holding
  a new server's tools until `openmoat mcp accept` (ADR-026, ADR-032).
- Audit anchors: `openmoat audit anchor` records the log's head in a git repository or a
  file you keep, and `openmoat audit verify --against` checks the log against them
  (ADR-031).
- Signed policy packs: `openmoat policy trust-key`, `install` and `remove`, verified with
  OpenSSH signatures (ADR-031).
- Repository policy (`<repo>/.moat/policy.yaml`) that only tightens until `openmoat trust`
  (ADR-022).
- Standard tier: Claude Code's, Codex's and Cursor's own sandboxes configured and
  pinned from the policy (ADR-018), and a protection level per agent in `openmoat status`.
- Lightweight tier: `openmoat run` with a generated Seatbelt profile (macOS), or Landlock
  rules and a seccomp filter (Linux), around the whole agent. On Linux it does not
  protect paths inside the project (`.env`, `.git`, `.moat`); `openmoat run --isolate`
  does.
- Isolated tier on Linux: `openmoat run --isolate` starts the agent under bubblewrap in
  new namespaces, rootless (ADR-018). On macOS it refuses until ADR-023 is built.
- `openmoat proxy`: default-deny egress with an SNI check, its own DNS and an audit row
  per connection, and a secrets broker that blocks a brokered secret on its way to the
  wrong host (ADR-020). HTTPS injection is not built yet (#247).
- Fail-closed exit codes (ADR-004, ADR-015), a conformance suite tagged by threat
  ([COVERAGE.md](COVERAGE.md)), a differential suite across the hook and the host
  sandboxes with hostile project scripts ([EVIDENCE.md](EVIDENCE.md)), MoatBench mini,
  and fuzz targets that run in CI.

What it does not do: confine every call. Only commands inside the host sandboxes or
`openmoat run` are confined by the operating system. Elsewhere an allowed call runs with
your permissions and the hook's decision is the only check, so a classifier mistake is
a security bug ([THREAT_MODEL.md](THREAT_MODEL.md) §5).

## Next

0.5.0 was the first stable release with the quiet default. What comes next is making
it solid end to end in daily use, in the order of
[#562](https://github.com/crocodile-labs/openmoat/issues/562):

- OpenClaw support (0.7.0);
- a first run a person can follow and trust: `openmoat init` shows each change and asks,
  and messages and help use plain words;
- installed copies stay current: `openmoat status` says when a policy update or drift
  needs a person;
- the gaps in what each agent's hook shows OpenMoat, and the hardening items found in
  review, each with a fixture;
- the maintainer's own daily use continues: every false positive becomes a fixture and
  a fix.

People outside the project, the bypass round (#131) and the public challenge (#323)
follow once these are done.

## Positioning

The shell classifier triages and the operating system is the boundary. A policy
decision on a command string can be wrong (quoting, encodings, interpreters, programs
that run other programs), and no amount of parser work closes that gap. So:

- Where no OS layer applies (Claude Code's and Cursor's file tools, `WebFetch` and MCP
  calls, and commands Cursor runs outside its sandbox, unless the agent runs under
  `openmoat run`), the classifier is the only layer.
  Bypass reports are in scope ([SECURITY.md](../SECURITY.md)) and become fixtures.
- The parser is frozen (AGENTS.md §5, CONTRIBUTING.md "Decisions"). A newly found
  bypass gets an attack fixture and the smallest change that turns it into `ask`, not
  a new grammar. The time saved goes into enforcement.
- From the beta on, allowed commands run under OS enforcement derived from the same
  policy. A parser mistake then costs a prompt or a confusing message, not a breach.
  Every layer is generated from the one policy and the layers are tested against each
  other (ADR-018 to ADR-020): the host's own sandbox, configured and pinned by OpenMoat,
  by default; a container or VM with OpenMoat outside it for strict use (planned); one
  egress proxy and a secrets broker so the agent never holds credentials.

## Stages

### Alpha: `0.1.0-alpha.N`

Milestone `v0.1.0-alpha`. Released from `0.1.0-alpha.0` on, with the release workflow
and attestations (#89), the tag ruleset (#91), the guard latency budget (#95) and the
host and CLI follow-ups (#137–#143).

| Issue | Still open |
|---|---|
| #124 | A week of daily use by the maintainer, every false positive turned into a fixture |
| #138 | Cursor `Grep` and `Glob` tool names checked against a real Cursor payload |

Exit (ADR-013): installs from a tag on every target, the conformance suite green on
every CI platform, and a week of daily use with every false positive turned into a
fixture.

ADR-013 also listed a conservative PowerShell tokenizer under the alpha. It has no
issue yet; until one lands, Claude Code `PowerShell` is `unparseable`, which the default
policy defers to the agent's own prompt.

### Beta: `0.1.0-beta.N`, enforcement

Milestone `v0.1.0-beta`.

| Issue | Done |
|---|---|
| #119 | Spike: Seatbelt does not nest, host defaults leak; outcome in ADR-018 |
| #168, #169, #324 | Standard tier: generated and pinned Claude Code, Codex and Cursor sandbox settings (ADR-018) |
| #176 | Lightweight tier: `openmoat run` with generated Seatbelt, or Landlock and seccomp |
| #170, #335, #346 | Executing differential fixtures across the hook and the host sandboxes, and hostile project scripts under every OS layer ([EVIDENCE.md](EVIDENCE.md)) |
| #171, #172, #173 | `openmoat proxy` (default deny, SNI, own DNS), secrets broker, minimal session taint (ADR-020) |
| #177, #129 | Hash-chained audit log; audit export and a team report |
| #128 | Repository policy (`<repo>/.moat/policy.yaml`) and `openmoat trust` |
| #178 | Codex `PermissionRequest`: investigated; Codex runs that hook only after it decides to prompt, so a Codex `ask` stays a deny (ARCHITECTURE §5) |
| #132, #336, #337 | MoatBench mini, the developer-workflow suite and the host failure matrix |
| #334 | A protection level per agent in `openmoat status` and `openmoat doctor` |
| #167 | Policy compiler (ADR-019): the IR, `openmoat policy compile` and the "never widens" tests |
| #356 | Beta gate: every protection claim has executable evidence |
| #321, #322 | Landing page ([openmoat.dev](https://openmoat.dev)) and the first non-pre-release |

| Issue | Open |
|---|---|
| #131, #323 | Bypass challenge with security people, then a public challenge and the announcement (on hold until the work in "Next" above is done) |

Exit (ADR-013): executing fixtures show obfuscated exfiltration failing at the OS
level, and read-then-exfiltrate fixtures are blocked.

### 1.0

Milestone `v1.0.0`.

| Issue | Work |
|---|---|
| #320 | `openmoat serve` |
| #135 | Windows enforcement |
| #136 | Stable policy schema and `openmoat policy migrate` |
| #175 | Isolated tier on macOS: `openmoat run --isolate` in an Apple Virtualization guest (ADR-023) |

| Issue | Done |
|---|---|
| #133 | `openmoat mcp proxy`: MCP stdio proxy with tool description pinning, for hosts whose hooks skip MCP (0.5.7) |
| #134 | OpenClaw plugin (0.7.0) |
| #136 | Signed policy packs (0.6.0) |
| #174 | Isolated tier on Linux: `openmoat run --isolate` under bubblewrap (0.1.1) |
| #363 | Policy secrets compiled into Claude Code's credential masking (0.2.0) |

Exit (ADR-013): MoatBench meets its gate and the policy schema is stable.

### More agents

Tracking issue #267 lists every agent checked, with the hook API each one offers.
Until an agent has an adapter, `openmoat run` can still sandbox it.

| Issue | Agent | Hook it would use |
|---|---|---|
| #264 | Continue CLI (`cn`) | Claude Code-compatible `PreToolUse`. Security: `cn` already loads OpenMoat's Claude Code hooks but ignores `ask` |
| #257 | Gemini CLI | `BeforeTool` |
| #258 | GitHub Copilot (CLI, cloud agent, VS Code) | `preToolUse` in `.github/hooks` |
| #259 | Windsurf | `pre_run_command`, `pre_read_code`, `pre_write_code`, `pre_mcp_tool_use` |
| #260 | Cline | `PreToolUse` script hook |
| #261 | Kiro | `PreToolUse` command hook |
| #262 | Amp | plugin `tool.call` event |
| #263 | goose | `PreToolUse` |
| #265 | OpenCode | plugin `tool.execute.before` and `permission.ask` |
| #266 | Junie (CLI) | `PreToolUse` |

Aider and the Zed agent have no pre-execution hook, and Roo Code has shut down; use
`openmoat run` for those.

## The team wedge

A team gets value when one policy and one record cover everyone's agents:

1. **Repo policy** (#128). A committed `.moat/policy.yaml` adds rules for everyone who
   works in the repository, whatever agent they use. A cloned repository must not be
   able to loosen a person's policy, so by itself it only adds deny and ask rules; its
   allow rules load only after `openmoat trust <path>` pins the file by hash (ADR-022).
2. **Audit export** (#129). Decisions exported in a stable format, plus a team report
   built from them.

Both exist on `main`: `openmoat trust` for repository policy, and `openmoat audit export`,
`verify` and `report` for a team report over several machines.

## Not planned

- A chat assistant, channel integration, memory system, skills marketplace or UI.
- A model runtime. The kernel does not know which model is running.
- A new tool protocol. MCP is the protocol.
- A replacement for VM or container isolation of whole workloads. OpenMoat composes with them.
- Model-based decisions or intent detection. Decisions are deterministic rules over
  actions.
- Agents that run in a vendor's cloud rather than on the machine OpenMoat runs on.
