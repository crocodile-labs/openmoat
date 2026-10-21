# Roadmap

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know what exists today, what comes next and what is not planned.

**On this page:** [Where it is today](#where-it-is-today) · [Next](#next) · [Later](#later) · [More agents](#more-agents) · [Not planned](#not-planned) · [How OpenMoat is built to grow](#how-openmoat-is-built-to-grow)

The live, ordered work list is the roadmap issue
[#562](https://github.com/crocodile-labs/openmoat/issues/562). Neither it nor this page
carries dates. Release stages and their exit criteria come from ADR-013.

## Where it is today

The latest release is `0.9.0`, from GitHub Releases, the Homebrew tap and crates.io
([INSTALL.md](INSTALL.md)). What exists:

- **Agents.** One policy for Claude Code, Codex, Cursor, OpenClaw (a `before_tool_call`
  plugin, ADR-033), GitHub Copilot CLI, pi (an extension) and Gemini CLI, each through
  its own hooks; the Continue CLI adapter waits for a `cn` release that runs hooks.
- **Policy.** Kinds `shell`, `fs.read`, `fs.write`, `net`, `fetch`, `env.read`, `env.set`,
  `mcp`, `web.search` and `tool.unknown`; verdicts `allow`, `defer` (the default for
  anything no rule names, ADR-025), `ask` and `deny`.
- **Shell parsing.** OpenMoat's own POSIX lexer and classifier, executable pins
  (ADR-008) and symlink resolution (ADR-009).
- **Audit.** A redacted, hash-chained local log with `show`, `replay` and `report`;
  `openmoat audit export`, `verify` and `report` for a team; audit anchors (ADR-031).
- **Approvals.** `openmoat allow` for a command, a site or a directory (ADR-007).
- **Self-protection.** A policy lock checked on every call (ADR-006), `kernel-self`
  rules, Claude Code's `ConfigChange` veto, stable hook binary paths (ADR-016), and
  person-only commands that refuse when an agent is among their parent processes.
- **Session taint.** After a secret read or untrusted content, risky follow-up calls
  ask (ADR-020), also across the files a tainted session writes (ADR-029).
- **Package installs.** A name one typo away from a popular package asks (ADR-030);
  `openmoat run` keeps npm and uv off versions published in the last 7 days.
- **MCP.** Server definitions pinned in the lock (ADR-026); `openmoat mcp proxy` pins
  each tool's description and holds a new server's tools until `openmoat mcp accept`
  (ADR-032).
- **Signed policy packs.** `openmoat policy trust-key`, `install` and `remove`, verified
  with OpenSSH signatures (ADR-031).
- **Repository policy.** `<repo>/.moat/policy.yaml` only tightens until `openmoat trust`
  (ADR-022).
- **Standard tier.** Claude Code's, Codex's and Cursor's own sandboxes configured and
  pinned from the policy (ADR-018), and a protection level per agent in `openmoat status`.
- **Lightweight tier.** `openmoat run`: Seatbelt on macOS 13 or later, Landlock and seccomp
  on Linux, around the whole agent.
- **Isolated tier on Linux.** `openmoat run --isolate` under bubblewrap, rootless.
- **Egress proxy.** `openmoat proxy`: default deny, SNI check, its own DNS, an audit
  row per connection, a secrets broker, and a user service on macOS and Linux.
- **Evidence.** A conformance suite tagged by threat ([COVERAGE.md](COVERAGE.md)), a
  differential suite across the hook and the host sandboxes ([EVIDENCE.md](EVIDENCE.md)),
  MoatBench ([MOATBENCH.md](MOATBENCH.md)) and fuzz targets, all run in CI.

What it does not do: confine every call. Only commands inside the host sandboxes or
`openmoat run` are confined by the operating system. Elsewhere an allowed call runs with
your permissions and the hook's decision is the only check
([THREAT_MODEL.md](THREAT_MODEL.md#5-known-limitations)).

## Next

Making what exists solid in daily use, in the order of
[#562](https://github.com/crocodile-labs/openmoat/issues/562):

- Every false positive found in daily use becomes a fixture and a fix.
- The gaps in what each agent's hook shows OpenMoat, closed one at a time, each with a fixture.
- Hardening items found in review, each with a fixture.
- The Continue CLI checked end to end once a released `cn` runs hooks (#264).
- A bypass round with security people (#131), then a public challenge (#323).

## Later

Planned for 1.0 or after, not yet scheduled:

- Windows enforcement: an OS sandbox on Windows (#135).
- A user service for `openmoat proxy` on Windows (#272).
- A stable policy schema and `openmoat policy migrate` (#136).
- The Isolated tier on macOS: `openmoat run --isolate` in an Apple Virtualization guest (#175, ADR-023).
- HTTPS injection of brokered secrets in `openmoat proxy` (#247).
- `openmoat serve` (#320).
- A conservative PowerShell tokenizer; until then PowerShell is `unparseable` and defers.
- A scrubbed environment for agent commands (THREAT_MODEL T3).

## More agents

Tracking issue #267 lists every agent checked, with the hook each one offers. Until an
agent has an adapter, `openmoat run` can still sandbox it.

| Issue | Agent | Hook it would use |
|---|---|---|
| #258 | GitHub Copilot cloud agent and VS Code | `preToolUse` in `.github/hooks` |
| #259 | Windsurf | `pre_run_command`, `pre_read_code`, `pre_write_code`, `pre_mcp_tool_use` |
| #260 | Cline | `PreToolUse` script hook |
| #261 | Kiro | `PreToolUse` command hook |
| #262 | Amp | plugin `tool.call` event |
| #263 | goose | `PreToolUse` |
| #265 | OpenCode | plugin `tool.execute.before` and `permission.ask` |
| #266 | Junie (CLI) | `PreToolUse` |

Aider and the Zed agent have no pre-execution hook, and Roo Code has shut down; use
`openmoat run` for those.

## Not planned

- A chat assistant, channel integration, memory system, skills marketplace or UI.
- A model runtime. OpenMoat does not know which model is running.
- A new tool protocol. MCP is the protocol.
- A replacement for VM or container isolation of whole workloads. OpenMoat works alongside them.
- Model-based decisions or intent detection. Decisions are deterministic rules over actions.
- Agents that run in a vendor's cloud rather than on the machine OpenMoat runs on.

## How OpenMoat is built to grow

The shell classifier triages; the operating system is the boundary. A decision on a
command string can be wrong (quoting, encodings, interpreters, programs that run other
programs), so:

- The parser is frozen (AGENTS.md §5, CONTRIBUTING.md "Decisions"). A newly found bypass
  gets an attack fixture and the smallest change that turns it into `ask`, not a new
  grammar; the time saved goes into enforcement.
- Every enforcement layer is generated from the one policy, and the layers are tested
  against each other (ADR-018 to ADR-020).
- Where no OS layer applies (Claude Code's and Cursor's file tools, `WebFetch`, MCP calls,
  commands Cursor runs outside its sandbox, and every hook-only agent), the classifier is
  the only layer, so bypass reports there are in scope ([SECURITY.md](../SECURITY.md)).
