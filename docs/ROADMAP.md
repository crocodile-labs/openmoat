# Roadmap

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know what exists today, what comes next and what is not planned.

**On this page:** [Where it is today](#where-it-is-today) · [Next](#next) · [Later](#later) · [More agents](#more-agents) · [Not planned](#not-planned) · [How OpenMoat is built to grow](#how-openmoat-is-built-to-grow)

The live, ordered work list is the roadmap issue
[#562](https://github.com/crocodile-labs/openmoat/issues/562). Neither it nor this page
carries dates. Release stages and their exit criteria come from ADR-013.

## Where it is today

The latest release is `0.20.0`, from GitHub Releases, the Homebrew tap and crates.io
([INSTALL.md](INSTALL.md)).

**Release stage:** 0.x, usable daily, before 1.0. ADR-013's first two stages are
complete: installers for every target with the conformance suite green on every CI
platform and false positives from daily use turned into fixtures, then enforcement
(`openmoat run` with Seatbelt and Landlock + seccomp, the egress proxy, session taint,
the MCP proxy with description pinning) shown by the executing fixtures in
[EVIDENCE.md](EVIDENCE.md), where exfiltration fails at the OS level. What 1.0 still
needs, as ADR-013 sets it: a stable policy schema with `openmoat policy migrate` (#136)
and MoatBench meeting a 1.0 gate; the third, `openmoat serve` (#320), is built (ADR-066). [MOATBENCH.md](MOATBENCH.md)
defines the gate CI applies today (every bundled scenario decided as expected, with no
false positive, on every platform); the threshold 1.0 asks beyond that is not yet set.
What exists:

- **Agents.** One policy for Claude Code, Codex, Cursor, OpenClaw (a `before_tool_call`
  plugin, ADR-033), GitHub Copilot CLI, pi (an extension), Gemini CLI, OpenCode 1 and 2
  (one plugin on `tool.execute.before` and `execute.before`, ADR-040), Hermes Agent (a
  `pre_tool_call` shell hook, approved in its hook allowlist), the Cline CLI (`PreToolUse`
  and `PostToolUse` hook scripts) and goose (a `PreToolUse` hook in a plugin), each through
  its own hooks; the Continue CLI adapter waits for a `cn` release that runs hooks. Claude
  Code in the VS Code extension and the JetBrains plugin goes through the same hook, and
  Cursor's Tab reads through `beforeTabFileRead` (ADR-060, [IDE.md](IDE.md)).
- **Policy.** Kinds `shell`, `fs.read`, `fs.write`, `net`, `fetch`, `env.read`, `env.set`,
  `mcp`, `web.search` and `tool.unknown`; verdicts `allow`, `defer` (the default for
  anything no rule names, ADR-025), `review` and `deny`.
- **Shell parsing.** OpenMoat's own POSIX lexer and classifier, executable pins
  (ADR-008) and symlink resolution (ADR-009).
- **Audit.** A redacted, hash-chained local log with `show`, `replay` and `report`;
  `openmoat audit export`, `verify` and `report` for a team; audit anchors (ADR-031);
  `openmoat watch` follows the log live and `openmoat why` explains one decision.
- **Block messages.** A deny or review from a rule with a `title` tells the agent and the
  person what was stopped, why and the next step; every default deny and review rule has
  one (ADR-059).
- **Compliance evidence.** `openmoat audit evidence` reports the log per control of
  OWASP LLM 2025, SOC 2 and ISO/IEC 27001 (ADR-051, [COMPLIANCE.md](COMPLIANCE.md)).
- **Merge check.** `openmoat policy check-diff` and a composite GitHub Action report a
  pull request's changes to protected files and added tokens (ADR-050), and what its
  added lines do: supply chain, CI takeover, decoded or downloaded code that runs,
  private keys and new hosts, each level set by `check_diff.levels` (ADR-055,
  [MERGE_CHECK.md](MERGE_CHECK.md)).
- **Provenance.** `openmoat provenance` attributes a commit's files and lines to agent
  sessions from the audit log, keeps notes on `refs/notes/openmoat` and verifies them;
  `check-diff` shows them (ADR-056, [PROVENANCE.md](PROVENANCE.md)).
- **Approvals.** `openmoat allow` for a command, a site or a directory (ADR-007).
- **Self-protection.** A policy lock checked on every call (ADR-006), `kernel-self`
  rules, Claude Code's `ConfigChange` veto, stable hook binary paths (ADR-016), and
  person-only commands that refuse when an agent is among their parent processes.
- **Session taint.** After a secret read or untrusted content, risky follow-up calls
  need review (ADR-020), also across the files a tainted session writes (ADR-029); after a
  secret read, a URL carrying a long encoded value is denied (`encoded-egress`, ADR-047).
  A payment card number sent off the machine is denied (`card-egress`, ADR-052). With
  Claude Code, the Cline CLI and wrapped MCP servers, a later command or write that uses
  a host, path or command untrusted output named needs review (`injected-input`,
  ADR-057), also in another spelling of the same request (ADR-063, proposed). A send after the session collected
  files outside the project is recorded and counted in `openmoat report`, with no
  verdict yet (ADR-061, proposed).
- **Package installs.** A name one typo away from a popular package needs review (ADR-030);
  `openmoat run` keeps npm and uv off versions published in the last 7 days.
- **MCP.** Server definitions pinned in the lock (ADR-026); `openmoat mcp proxy`, opt-in
  per server with `openmoat mcp wrap` or `openmoat init --mcp-proxy`, pins
  each tool's description and holds a new server's tools until `openmoat mcp accept`
  (ADR-032), and is a gateway: it passes only the messages it checked and rewrote itself,
  and a call only when the policy does not deny it as the server receives it and the
  agent's hook decided exactly that call (ADR-045). A browser MCP call that only opens a
  page is a `fetch`, judged by every host a client may read its URL as (ADR-047). Text
  one wrapped server returned that reaches another server's acting tool needs review
  (`mcp-cross-server`, ADR-058).
- **Signed policy packs.** `openmoat policy trust-key`, `install` and `remove`, verified
  with OpenSSH signatures (ADR-031).
- **Repository policy.** `<repo>/.moat/policy.yaml` only tightens until `openmoat trust`
  (ADR-022).
- **Standard tier.** Claude Code's, Codex's and Cursor's own sandboxes configured and
  pinned from the policy (ADR-018), and a protection level per agent in `openmoat status`.
  Every sandbox denies the agents' logins to the commands they run (ADR-054).
- **Lightweight tier.** `openmoat run`: Seatbelt on macOS 13 or later, Landlock and seccomp
  on Linux, around the whole agent.
- **Isolated tier on Linux.** `openmoat run --isolate` under bubblewrap, rootless.
- **Egress proxy.** `openmoat proxy`: default deny, SNI check, its own DNS, an audit
  row per connection, a secrets broker, and a user service on macOS and Linux. It serves
  agent sessions only: `openmoat run`'s proxy issues its run's credentials (ADR-027), and
  the standalone proxy the host sandboxes use accepts the ones Claude Code's
  `SessionStart` hook issues, so each request carries its session's taint and share of
  the connections (#558, ADR-044). Inside `openmoat run`, a brokered secret with
  `tls: terminate` is injected into HTTPS requests, and only into the requests its
  `allow` rules name (ADR-043).
- **Evidence.** A conformance suite tagged by threat ([COVERAGE.md](COVERAGE.md)), a
  differential suite across the hook and the host sandboxes ([EVIDENCE.md](EVIDENCE.md)),
  MoatBench ([MOATBENCH.md](MOATBENCH.md)) and fuzz targets.
- **SDK.** `openmoat-sdk` for Rust and `@openmoat/sdk` for JavaScript (the engine as
  WebAssembly): the same decisions inside your own agent product, which enforces them
  (ADR-046, [SDK.md](SDK.md)). `openmoat-sdk` is on crates.io from 0.12.0; from
  0.16.0 `@openmoat/sdk` is published to npm by the release workflow, at the same version.

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
- A bypass round with security people (#131); the public challenge is open
  ([CHALLENGE.md](CHALLENGE.md), #323).
- The proposed ADRs' next steps: a default `staging-egress` rule once `openmoat report`
  has measured real sessions (ADR-061); method and path rules (`requests:`) for allowed
  hosts (ADR-062); after-call hooks of more agents, each once a real payload is captured
  (ADR-063).

## Later

Planned for 1.0 or after, not yet scheduled:

- Windows enforcement: an OS sandbox on Windows (#135).
- A user service for `openmoat proxy` on Windows (#272).
- A stable policy schema and `openmoat policy migrate` (#136).
- The Isolated tier on macOS: `openmoat run --isolate` in an Apple Virtualization guest (#175, ADR-023).
- HTTPS injection of brokered secrets in the standalone `openmoat proxy`, and keep-alive
  inside a terminated tunnel; `openmoat run` has both injection and the method and path
  rules (ADR-043, #247).
- A conservative PowerShell tokenizer; until then PowerShell is `unparseable` and defers.
- A scrubbed environment for agent commands (THREAT_MODEL T3).

## More agents

Tracking issue #267 lists every agent checked, with the hook each one offers. Until an
agent has an adapter, `openmoat run` can still sandbox it.

| Issue | Agent | Hook it would use |
|---|---|---|
| #258 | GitHub Copilot cloud agent and VS Code | `preToolUse` in `.github/hooks` |
| #259 | Windsurf | `pre_run_command`, `pre_read_code`, `pre_write_code`, `pre_mcp_tool_use` |
| #261 | Kiro | `PreToolUse` command hook |
| #262 | Amp | plugin `tool.call` event |
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
  gets an attack fixture and the smallest change that turns it into `review`, not a new
  grammar; the time saved goes into enforcement.
- Every enforcement layer is generated from the one policy, and the layers are tested
  against each other (ADR-018 to ADR-020).
- Where no OS layer applies (Claude Code's and Cursor's file tools, `WebFetch`, MCP calls,
  commands Cursor runs outside its sandbox, and every hook-only agent), the classifier is
  the only layer, so bypass reports there are in scope ([SECURITY.md](../SECURITY.md)).
