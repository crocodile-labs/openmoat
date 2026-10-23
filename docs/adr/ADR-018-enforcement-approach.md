# ADR-018: Enforcement tiers: the host's sandbox by default, isolation for strict

Status: accepted · Date: 2026-10-06 · Decided by the maintainer · Refines the `moat exec` part of ADR-003 and the beta scope of ADR-013

## Context

ADR-003 planned enforcement as `moat exec`: rewrite each allowed shell command so it runs
under a Seatbelt or Landlock profile derived from the policy. A decision on a command string
cannot see what `npm test`, `cargo build` (`build.rs`), `make` or `conftest.py` run, so only an
OS boundary stops a malicious project script.

**The sandbox spike** (#119, evidence in `spikes/sandbox/`, macOS 26.7, Claude Code 2.1.290,
codex-cli 0.160.0) found four things:

1. **Seatbelt does not nest.** A process already in a sandbox can apply only a profile that
   compiles to the policy it already has; any other profile fails with
   `sandbox_apply: Operation not permitted`. This holds inside `codex sandbox`, and in reverse:
   Claude Code's sandbox cannot start inside a moat profile. So `moat exec` cannot run while
   either host's sandbox is on.
2. **A Seatbelt profile generated from the default policy works around a whole agent.** It
   confined Claude Code and every script it started. Seatbelt cannot name hosts, so egress needs
   a proxy. The agent and its scripts also share one profile: what the agent needs, every script
   gets.
3. **Both hosts' sandboxes can be configured from the policy, but their defaults leak.** Codex's
   built-in `workspace-write` lets `npm test` read `~/.ssh` and `~/.aws`. Generated
   configurations blocked every payload: Codex `[permissions]` plus its network proxy, and
   Claude Code's `sandbox` settings. The translation is lossy in places, and it has silent
   traps that a generator must handle.
4. **Claude Code's sandbox covers only `Bash`, `PowerShell` and `Monitor`.** Its file tools, web
   tools, MCP servers and hooks run outside it.

**A competitor review** (2026-10-06, primary sources) found:

- OpenShell, Docker Sandboxes, OpenHands and OpenClaw all isolate the whole agent in a
  container or a VM for their strict mode.
- Codex abandoned Landlock-only isolation for bubblewrap.
- The hosts' own sandboxes are patched quickly but have a steady CVE history: symlink and
  worktree escapes, and a sandbox escape by writing settings.

## Decision

Three tiers, all generated from the one policy (ADR-019):

**Standard (default): the host's own sandbox, configured by moat.**
- `moat init` and `moat sandbox sync` write each host's sandbox configuration from the policy:
  - **Claude Code** gets the `sandbox` block with `enabled`, `failIfUnavailable: true`,
    `allowUnsandboxedCommands: false`, `excludedCommands: []`, filesystem deny and allow lists
    with absolute anchors, `network.allowedDomains`, `strictAllowlist: true`, and
    `httpProxyPort` pointing at `moat proxy`.
  - **Codex** gets a `[permissions.moat]` profile, set as `default_permissions`, with its domain
    rules.
- The generated files are pinned in `policy.lock` (ADR-006), so drift is `kernel-integrity`.
  `moat doctor` flags any weakened setting.
- moat's hooks remain the per-call decision layer for everything the host sandbox does not
  cover: file tools, web fetch, MCP, `ask`, shell semantics.

**Isolated: `moat run --isolate -- <agent>`.**
- The agent runs in a Linux guest: a rootless container on Linux (Podman, or Docker), and a
  lightweight VM on macOS (Apple Virtualization).
- `moat`'s kernel, the egress proxy and the secrets broker (ADR-020) run on the host, outside
  the guest. The guest's only network route is the proxy.
- Inside the guest, the agent's own sandbox stays on and is configured as in Standard. On Linux
  it is bubblewrap inside the guest, so it nests.
- This is the strict tier and the one the beta's security claims are measured on.

**Lightweight: `moat run -- <agent>` without a runtime.**
- A generated Seatbelt profile (macOS) or Landlock and seccomp (Linux) around the agent
  process, with the proxy as the only exit.
- The host's sandbox must be off inside it on macOS, so this tier is documented as weaker per
  command than Standard plus Isolated. It is for machines without a container or VM runtime.

**Per-command `moat exec`** remains only for hosts without a sandbox of their own (OpenCode, and
Cursor until verified).

**What every tier keeps decide-only:**
- `shell` semantics (destructive git, push, installs, `sudo`)
- `mcp` rules
- `executables` pins
- `ask`
- Claude Code's in-process tools, which only the hooks see (and the guest boundary, in
  Isolated)

**Hooks are written so a host's parser cannot turn a block into a run:**
- An `ask` that a host cannot express is sent as a deny. Codex is the case today: #166.
- An `allow` never depends on the host accepting a document.

## Consequences

- Enforcement reaches users without changing how they start their agent (Standard). A stronger
  boundary is one flag away (Isolated).
- Standard is as strong as the host's sandbox and our translation. Every host version bump must
  pass the executing differential fixtures (ADR-019). A renamed key fails `moat doctor` instead
  of passing silently.
- Isolated costs a runtime dependency and about a second of start-up, and fits IDE agents
  (Cursor) less well. It gives the same boundary on every OS and removes the nesting problem.
- Translation losses in Standard are stated in THREAT_MODEL:
  - Codex cannot re-allow `.env.example` inside a deny glob.
  - Codex cannot express `**/` outside known roots.
  - Codex makes all of `.git` read-only.
- Apple has deprecated `sandbox-exec`. Codex, Claude Code and Chromium still depend on it.
  Isolated does not.
- Open risks:
  - Covert channels through allowlisted hosts.
  - Proxy-unaware tools lose network.
  - Reads outside the project stay open in Standard until the policy lists them (browser
    profiles, cookies). Isolated closes them by not mounting them.
  - In Lightweight, keychain access must never be granted.
