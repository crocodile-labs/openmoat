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
  cover: file tools, web fetch, MCP, `review`, shell semantics.

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
- `review`
- Claude Code's in-process tools, which only the hooks see (and the guest boundary, in
  Isolated)

**Hooks are written so a host's parser cannot turn a block into a run:**
- A `review` that a host cannot express is sent as a deny. Codex is the case today: #166.
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

## Amendment 2026-11-08: a temp directory of the run's own

`openmoat run` granted its own process's temp directory to commands, read and write. On
Linux that is usually `/tmp` itself, shared with every other program and session of the
user: other tools' state, sockets' folders and Kerberos ticket caches
(`/tmp/krb5cc_<uid>`), which `secrets-paths` did not name.

- Each run now creates `openmoat-run-<random>` (mode `0700`) inside the system's temp
  directory, grants that one alone for writing, gives it to the agent as `TMPDIR` and
  removes it when the run ends. Tools that honour `TMPDIR` keep working; a fixed
  `/tmp/<name>` write fails, as it already did on macOS. Under `--isolate` the temp
  directory is an empty `tmpfs` already and stays so.
- The shared temp directory stays a read root (`/tmp`, `/var/folders`): builds read
  files there that were made outside the run, and narrowing it is left until there is
  evidence of what it breaks.
- A new deny rule, `kerberos-tickets`, names `/tmp/krb5cc_*` and `/tmp/krb5cc_*/**`. It is
  `hook_only` (ADR-034) for the host sandboxes: Codex's Linux sandbox lists every folder
  below a deny glob, and Cursor's would stop granting `/tmp`. `openmoat run` applies it in
  its own sandbox and adds the cache `KRB5CCNAME` names. In the network namespace on Linux, a deny whose glob is
  in the last name only is applied to the entries that exist when the session starts in a
  granted folder (hidden or bound read-only), as a literal path is.

## Amendment 2026-11-08: hook settings that do not exist yet, on Linux

A mount needs a path to cover, so on Linux `openmoat run` protected an agent's hook
settings in the project only where they existed when the agent started. A command could
create `.gemini/settings.json` or `.claude/settings.local.json` with `disableAllHooks`,
and the next session ran without OpenMoat's hook; Seatbelt on macOS denies them by
pattern, existing or not.

- In the network namespace and under `--isolate`, each hook settings file `kernel-self`
  names below a folder (`**/<dir>/<file>`) that is missing directly in the project is
  created for the session, with the folders above it: `{}` for a JSON file, which every
  agent reads as settings that change nothing, an empty folder for `.copilot/hooks`. The
  file is bound read-only and the folders onto themselves, as for an existing one. Each is
  removed when the agent exits while it is still as made. They show in `git status`
  during the session.
- Without a namespace (port-only), nothing can cover them. `openmoat run` notes the gap
  when it starts and, when the agent exits, names each that was missing at the start and
  exists now. Refusing to start there was weighed and not chosen: the port-only mode
  already warns on every start, and a refusal would stop every run on such machines for a
  file most projects never get.

## Amendment 2026-11-09: `openmoat run` leaves the shared temp directories out

`openmoat run` already gave each run a temp directory of its own and no write to the
shared ones, so nothing a command wrote could be there to read back. `/tmp` and
`/var/folders` stayed read roots, which left other programs' files open to commands.

- For the Lightweight tier the sandbox's copy of the policy has `/tmp`, `/private/tmp`,
  `/var/folders` and `/private/var/folders` out of `sandbox.read_roots`
  (`sandbox/shared_temp.rs`). The hook still decides with the whole policy.
- On macOS `/var/folders/*/*/C` and `/var/folders/*/*/0` stay, the per-user cache and
  per-user directory, which system libraries and Apple's tools read whatever `TMPDIR`
  says; `/var/folders/*/*/T`, the temp folder, goes.
- `--isolate` is unchanged: its shared temp directory is an empty `tmpfs` already.
- The host sandboxes keep both roots, which they use as their temp directory.
- On Linux this also closes the ticket caches in `/tmp` where there is no network
  namespace to hide them, since Landlock no longer grants `/tmp`.
- Ticket caches that are no file stay out of reach by what exists already: the seccomp
  filter's Unix-socket and `keyctl` refusals on Linux, the profile's two allowed
  `mach-lookup` services on macOS.
