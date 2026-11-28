# ADR-108: Landlock ABI 10, a protection score, strict mode, and more agents with an `openmoat run` command

Status: accepted, released in 0.26.0 (§7 and §8 in 0.27.0) · Date: 2026-11-22 · Builds on ADR-018 (tiers), ADR-076 (the `openmoat
run` command for hook-only agents), ADR-077 (full boundary), ADR-082 (the Landlock ABI
ladder), ADR-089 (the run's boundary record), ADR-106 (sandboxed start) · Numbered 108:
109 to 114 are taken by changes open at the time of writing

## Context

The design rule is that the shell classifier triages and the operating system is the
boundary. For most agents OpenMoat protects, though, there is no OS boundary by default:
of the agents with a hook, only Claude Code, Codex and the Cursor CLI get a sandbox
`openmoat init` writes. The rest are `hook only`, where an allowed call runs with the
person's permissions and a classifier mistake is a bypass. `openmoat run` confines them,
but only if the person knows to type it, and for three of them (OpenClaw, Qwen Code,
Crush) no command was offered at all.

Where `openmoat run` does confine, four things were missing:

1. **Landlock ABI 10** (Linux 7.2) restricts UDP bind, connect and send. ADR-082 left it
   unused because the `landlock` crate, 0.4.7, could not ask for it. The seccomp filter
   refuses UDP sockets, so nothing was open, but a kernel rule beside the filter is
   what the ladder is for.
2. **No single answer to "how much of the boundary is in force here".** The boundary
   record lists each restriction, but a person reading `openmoat doctor` had to work out
   from several rows whether the Isolated tier, the namespace and the newer Landlock
   steps applied. Other sandboxes (agentsh's `detect`) print one 0 to 100 score with the
   missing parts named.
3. **No way to refuse a run that is weaker than the platform allows.** `require.run:
   full-boundary` (ADR-077) asks for a sandbox and a network of the agent's own, but
   accepts any Landlock ABI from 4; a person who wants every kernel feature or nothing
   could not say so.
4. **Competitors' documented egress gaps** (Coder's agent firewall: UDP, connecting
   to the proxy's port directly, DNS; Vercel's and Anthropic's notes: raw addresses,
   domain fronting, broad allowed hosts such as github.com; the sandbox-runtime advisory
   in which an empty allowlist applied no restriction) had no test named for each.

## Decision

### 1. Landlock ABI 10 is used, beside the seccomp filter

`landlock` moves to 0.4.8 (semver-compatible, same MSRV floor as the workspace; it adds
`ABI::V10`, `AccessNet::BindUdp` and `AccessNet::ConnectSendUdp`, its CHANGELOG). The
run's ruleset handles both UDP rights best-effort and grants no UDP rule, so on a kernel
with ABI 10 every UDP bind, connect and send is refused by Landlock as well as by the
seccomp filter's refusal of UDP sockets. A kernel without ABI 10 drops the rights and
keeps exactly the previous behaviour. The record gains the restriction
`landlock_udp`, applied from `restrict_self` like the other steps.

| ABI | Linux | What `openmoat run` does with it | Without it |
|---|---|---|---|
| 4 | 6.7 | required: files, the proxy's TCP port | refuses to start |
| 5 | 6.10 | not used: the terminal's `ioctl`s must work | seccomp refuses `TIOCSTI`, `TIOCLINUX` |
| 6 | 6.12 | used: abstract Unix sockets and signals scoped | seccomp refuses Unix sockets |
| 7 | 6.15 | not used: kernel audit logging | nothing changes |
| 8 | 7.0 | not used: one ruleset for every thread (the proxy thread must stay outside) | nothing changes |
| 9 | 7.1 | used: pathname Unix sockets made outside refused | seccomp alone |
| 10 | 7.2 | **used: every UDP bind, connect and send refused** | seccomp refuses UDP sockets |
| 11 | 7.3 | nothing to add: `no_new_privs` is set already | nothing changes |
| 12 | 7.4 | not in the crate (0.4.8 knows up to 10) | seccomp refuses new namespaces |

A side effect, stated: on a kernel at exactly ABI 9 the ruleset now asks for rights the
kernel lacks, so Landlock reports it partly enforced and the record shows ABI 9's step
as unknown rather than applied, as it already did for ABI 6 on ABI 6 to 8 kernels. No
run stops for it; strict mode (§3) refuses such a run anyway.

### 2. A protection score

`openmoat_core::boundary::score` weights each kernel feature of the platform so the
weights add up to 100:

| Linux | Weight | Linux | Weight |
|---|---|---|---|
| `landlock_filesystem` | 25 | `landlock_resolve_unix` | 5 |
| `landlock_tcp_port` | 10 | `landlock_udp` | 5 |
| `seccomp` | 15 | `network_namespace` | 15 |
| `no_new_privs` | 5 | `isolated_view` | 15 |
| `landlock_scopes` | 5 | | |

On macOS the Seatbelt profile is the whole 100 (files, the proxy's address alone and the
Mach services are one profile). Elsewhere `openmoat run` has no sandbox and the score is
0. The hook alone scores 0.

A feature counts when the system has it and the run asks for it; once the agent started,
only when the launch confirmed it (`applied` or `tested` true; Seatbelt counts once
`sandbox-exec` started the program, since it refuses to start one it cannot confine).
Every feature not in force is named with why (not on this system, not asked for by this
run, reported off, not confirmed) and what brings it (the Landlock ABI and Linux
release, bubblewrap, `--isolate`). The score is a field of the boundary record
(`score`, optional, so older rows still read), so `--print-boundary`, `--verbose` and the
audit row carry it, and `openmoat doctor` prints one line per tier this system can start
(Isolated, Lightweight) and one for the hook alone. Weights favour what closes the most:
the file rules and the seccomp filter, then the network, then the view of the machine,
then the newer Landlock steps, which each stand beside a seccomp rule already.

A score compares runs on one operating system, not operating systems.

### 3. `sandbox.strict: true` fails closed

A new `sandbox.strict` (default false), read from the person's own policy only (a
repository policy or pack with `sandbox:` is refused, so a project can neither set it
nor clear it). With it, `openmoat run`:

- refuses before anything starts when the planned score is not 100, naming what is
  missing (exit 64);
- `--print-boundary` prints the plan, then refuses the same way;
- after the start, adds an incomplete confirmed score to what stops the agent and its
  processes, with a `deny` boundary row.

No score is an incomplete one. On Linux this means the Isolated tier on Landlock ABI 10
or later: on today's common kernels strict mode refuses every run, which is its purpose.
`require.run: full-boundary` stays the lighter, repository-settable requirement.

### 4. An empty allowlist is no network

Tests pin the sandbox-runtime advisory's case shut at every layer: the proxy refuses
every name and address (in every spelling: dotted, decimal, hex, IPv6, a subdomain
carrying data) under six ways of listing nothing; Landlock's only TCP port is the
proxy's whatever the policy says; Claude Code's settings get `allowedDomains: []` with
`strictAllowlist: true`, never a missing list.

### 5. Three agents' facts, and saying "hook only" out loud

- **Qwen Code**: `RunFacts::Known { program: "qwen", writes: [ConfigDir] }`. Its settings
  reference (`docs/users/configuration/settings.md` in QwenLM/qwen-code) names
  `~/.qwen` for settings, `file-history/`, chat recordings and locales; system files are
  only read.
- **Crush**: `RunFacts::Known { program: "crush", writes: [~/.local/share/crush,
  ~/.cache/crush] }`. Its README ("Data directories such as `~/.local/share/crush` … contain
  JSON state only") and `internal/config/load.go` (`GlobalConfigData()`,
  `GlobalCacheDir()`: `~/.cache/crush` on every Unix, macOS too); logs and database are
  in the project's `.crush`. The global `crush.json`, which holds OpenMoat's hook, is not
  granted. `run_env` gets the README's non-cloud provider keys and Crush's own
  directory variables.
- **OpenClaw** stays `Unknown`: its Gateway is a long-running service on a local port
  that the person's other clients connect to. `openmoat run` grants no listening
  socket, and inside a network namespace the port would be unreachable from outside, so
  a confined Gateway is either refused or useless. Confining it needs an inbound-port
  fact and a decision about which clients may reach a sandboxed service: a later change.

Nothing turns on silently. Sandboxed start stays an opt-in question (ADR-106); `openmoat
init` now names, per agent, that it is hook only and what typing its name would do, and
says after a no that `openmoat status` has the command. `openmoat status` lists each
hook-only agent with a command and no shim under `Needs your attention`, with that one
command as the fix; a warning, so the status stays healthy.

### 6. Competitors' documented bypasses, each a test

| Bypass (who documents it) | Where it is held | Test |
|---|---|---|
| UDP datagram, DNS to any resolver (Coder) | seccomp refuses UDP sockets; Landlock ABI 10; Seatbelt allows only the proxy | e2e `run/bypass` |
| Name lookup without the proxy (Coder `use_real_dns`) | no resolver socket (Linux), no `mDNSResponder` (macOS) | e2e `run/bypass` |
| Direct connection to the proxy's port (Coder landjail) | the proxy serves only requests with the session's credential (ADR-044): 407 | e2e `run/bypass` |
| The proxy's port on another host (Landlock by port) | the network namespace; port-only runs say so and lose `network_namespace` in the score | e2e `run/network`, score |
| Raw address (Vercel) | no allow rule names it: 403 | e2e `run/bypass`, `decide` unit |
| Domain fronting, SNI ≠ CONNECT host (Anthropic) | `proxy-sni` | `tests/proxy/tunnel.rs` (existing) |
| Domain fronting, `Host` ≠ target (plain HTTP and inside a terminated tunnel) | refused before forwarding | `request` unit (new), `exchange/tests/attacks.rs` (existing) |
| Exfiltration through an allowed broad host (github.com gists, issues) | `requests:` rules, every spelling and override | `requests/tests.rs`, `exchange/tests/attacks.rs` (existing) |
| Empty allowlist means all (sandbox-runtime advisory) | §4 | `decide`, Landlock and Claude Code unit tests |

Every one held before this change; none needed a fix in the proxy.

### 7. One loopback port to listen on: OpenClaw under `openmoat run`

*Added 2026-11-23, before this ADR was accepted; it replaces §5's "OpenClaw stays
`Unknown`".*

OpenClaw's tools run in its Gateway, a long-running server on one local port. Its
documentation (<https://docs.openclaw.ai/gateway>) gives the port's order: "`--port` →
`OPENCLAW_GATEWAY_PORT` → `gateway.port` → named-profile default → `18789`", and the
default bind mode `loopback`; `openclaw gateway` runs it in the foreground.

- **The fact.** `HostSpec::run_listen: Option<RunListen>` names what listens, the
  default port, the variable, the key in the hook file and the variable under which the
  default is not known (`OPENCLAW_PROFILE`: a named profile derives its port). OpenClaw's
  `RunFacts` become `Known { program: "openclaw", args: ["gateway"], writes: [ConfigDir] }`.
  `openmoat status` resolves the port as OpenClaw does (variable, then `gateway.port` in
  `openclaw.json`, then 18789) and prints `openmoat run --listen 18789 --write
  ~/.openclaw -- openclaw gateway`; with a profile and no port set it offers no command
  and says why. Only ports from 1024 are accepted.
- **The capability.** `openmoat run --listen PORT` lets the confined processes bind and
  accept on that one port, on loopback only. They may still connect only to the proxy:
  not to the listened port, so a command cannot drive the Gateway through it.
  - macOS: refused. The Seatbelt rules `(allow network-bind (local ip "localhost:PORT"))`
    and `(allow network-inbound (local ip "localhost:PORT"))` were meant to keep the port
    to loopback, but the end-to-end test on macOS 15 showed a bind to `0.0.0.0` on the
    port going through too, so the port could be reachable from the network, as with
    Landlock alone below. `openmoat run --listen` refuses on macOS, and `status` offers
    no command for OpenClaw there, until a profile can hold the port to loopback.
  - Linux, with a network namespace (the Isolated tier, and the Lightweight tier where
    bubblewrap works): Landlock ABI 4 grants `BindTcp` on that port alone. The
    namespace's only interface is its loopback, so whatever address the Gateway binds
    there is reachable from nowhere else. `openmoat run` listens on this machine's
    `127.0.0.1:PORT` and hands each connection to `moat isolated` inside through a Unix
    socket in the session's private directory; `moat isolated` connects to the port on
    the namespace's loopback. The agent's seccomp filter refuses it any Unix socket, so
    only `moat isolated` uses that socket. A port already in use outside stops the run
    before the agent starts.
  - Linux without a namespace (port-only network): refused. Landlock restricts a bind by
    port only, on every address, so the port would be open to the network.
  - Windows: refused; the tier holds the network by the proxy variables alone (ADR-115).
- **Clients.** The Gateway's clients (the browser Control UI, the apps, `openclaw tui`
  started outside) reach it on loopback as before. A client started inside the same or
  another `openmoat run` cannot: the sandbox reaches the proxy alone, and the proxy
  refuses loopback. So a sandboxed-start shim for a host with `run_listen` confines its
  serving command alone (`openclaw gateway`, with or without options); every other
  `openclaw` command starts the real program as before. The browser tool's control
  service listens on a port of its own and is not granted: it does not start inside
  `openmoat run`. A Gateway installed as a service (`openclaw onboard --install-daemon`)
  is started by launchd or systemd, not by the shim, and runs with the hook only.
- **Attack tests.** Unit: the profile has one bind and one inbound rule, for
  `localhost:PORT`, and still one outbound rule, for the proxy; Landlock's rules carry the
  bind port alone; the forward relays both ways and refuses a port in use. End to end
  (Linux CI): inside `openmoat run --listen`, a bind to the port on `127.0.0.1` works,
  and a bind to another port and a connection to the port are refused; on macOS
  `--listen` itself is refused.

### 8. Confining by default is asked, per agent

*Added 2026-11-23.* Of the 14 agents, 11 are hook only by default. Sandboxed start (ADR-106)
stays opt-in, default no, never silent:

- **`openmoat init`**, of a person at a terminal (the same conditions as ADR-106 §1),
  says once why hook only is a gap and asks per agent, with the score difference this
  system gives (§2):

  ```
    Sandboxed start  these agents run with the hook only: an allowed call runs with your permissions, so a classifier mistake is a bypass. `openmoat run` confines them; a yes writes a shim to ~/.moat/bin and, once, 2 lines to ~/.zshrc
    Gemini CLI       hook only 0/100 → openmoat run 100/100: typing `gemini` starts it confined?  [y/N/d]
    OpenClaw         hook only 0/100 → openmoat run 100/100: typing `openclaw gateway` starts its Gateway confined; its other commands start as before?  [y/N/d]
  ```

  Only `y` or `yes` is a yes; `d` shows that agent's shim and the start-up file's lines.
  `--yes`, `--hooks-only`, `--format json`, a dry run and unattended runs are never asked
  and change nothing, as before.
- **`openmoat confine <agent>…|--all`** does the same later. Typing it is the yes; it
  prints the score difference and every file it writes, then re-pins the lock (the
  shims are state files). `openmoat confine --off <agent>…|--all` deletes the shims that
  are still as written, and the `PATH` lines with the last. Both are person-only: refused
  from an agent, without a terminal and over a drifted lock, as every command that
  re-pins is. An agent that cannot be confined is named with why (its own sandbox, not
  set up, no command, not on `PATH`); with nothing done for named agents the exit is 64.
- **`openmoat status` and `openmoat doctor`** add the score to each hook-only agent's
  row in `Agents`: `protection 0/100` for the hook alone, `protection N/100 with
  sandboxed start` when this shell finds its shim first. Agents with their own sandbox
  from OpenMoat keep their row: this score measures `openmoat run`. `--format json`
  carries it as `score: {points, sandboxed_start}`.

## Consequences

- One more restriction (`landlock_udp`) and an optional `score` in the boundary record's
  JSON; `VERSION` stays 1 since fields are only added.
- Strict mode refuses most Linux systems today. It is opt-in, documented as such, and the
  refusal names the kernel release that would satisfy it.
- `openmoat status` shows a warning for every hook-only agent with a command until the
  person confines it or sets up sandboxed start: more text in `status` for people who
  chose the hook alone. It is a warning, never a failure.
- The ladder test (`the_ladder_matches_the_landlock_crate`) fails again when the crate
  learns ABI 11 or 12, as it should.
- Qwen Code's and Crush's directories come from documentation and source, not a real run;
  a directory they write that is not named shows up as a refused write.
