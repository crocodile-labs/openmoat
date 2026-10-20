# OS sandboxes: Standard, Lightweight and Isolated tiers

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want the operating system to enforce the policy: the agents' own sandboxes (Standard tier), `openmoat run` (Lightweight) and `openmoat run --isolate` (Isolated).

OpenMoat decides each tool call in the agent's hook. The sandboxes below make the operating system enforce the same policy on everything those calls start.

## Host sandboxes (Standard tier)

`openmoat init` also turns on each agent's own sandbox and configures it from the policy
(ADR-018). Commands the agent runs, and every script they start (`npm test`,
`build.rs`, `make`), are then confined by the operating system: no secrets, no reads
outside the project and `sandbox.read_roots`, no writes outside the project, and
network only to allowlisted hosts, through a proxy ([POLICY.md §9](POLICY.md)). On
macOS a write outside the project fails. On Linux both sandboxes build the command's
view of the home in memory, with only the project and the read roots mounted from
disk, so a write elsewhere in the home that is not refused outright (`~/stolen.txt`,
and under Claude Code also `~/.zshrc`) completes in memory and is gone when the
command ends; the file on disk does not change (`contained` in
[EVIDENCE.md](EVIDENCE.md)). A deny group marked `hook_only` (ADR-034), such as the
default `build-credentials` (`~/.m2/settings.xml`, `~/.gradle/gradle.properties`), is
left out of every generated sandbox, so `mvn` and `gradle` can read their settings
wherever the sandbox lets commands read `~/.m2` or `~/.gradle`; the hook still denies
the agent's own access.

- **Claude Code** (`settings.json`): the `sandbox` block (`enabled`,
  `failIfUnavailable: true`, `allowUnsandboxedCommands: false`, `excludedCommands: []`,
  read and write lists, `network.allowedDomains` with `strictAllowlist`) and
  `permissions.blockReadsOutsideWorkingDirectories: true`. Claude Code's file tools
  then refuse reads outside the working directories; `/add-dir` adds one. On every
  OS it also adds a `Read(//…)` or `Edit(//…)` rule to `permissions.deny` for each
  path a policy deny rule names (secrets, OpenMoat's own files, shell start-up
  files), and an `Edit(//…)` rule for the recorded `openmoat` binary and its directory.
  Claude Code's file tools obey those without the hook, so they hold when
  `openmoat` is missing or killed; on native Windows, where Claude Code has no sandbox,
  only these rules are written, drive paths as `//c/…`. On Linux
  (and WSL2) it also adds `Read(./**/.env)`, `Read(./**/.env.*)` and
  `Read(./**/.envrc)` to `permissions.deny`. There, bubblewrap needs concrete paths,
  and Claude Code's sandbox expands a `denyRead` glob from its first literal directory
  when each command starts, so it skips `/**/.env`. A `Read` deny rule is expanded
  under the session's working directory instead, so a script reading one gets
  `EACCES`. A `.env` created after a command starts, or one in another readable
  directory, is not covered, and Claude Code's file tools also refuse `.env.example`.
  `openmoat sandbox show` lists both.
  Write lists get no expansion on Linux: Claude Code's sandbox drops every glob in
  `denyWrite`, `Edit(…)` deny rules included. A rule without a glob is kept and
  resolved against the working directory, so `openmoat init` also adds `Edit(./.env)`,
  `Edit(./.envrc)` and `Edit(./.moat)`. Only names directly in the working directory
  get such a rule: where a denied path is missing, bubblewrap mounts its first
  missing component read-only for the command (an empty `.envrc` or `.moat` shows up
  there meanwhile), and `Edit(./bin/moat)` would do that to a missing `bin`. The
  exception is a file below a directory the policy denies writing itself: `openmoat init`
  also adds `Edit(./.cursor/hooks.json)`, `Edit(./.cursor/sandbox.json)` and
  `Edit(./.codex/hooks.json)`, so sandboxed commands cannot plant another agent's
  hooks there. A missing `.cursor` or `.codex` is read-only for the command, which
  the policy denies creating anyway. Claude Code itself keeps the working directory's
  `.git/hooks`, `.git/config` and `.claude` settings read-only. Everything else the
  policy denies by a `**/` glob (a `.env` in a subdirectory, `.env.local`,
  `.git/info/attributes`, submodule hooks, those hook files in a subdirectory,
  `bin/moat`) stays writable for sandboxed commands on Linux; `openmoat sandbox show`
  lists it (`claude-code.linux-write-globs`).
- **Codex** (`config.toml`): a `[permissions.moat]` profile, `default_permissions =
  "moat"` and `features.network_proxy = true`. The `**/` denies (`.env` files) cover
  the project and the read roots inside the home, not system read roots such as
  `/etc`, `/usr` and `/tmp`: on Linux Codex lists every directory below a deny glob
  before each command and runs none when one is unreadable, and those hold root-only
  directories. `openmoat sandbox show` lists these roots (`codex.outside-home`); the hook
  still denies the agent's own reads there. A directory you cannot list inside the
  project or a home read root still stops Codex on Linux. There a glob hides only the
  files it matches when a command starts, so a command could create a missing match;
  on Linux the profile therefore also denies each `**/<name>` deny's name directly in
  the workspace roots (`.env`, `.envrc`): bubblewrap mounts an empty read-only file
  over a missing one while the command runs. The policy also denies writing `.claude`
  and `.cursor` themselves, so on Linux the profile makes them read-only in the
  workspace roots: sandboxed commands cannot plant `.claude/settings.local.json` or
  `.cursor/hooks.json` there, nor write anything else in those directories, and while
  a command runs a missing `.claude` or `.cursor` shows up as an empty file
  (`codex.linux-agent-dirs`). Codex keeps `.codex` read-only itself. The rest
  (`.env.local`, a `.envrc` or `.claude` in a subdirectory, `bin/moat`) can still be
  created by sandboxed commands on Linux;
  `openmoat sandbox show` lists it (`codex.linux-write-globs`). Codex on Linux also runs its
  own executable inside the sandbox, so on Linux the profile lets commands read the
  executable `codex` on `PATH` starts (through npm's launcher, the platform binary),
  listed as `codex.own-binary`. Run `openmoat sandbox sync` after installing, moving or
  updating Codex. When `codex` is not on `PATH`, `openmoat sandbox show` says so and Codex
  starts commands only when installed under a read root. Codex's standalone installer
  puts the executable in the Codex home, which the profile denies, and Codex hides a
  denied directory after the read paths inside it. When no read root or write grant
  includes the Codex home, commands cannot read it anyway, so on Linux the profile
  then denies by name what Codex keeps there instead of the whole directory: logins
  and tokens (`auth.json`, `.credentials.json`, `secrets`, `proxy`), config
  (`config.toml`, `managed_config.toml`, `hooks.json`), conversations
  (`history.jsonl`, `sessions`, `archived_sessions`, `log`, `shell_snapshots`), your
  own content (`memories`, `rules`, `skills`, `AGENTS.md`) and its SQLite databases
  (`**/*.sqlite*`, which Codex expands to the files present when a command starts). Commands may then read the installer's
  `packages/standalone/releases` directory, which holds only Codex's published
  releases (the executable, ripgrep, bubblewrap and the package manifest, one
  directory per version), so Codex keeps starting commands after it updates itself
  without `openmoat sandbox sync`. Those names still apply when Codex runs with the home
  directory as its project; other files there are then readable. Otherwise, as for an executable inside any other denied path, nothing is
  granted (a deny wins), so Codex on Linux starts no command; `show` says that too.
- **Cursor** (`sandbox.json` next to `hooks.json`: `~/.cursor`, or `$CURSOR_CONFIG_DIR`):
  `type: "workspace_readwrite"`, `readBoundary: "workspace"`, `additionalReadPaths`
  (the read roots and read allow rules), `additionalReadwritePaths` (write allow rules
  outside the project) and `networkPolicy` (`default: "deny"`, the allowed and denied
  domains). Cursor's file tools then ask before reading outside the workspace. See
  [Cursor's sandbox](#cursors-sandbox) for what its schema cannot express.

Claude Code's sandbox runs on macOS, Linux and WSL2 only, and with `failIfUnavailable`
Claude Code exits at startup where it cannot run. On native Windows, OpenMoat therefore
writes neither the `sandbox` block nor `blockReadsOutsideWorkingDirectories`; `moat
init`, `sandbox sync`, `sandbox show`, `doctor` and `status` print `sandbox not
available on native Windows; the hook still applies the policy (use WSL2 for OS
confinement)` for Claude Code instead. `openmoat init` and `openmoat sandbox sync` remove those
settings where an older version wrote them, keep the rest of the file and re-pin it.
Codex is configured as on other systems. `openmoat status` reports such an agent as
`hook only`, and a sandbox that is missing, weakened or out of date the same way, with
the reason ([USAGE.md](USAGE.md#how-each-agent-is-protected)).

Network has two modes:

- **Default:** each agent's own proxy enforces the allowlist.
- **Opt-in:** set `sandbox.proxy_port: 18080` in the policy, run `openmoat sandbox sync`,
  and keep `openmoat proxy` running (a user service works). Sandboxed commands then reach
  the network through `openmoat proxy`, which records every connection, injects brokered
  secrets and refuses private addresses.
  - Claude Code's `network.httpProxyPort` and `socksProxyPort` name the proxy. While
    it is stopped, its sandboxed commands have no network, and `openmoat doctor` and
    `openmoat status` warn.
  - Codex's proxy passes what it allows on to `openmoat proxy` when you start Codex with
    `HTTP_PROXY` and `HTTPS_PROXY` set to `http://127.0.0.1:18080`. Codex's own API
    hosts then need an allow rule.

Claude Code's own broker also runs from the policy (#363). `openmoat sandbox sync` writes
the policy's `secrets:` entries into Claude Code's `sandbox.credentials` as `mask` entries
with the host in `injectHosts`, and turns on `network.tlsTerminate` so Claude Code's
built-in proxy substitutes the real value inside HTTPS for sandboxed `Bash`,
`PowerShell` and `Monitor` commands. One policy therefore drives both Claude Code's
broker and `openmoat proxy`. A secret whose host is not in `net` allow is skipped with a
loss, as is a `keychain` source (Claude Code's broker reads env and file sources only);
both still work through `openmoat proxy`. On macOS, Claude Code denies a `file` source
instead of masking it, so the tool that reads the file does not authenticate inside
the sandbox; `openmoat sandbox show` lists this and the HTTPS allowance. Claude Code's
`allowPlaintextInject` is block-scoped: setting it `true` lifts the HTTPS requirement
for every mask entry in the `credentials` block. When a policy mixes `plain_http: true`
and `plain_http: false` secrets, OpenMoat therefore drops the `plain_http: true` entries
from Claude Code's mask block (lifting TLS for them would widen the others, which
ADR-019 forbids); they still work through `openmoat proxy`, whose broker is per-secret,
and `openmoat sandbox show` names each dropped id (#401). Its text output starts with a
`Secrets` list: one line per secret with its host, header and source, never the value,
and whether Claude Code masks it or why it skips it. `openmoat doctor` prints the same per
secret from the settings file on disk: masked (the `mask` entry for its host and
`tlsTerminate` are both there), denied instead of masked (a `file` source on macOS),
skipped with the loss, or not yet written, until `openmoat sandbox sync`. A secret Claude
Code does not mask keeps the hook and `openmoat proxy`'s handling. `tlsTerminate` is on only
while at least one secret is masked: Claude Code calls it experimental, and its
proxy then terminates TLS for sandboxed commands
([sandboxing](https://code.claude.com/docs/en/sandboxing#mask-credentials)). Claude
Code honours `mask` entries and `tlsTerminate` only from user, managed or `--settings`
settings, which is where OpenMoat writes them. `openmoat doctor` also flags
`credentials.allowPlaintextInject: true` in the file when the policy did not ask for it,
since it lets every masked secret go to a plain-HTTP host.

Other settings and comments are kept, and each file is copied to
`<file>.moat-sandbox-backup` before moat changes it. `openmoat sandbox show` prints what
the policy compiles to, with every place a host is stricter or wider than the policy;
`openmoat sandbox sync` rewrites them after you edit the policy and re-pins them; it
writes only the agents whose OpenMoat hook is installed and leaves the files of any
other agent as they are. Editing
the generated parts by hand is drift (`kernel-integrity`), and `openmoat doctor` names any
weakened setting. Under Claude Code, sandboxed commands can run `git commit` but cannot
write `.git/hooks`, `.git/config` or the other paths that make git run code (ADR-021);
on Linux only in the working directory's own repository, `info/attributes` and
submodules aside (above).
Codex keeps `.git` read-only: commit outside its sandbox (Codex asks to).
A `.git` file or directory below the project root (`sub/.git` holding `gitdir: …`)
is a repository git follows, so the hook asks before writing one. No host sandbox
can deny it without also denying the root's `.git`, so it stays writable for sandboxed
commands under Claude Code (on macOS its hooks and config aside), Codex
(`codex.nested-git`) and Cursor. `openmoat run` keeps it unwritable on macOS, and
`openmoat run --isolate` keeps one that exists when the session starts read-only.

git treats any directory holding `HEAD`, `objects/` and `refs/` as a bare repository
and runs what its `config` names, so a script could plant one for a later `git status`
in it. `openmoat init` therefore also sets git's `safe.bareRepository=explicit` for every
command the agent starts (git 2.38 or later uses a bare repository only when
`--git-dir` or `GIT_DIR` names it), through `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`
and `GIT_CONFIG_VALUE_<n>` in Claude Code's `env` settings and Codex's
`shell_environment_policy.set`, appended after the entries already there. Those
values replace any the agent inherits from the shell, and Codex's `include_only` and
`filters` can remove them. Cursor's `sandbox.json` has no key that sets a variable,
so Cursor gets none. The hook denies the agent setting `GIT_*` (`env-poison`), but a
script it runs can unset them.

[EVIDENCE.md](EVIDENCE.md) lists what each agent's sandbox, configured this way, does
to hostile project scripts on macOS and Linux. CI runs them on every pull request with
pinned Claude Code and Codex binaries and no account: Claude Code headless against a
local fake API, Codex through `codex sandbox -P moat`.

To undo, delete the `sandbox` key, `permissions.blockReadsOutsideWorkingDirectories`
and the rules OpenMoat added to `permissions.deny` (listed in `~/.moat/hosts.json`) from Claude Code's settings,
`default_permissions`, `[permissions.moat]` and `features.network_proxy` from Codex's
`config.toml`, and `type`, `readBoundary`, `additionalReadPaths`,
`additionalReadwritePaths` and `networkPolicy` from Cursor's `sandbox.json` (or restore
the backups), then run `openmoat doctor --accept`. `openmoat uninstall` does this for you.

### Cursor's sandbox

Cursor's sandbox (Seatbelt on macOS, Landlock and seccomp on Linux) confines the
terminal commands its agent runs. The keys are those of Cursor 3.23's
[`sandbox.json` reference](https://cursor.com/docs/reference/sandbox) and
[Run Modes](https://cursor.com/docs/agent/security/run-modes) page; OpenMoat follows
the documentation, and the generated file has not yet been run under a Cursor build.

`sandbox.json` has no key that denies a path. A read root with a denied path below it
(`~/.cargo` holds `~/.cargo/credentials.toml`) is therefore left out, which is stricter
and is listed as such, and what the policy denies by name inside the workspace
(`**/.env`, `.moat`, `.git`) stays readable and writable to sandboxed commands, listed
as wider. Cursor itself keeps `.cursor/*.json`, `.claude/**/*.json`, `.vscode`,
`.git/hooks`, `.git/config` and `.git/info/attributes` unwritable. With the
workspace read boundary, sandboxed commands read only the workspace, the listed paths,
the system paths tools need and, of `~/.ssh`, only `known_hosts`.

What no key in `sandbox.json` changes, and `openmoat sandbox show` lists as wider:

- Cursor runs a command outside its sandbox when its Auto-review classifier approves
  it (a command that cannot use the sandbox, or a rerun after a sandbox error), in Run
  Everything mode, in Allowlist mode with sandboxing off, and in the Cursor CLI unless
  it starts with `--sandbox enabled`. On Linux without Landlock v3 Cursor asks instead.
- Cursor's Network access setting: its default, "sandbox.json + Defaults", adds
  Cursor's package-manager domains, and "Allow All" ignores `sandbox.json`. Choose
  "sandbox.json Only".
- A project's own `.cursor/sandbox.json` replaces the read boundary and the read list
  and adds paths and hosts. The default policy denies the agent writes to it, and Cursor
  keeps sandboxed commands from writing it, but a cloned repository can ship one.
- `sandbox.proxy_port` has no Cursor equivalent: Cursor's own allowlist decides, and
  that traffic does not reach `openmoat proxy`.

Cursor documents its sandbox for macOS and Linux only, so on native Windows `openmoat init`
leaves `sandbox.json` alone and `openmoat status` reports Cursor as `hook only`.

## `openmoat run` (Lightweight tier)

Without a container or VM runtime, `openmoat run` puts a whole agent in a sandbox generated
from the policy, with network only through an `openmoat proxy` it starts (ADR-018):

```bash
openmoat run --write ~/.claude --write ~/.claude.json -- claude
```

The two `--write` paths are Claude Code's own state, which it must write to run. They
also hold what Claude Code starts in its next session, outside any sandbox (MCP servers
in `~/.claude.json`, plugins in `~/.claude/plugins/`), and in this tier every command the
agent runs shares that grant. The hook asks before the agent's own tools write one
(`runs-later`); a script it runs is not asked. Where the agent's own sandbox is
available, the Standard tier keeps its commands out of the home altogether.

- **macOS 13 or later:** a Seatbelt profile, started with `/usr/bin/sandbox-exec`.
  On macOS 12 and earlier `sandbox-exec` cannot read the profile's `TIOCSTI` deny,
  so `openmoat run` refuses there and `openmoat doctor` warns ([INSTALL.md](INSTALL.md)).
  On some macOS 14 machines, Seatbelt itself sometimes refuses the connection to the proxy
  that the profile allows. This happens for a few milliseconds about every 15 seconds,
  so a network request now and then fails at once with `Operation not permitted`.
  Nothing gets out, and a retry succeeds. A one-rule `sandbox-exec` profile and a
  plain listener show the same thing without OpenMoat, so the cause is macOS
  ([#280](https://github.com/crocodile-labs/openmoat/issues/280),
  [evidence in #351](https://github.com/crocodile-labs/openmoat/pull/351)). CI's
  macOS 15 runners (`macos-15-intel`) did not show it.
- **Linux 6.7 or later:** Landlock rules, plus a seccomp filter that allows only TCP
  sockets (no UDP, Unix sockets or `ptrace`). Windows refuses.
- **The network on Linux.** Landlock restricts TCP connections by port only, and a
  seccomp filter cannot read the address `connect()` is given (it gets a pointer), so
  those two alone would let a command reach any host on the proxy's port and go around
  the proxy. Where bubblewrap can run (`bwrap` in `/usr/bin`, `/bin` or
  `/usr/local/bin`, and unprivileged user namespaces, as for `--isolate` below),
  `openmoat run` starts the agent in a network namespace of its own with nothing but
  loopback, where OpenMoat serves the proxy's port and relays each connection over a
  Unix socket to the proxy outside. Nothing else changes: the agent sees the machine's
  files as before, and the same Landlock rules and seccomp filter apply. Where
  bubblewrap is missing or cannot create the namespaces, `openmoat run` starts with
  Landlock and seccomp alone and says on every start that the network is restricted
  by port only, and `openmoat doctor` warns.
- **What Linux does not protect.** Landlock can only grant access to whole directory
  trees, so inside the project the policy's deny rules do not hold for the agent's
  commands: they can read and write `.env`, create `.envrc`, write `.moat/policy.yaml`
  and add files under `.git/hooks`. The same goes for secrets inside a read root
  (`~/.cargo/credentials.toml`). [EVIDENCE.md](EVIDENCE.md) marks each as a gap. The
  hook still decides the agent's own tool calls on them. `openmoat run --isolate` covers
  these paths where bubblewrap runs (below).
- **OpenMoat's state directory.** For the same reason, `openmoat run` on Linux refuses to
  start when a tree it grants (the project, a read root, a `--write` path, the temp
  directory) holds the state directory (`MOAT_HOME`, default `~/.moat`) or lies inside
  it, symlinks resolved: commands could otherwise read the audit log and the lock.
  Move `MOAT_HOME` out of the tree it names. `openmoat run --isolate` starts when the
  state directory is below the temp directory, which it covers with an empty `tmpfs`;
  anywhere else it refuses too. `~/.moat` is in none of the default grants, and
  `openmoat doctor` warns on Linux when the state directory is inside one.
- **The terminal.** The agent runs in the terminal it was started in. Neither it nor
  a command it starts may type into that terminal: Seatbelt denies `ioctl(TIOCSTI)`,
  and the seccomp filter (also inside `--isolate`) denies `TIOCSTI` and `TIOCLINUX`,
  both with `Operation not permitted`. Typed characters would wait in the terminal's
  input, and the user's shell would run them after the session, outside the sandbox.
  What they write to the terminal (escape sequences included) still reaches it.
- The agent and every command it starts may read the project, `sandbox.read_roots`,
  the temp directory and the agent's own executable; never the keychain. They may
  write the project, the temp directory and each `--write` path (the agent's state).
  Deny rules still win (`~/.claude/settings.json` stays unwritable).
- git uses a bare repository only when named: `openmoat run` (and `--isolate`) appends
  `safe.bareRepository=explicit` to the agent's `GIT_CONFIG_COUNT` entries, keeping
  the ones it inherits, and refuses to start when `GIT_CONFIG_COUNT` is not a number.
- npm and uv install no package version published in the last 7 days:
  `openmoat run` sets `npm_config_before` and `UV_EXCLUDE_NEWER` unless you set a cut-off
  yourself (`sandbox.package_min_release_age_days`, `0` turns it off;
  [POLICY.md](POLICY.md) §9.1, ADR-030).
- Network goes only to the proxy on a loopback port (`HTTP_PROXY`, `HTTPS_PROXY`),
  which allows the hosts the policy allows. A tool that ignores those variables has
  no network. The proxy serves this run alone: the variables carry the run's
  credential as `http://<session>:<token>@127.0.0.1:<port>`, and a request without it
  gets `407` (ADR-027). A tool that drops the URL's user and password has no network
  either.
- Turn the agent's own sandbox off inside: sandboxes do not nest, so Claude Code's
  `sandbox.enabled` (which `openmoat init` turns on) fails there and Codex needs
  `--sandbox danger-full-access`. Credentials must not come from the keychain: use
  an API key or `apiKeyHelper`.
- Before the agent starts, `openmoat run` prints how many places the sandbox is stricter
  or wider than the policy; `openmoat run --verbose` lists each one (`openmoat sandbox show`
  prints the same for the current directory). Linux is wider than macOS (the paths inside
  the project above, and, without bubblewrap, the proxy's port on any host; `--isolate`
  closes both, below); see [THREAT_MODEL.md](THREAT_MODEL.md).

It is weaker per command than the Standard tier: the agent and its scripts share one
sandbox, so whatever the agent needs, `npm test` gets too. On macOS and Linux alike,
data can still leave through the hosts the policy allows: the proxy checks the host,
and the secrets broker blocks a brokered secret it can see, but it cannot read inside
HTTPS. It applies the session's taint from the agent sessions whose hooks linked
themselves to the run ([THREAT_MODEL.md](THREAT_MODEL.md) §5, ADR-027).

The agent's hooks run inside the sandbox too, where `~/.moat` is closed to them. They
send each tool call to the `openmoat run` process over the proxy's port, with a token made
for the run (`MOAT_GUARD_SOCKET`, `MOAT_GUARD_TOKEN`), and that process decides and
records it outside the sandbox (ADR-028). The sandbox gets no new rule for this:

- macOS: the profile's one way out stays `(allow network-outbound (remote ip
  "localhost:<port>"))`; no Unix socket is allowed.
- Linux: Landlock does not restrict connecting to a Unix socket by path at the ABI
  `openmoat run` uses (ABI 6 scopes only abstract sockets), which is why the seccomp
  filter refuses Unix sockets altogether. The relay uses the proxy's TCP port, so that
  filter and the Landlock port rule stay as they are, in the network namespace and
  under `--isolate` too.

If the token is wrong, the connection fails or no answer comes within the hook's
10 s, the hook denies the call.

[EVIDENCE.md](EVIDENCE.md) lists what `openmoat run` does to hostile project scripts on
macOS and Linux (reading keys and credentials, writing outside the project, direct
connections, DNS, symlinks out of the project, editing the policy), as CI asserts it on
every pull request, with the Linux gaps marked.

## `openmoat run --isolate` (Isolated tier, Linux)

On Linux, `--isolate` runs the agent in its own view of the machine, built with
[bubblewrap](https://github.com/containers/bubblewrap) (ADR-018):

```bash
openmoat run --isolate --write ~/.claude --write ~/.claude.json -- claude
```

- **What it sees.** Only the project, `sandbox.read_roots`, the agent's executable,
  the `--write` paths and an empty temp directory, each at its usual path. The rest
  of the home directory (`~/.ssh`, `~/.aws`, other projects) does not exist in there.
- **What it hides inside them.** Every path the policy denies that exists when the
  session starts: a denied read (the project's `.env` files, `~/.cargo/credentials.toml`)
  is covered by an empty placeholder no one may open (`EACCES`), and a denied write
  (`.git`, `.claude/settings.json`) by the path itself, read-only. `.env`, `.envrc`
  and `.moat` directly in the project are covered even when they are missing: OpenMoat
  creates an empty placeholder file there for the session and removes it afterwards.
- **Writes** go only to the project, the temp directory (in memory, gone when the
  session ends) and the `--write` paths.
- **Network** goes only to OpenMoat's proxy: the agent has its own network namespace
  with nothing but loopback, where OpenMoat serves the proxy's port and relays each
  connection over a Unix socket to the proxy outside. A tool that ignores
  `HTTP(S)_PROXY` has no network; there is no DNS.
- Inside, the Lightweight tier's Landlock rules and seccomp filter apply too, so
  Linux 6.7 or later is needed. The agent's own sandbox must be off, as under
  `openmoat run`.
- **No user namespaces of its own.** Where bubblewrap accepts `--disable-userns`
  (0.8 and later), OpenMoat passes it, so the agent cannot create further user
  namespaces inside; an older bubblewrap runs without it.

It needs `bwrap` in `/usr/bin`, `/bin` or `/usr/local/bin` (`apt install bubblewrap`, `dnf install bubblewrap`; never taken from `PATH`, since it starts outside the sandbox) and
unprivileged user namespaces; on Ubuntu 24.04 AppArmor restricts them unless
`kernel.apparmor_restrict_unprivileged_userns` is 0 or an AppArmor profile allows
`bwrap`. Where bubblewrap is missing or cannot create its namespaces, `openmoat run
--isolate` refuses (exit 64) and never falls back to the Lightweight tier.

macOS: tracked in [ADR-023](adr/ADR-023-isolated-tier-macos.md), first stub ships
here. On macOS `openmoat run --isolate` refuses with exit 64 and names what is missing:
Apple's `container` CLI if the toolchain is not installed (install hint included),
or "not yet implemented, see ADR-023" when it is. The ADR picks Apple's
`containerization` toolchain for the implementation (its note of 2026-10-12 corrects
what it assumed about that toolchain and lists open questions) and lists the follow-up PRs
under [#175](https://github.com/crocodile-labs/openmoat/issues/175). Never a silent
fallback to the Lightweight tier.

Limits:

- A match of a deny rule created after the session starts (`.env.local` written by a
  command, a `.env` in a new subdirectory) is not hidden; the hook still decides the
  agent's own tool calls on it.
- The agent and its commands still share one sandbox, as under `openmoat run`.
- Ctrl-C ends the whole session unless the agent reads the terminal itself (Claude
  Code's and Codex's interfaces do).
- A project with more than a million files and directories is refused: each is looked
  at to find what to hide.

### Cursor CLI under `openmoat run`

Cursor's CLI (`agent`, formerly `cursor-agent`) needs three things the default policy
does not give it:

1. Its installation directory readable: it is a script that starts the Node.js and
   JavaScript files beside it. Add `~/.local/share/cursor-agent` to
   `sandbox.read_roots` (`openmoat edit`).
2. Its API host allowed: add an allow rule with `net: ["api2.cursor.sh"]`. The
   audit log names any other host the proxy refused.
3. Its state directory writable, and credentials from `CURSOR_API_KEY`: on macOS
   `agent login` keeps them in the keychain, which the sandbox blocks.

```bash
CURSOR_API_KEY=… openmoat run --write ~/.cursor -- agent --sandbox disabled
```

`--sandbox disabled` turns Cursor's own sandbox off for this run only, because
sandboxes do not nest; it does not change `~/.cursor/cli-config.json`. `~/.cursor`
must already exist, and `~/.cursor/hooks.json` stays unwritable. Checked on macOS
with Cursor CLI `2026.10.01`: it starts, writes only `~/.cursor`, and reaches
`api2.cursor.sh` through the proxy; a session with an account and the commands it runs
were not checked, nor was Linux, where the CLI keeps its settings in
`$XDG_CONFIG_HOME/cursor` when that variable is set.
