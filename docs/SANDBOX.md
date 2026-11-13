# OS sandboxes: Standard, Lightweight and Isolated tiers

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want the operating system to enforce the policy: the agents' own sandboxes (Standard tier), `openmoat run` (Lightweight; on Linux the Isolated tier by default where bubblewrap works) and `openmoat run --isolate` (Isolated).

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
the agent's own access. The default `agent-folders` (renaming a `.github` or
`.github/copilot` folder) is one too, so a clone or an install inside the sandbox can
still create a `.github`. `openmoat sandbox show` lists these groups and their paths as
decided by the hook only, not in the OS sandbox (`hook_only` in `--format json`).

The default `agent-credentials` (where each agent keeps its login, provider keys and
OAuth tokens) is denied in every sandbox (ADR-054). Each agent's own sandbox confines
only the commands it runs, never the agent itself, so the agent keeps signing in while
a command it runs (a test, a package script, a downloaded binary) gets `EPERM` or
`EACCES` on any agent's login, its own included: Claude Code's `denyRead`, `denyWrite`
and `Read(//…)`/`Edit(//…)` rules, Codex's profile (which denies the Codex home whole
already) and Cursor's read boundary, which grants no path holding one. A command that
needs another agent's login (`codex exec` started from Claude Code) fails there; set
`hook_only: true` on the group in your policy to leave it to the hook again.
`openmoat run` holds the agent itself (below), so it keeps that agent's login readable.
`openmoat sandbox show` lists the logins under `Agent logins` and what `openmoat run`
keeps for each agent (`agent_logins` in `--format json`).

```console
# a command Claude Code runs in its own sandbox, after `openmoat init`:
$ cat ~/.codex/auth.json
cat: /Users/you/.codex/auth.json: Operation not permitted
$ cat ~/.claude/.credentials.json
cat: /Users/you/.claude/.credentials.json: Operation not permitted
# Claude Code itself still signs in: it reads the file outside its sandbox
```

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
  also adds `Edit(./.cursor/hooks.json)`, `Edit(./.cursor/sandbox.json)`,
  `Edit(./.codex/hooks.json)` and `Edit(./.gemini/settings.json)`, so sandboxed commands
  cannot plant another agent's hooks there. A missing `.cursor`, `.codex` or `.gemini`
  is read-only for the command, which
  the policy denies creating anyway. Claude Code itself keeps the working directory's
  `.git/hooks`, `.git/config` and `.claude` settings read-only. Everything else the
  policy denies by a `**/` glob (a `.env` in a subdirectory, `.env.local`,
  `.git/info/attributes`, submodule hooks, those hook files in a subdirectory,
  `bin/moat`) stays writable for sandboxed commands on Linux; `openmoat sandbox show`
  lists it (`claude-code.linux-write-globs`).
  The directories themselves (`.claude`, `.codex`, `.cursor`, `.copilot`, `.gemini`)
  are left out of `denyWrite`, which would make everything inside read-only
  (`claude-code.directory-nodes`). On macOS Claude Code's sandbox keeps each directory
  above a literal `denyWrite` path from being renamed or removed, so `openmoat init`
  writes the `Edit(./.cursor/hooks.json)` rules above, and `Edit(./.copilot/hooks)`,
  `Edit(./.copilot/settings.json)` and `Edit(./.copilot/config.json)`, on every OS: a
  sandboxed command cannot move the working directory's `.cursor`, `.codex`,
  `.copilot` or `.gemini` away and put another one with its own hooks in its place.
  The home's are kept the same way by their literal entries, and `.claude` by Claude
  Code itself. Such a directory in a subdirectory, and any of them on Linux, can
  still be moved by a sandboxed command; the hook denies the agent moving, removing
  or replacing one (`mv`, `rename`, `rm -rf`; `kernel-self`).
  On Linux the audit log's `-wal` and `-shm` files come and go as `openmoat guard`
  writes, and Claude Code's sandbox skips a `denyRead` path that is missing when a
  command starts, so one made while it runs would stay readable: there the state
  directory itself is in `denyRead` (`claude-code.linux-state-dir`). Under the home
  Claude Code hides it already; a `MOAT_HOME` elsewhere is hidden from sandboxed
  commands whole, its policy included. Claude Code's file tools still read the policy.
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
  `openmoat sandbox show` lists it (`codex.linux-write-globs`). Codex compares those globs
  with file names case-sensitively, so in a directory that folds case (`chattr +F`) a
  `.ENV` that exists would not be hidden: the Linux profile writes every letter case of
  each glob of up to five letters (`**/.env`, `**/.env.*`, `**/.envrc`, `**/.moat/**`)
  and lists the
  longer ones (`codex.linux-case-variants`). Codex on Linux also runs its
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
writes neither the `sandbox` block nor `blockReadsOutsideWorkingDirectories`; `openmoat
init`, `sandbox sync`, `sandbox show`, `doctor` and `status` print `sandbox not
available on native Windows; the hook still applies the policy (use WSL2 for OS
confinement)` for Claude Code instead. `openmoat init` and `openmoat sandbox sync` remove those
settings where an older version wrote them, keep the rest of the file and re-pin it.
Codex is configured as on other systems, and `openmoat doctor` shows the Windows sandbox
mode its `config.toml` selects: under `unelevated` Codex does not enforce denied reads, so
OpenMoat's read denies hold only through the hook there (ADR-083). `openmoat status` reports such an agent as
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
    `openmoat status` warn. Each session's `SessionStart` hook gives its commands a
    credential of their own (ADR-044), so the proxy applies that session's taint.
  - Codex's proxy passes what it allows on to `openmoat proxy` when you start Codex with
    `HTTP_PROXY` and `HTTPS_PROXY` set to `http://127.0.0.1:18080`. Codex's own API
    hosts then need an allow rule. Codex sends no session credential, so
    `openmoat proxy` refuses that traffic unless the policy sets
    `sandbox.proxy_serve_without_credential: true` (no session taint then);
    `openmoat run -- codex` is the per-session alternative.

Claude Code's own broker also runs from the policy (#363). `openmoat sandbox sync` writes
the policy's `secrets:` entries into Claude Code's `sandbox.credentials` as `mask` entries
with the host in `injectHosts`, and turns on `network.tlsTerminate` so Claude Code's
built-in proxy substitutes the real value inside HTTPS for sandboxed `Bash`,
`PowerShell` and `Monitor` commands. One policy therefore drives both Claude Code's
broker and `openmoat proxy`. A secret whose host is not in `net` allow is skipped with a
loss, as is a `keychain` or `command` source (Claude Code's broker reads env and file
sources only; a `command` source is run and renewed by `openmoat proxy` alone, ADR-087);
both still work through `openmoat proxy`. On macOS, Claude Code denies a `file` source
instead of masking it, so the tool that reads the file does not authenticate inside
the sandbox; `openmoat sandbox show` lists this and the HTTPS allowance. A
`plain_http: true` secret goes to plain-HTTP requests on one port only (`port`, or
80), and Claude Code's broker cannot bind a secret to a port: its
`allowPlaintextInject` injects on every port of the host, and it is block-scoped, so
setting it `true` would also lift the HTTPS requirement for every other mask entry in
the `credentials` block. OpenMoat therefore leaves every `plain_http: true` secret out
of Claude Code's mask block and never sets `allowPlaintextInject`; those secrets still
work through `openmoat proxy`, whose broker is per-secret and per-port, and `openmoat
sandbox show` names each one left out with its port (#401). Its text output starts with a
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
`credentials.allowPlaintextInject: true` set by hand in a block that holds the policy's
masked secrets, since it lets every one of them go to a plain-HTTP host.

Other settings and comments are kept, and each file is copied to
`<file>.moat-sandbox-backup` before OpenMoat changes it. `openmoat sandbox show` prints what
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
is a repository git follows, so the hook holds a write of one for review. No host sandbox
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
to hostile project scripts on macOS and Linux, run with pinned Claude Code and Codex
binaries (`scripts/ci/host-binaries.sh`) and no account: Claude Code headless against a
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

## Which tier `openmoat run` starts

On Linux `openmoat run` starts the Isolated tier (below) by default where bubblewrap
works, and the Lightweight tier otherwise (ADR-080). macOS has the Lightweight tier only.

| Linux, `openmoat run` … | bubblewrap works | bubblewrap missing or blocked |
|---|---|---|
| (no flag) | Isolated tier | Lightweight tier; says why on every start and records it in the audit log (`run-isolation-unavailable`) |
| `--isolate` | Isolated tier | refused (exit 64) |
| `--no-isolate` | Lightweight tier, recorded in the audit log (`run-no-isolate`) | the same |
| any of these under `require.run: full-boundary` | Isolated tier; `--no-isolate` refused | refused (exit 64) |

```bash
openmoat doctor          # "openmoat run     starts the Isolated tier (bubblewrap works here)"
openmoat run -- claude   # the Isolated tier here, or the Lightweight one with a warning
openmoat run --no-isolate --write ~/.claude --write ~/.claude.json -- claude
```

The rows are in the audit log under the run's own session (`openmoat show`, host
`moat-run`, tool `isolation`). On macOS `--no-isolate` changes nothing and writes nothing.

## The run's boundary record

Every `openmoat run` that starts an agent writes one more row to its audit session:
tool `boundary`, rule `run-boundary`, its reason the whole record as JSON (ADR-089).
It names the tier asked for and the tier that started, every downgrade (the tier, the
network, and the project's top when `sandbox.project_top: writable` opened it) with why
and whether the person chose it, how the network is held
(`namespace`, `port_only`, or Seatbelt's `profile`), the Landlock ABI, whether tool
commands get the hook relay token, and for each restriction whether the system has it
(`available`), the run asks for it (`configured`), it is in force (`applied`) and a
check after the agent started confirmed it (`tested`).

```bash
openmoat run --print-boundary -- claude                 # what a run here would start with
openmoat run --print-boundary --format json -- claude | jq '.tier, .downgrades'
openmoat show --format json | jq 'select(.tool == "boundary") | .reasons[0] | fromjson'
```

`--print-boundary` makes the same choices as a run (flags, policy, bubblewrap, kernel)
and starts nothing. It refuses, with the run's words and exit 64, where a run would
refuse before building its sandbox (no sandbox here, Landlock below ABI 4, a policy's
`require.run: full-boundary` or `--netns=require` that cannot be met); a refusal that
depends on the generated grants (a grant over OpenMoat's state directory, a `--write`
path holding protected files without a namespace) only a start finds.

**The check after the start, on Linux.** The thread that starts the agent applies the
Landlock rules and seccomp filters, keeps what Landlock's `restrict_self` reports (the
kernel's ABI and whether the ruleset is enforced: the row's ABI is this one, not a
probe's), starts the agent and reads its `/proc/<pid>/status`: `NoNewPrivs: 1`, and
`Seccomp: 2` with `Seccomp_filters` grown by exactly this run's filters (a container's
or service manager's own filter does not count), and the ruleset enforced. Anything
missing or unknown stops the agent and every process it started at once; the run says
why, exits 64, and the row is a `deny` naming what was missing. So does a row that
cannot be written. Under bubblewrap (the Isolated tier, and the Lightweight tier's
network namespace) the check runs in `openmoat isolated` inside, which reports it on a
Unix socket in the run's private session directory, connected before the agent starts
and authenticated by a nonce only it was given, and then waits for the run's go: no
go, or no reply within a minute, and it stops the agent. A run that gets no report
while bubblewrap keeps running, or that cannot record one, stops bubblewrap and every
process below it. Landlock's rules cannot be read back from the kernel, so Landlock's rows are
`applied` from `restrict_self` and never `tested`; the access tests are the end-to-end
suite's.

**On macOS** the row names the Seatbelt profile, configured; `sandbox-exec` reports
nothing back and macOS has no `/proc`, so it is neither `applied` nor `tested`, and the
row has no `launch` part. The profile is the one `openmoat sandbox show` prints.

## `openmoat run` (Lightweight tier)

Without a container or VM runtime, `openmoat run` puts a whole agent in a sandbox generated
from the policy, with network only through an `openmoat proxy` it starts (ADR-018):

```bash
openmoat run --write ~/.claude --write ~/.claude.json -- claude
```

The two `--write` paths are Claude Code's own state, which it must write to run. They
also hold what Claude Code starts in its next session, outside any sandbox (MCP servers
in `~/.claude.json`, plugins in `~/.claude/plugins/`), and in this tier every command the
agent runs shares that grant. The hook holds the agent's own tools' writes of one for review
(`runs-later`); a script it runs is not held. Where the agent's own sandbox is
available, the Standard tier keeps its commands out of the home altogether. On Linux
without a network namespace (below) `openmoat run` refuses every `--write` path
outside the project, `~/.claude` included, which holds `settings.json`: install
bubblewrap.

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
  sockets (no UDP, Unix sockets or `ptrace`) and only stream and sequenced-packet
  socket pairs (a datagram pair could be sent to a pathname socket outside), no TCP
  Fast Open send
  (`MSG_FASTOPEN`, which connects without the `connect()` Landlock checks), refuses
  the kernel keyrings (`keyctl`,
  `add_key`, `request_key`), refuses new namespaces (`unshare`, and `clone` with a
  namespace flag; `clone3`, whose flags a filter cannot read, answers `ENOSYS`, so the
  C library falls back to `clone`) and joining an existing one (`setns`, so `nsenter`
  and a container runtime's `exec` fail), and refuses `pidfd_getfd` (copying an open
  file of another process; `pidfd_open` stays). Containers, bubblewrap and Chromium's own
  sandbox cannot start inside. Windows refuses.
- **Newer Linux kernels (the Landlock ABI ladder, ADR-082).** `openmoat run` needs
  Landlock ABI 4 and adds what a newer kernel has beside the seccomp filter, never in
  its place, so an older kernel keeps exactly the protection above:

  | Landlock ABI | First Linux | What `openmoat run` does with it |
  |---|---|---|
  | 4 | 6.7 | required: files and the proxy's TCP port |
  | 5 | 6.10 | not used (device `ioctl`): the terminal's own calls must work; seccomp refuses `TIOCSTI` and `TIOCLINUX` |
  | 6 | 6.12 | used: abstract Unix sockets and signals outside the sandbox refused |
  | 7 | 6.15 | not used (kernel audit logging): OpenMoat's audit log records its own decisions |
  | 8 | 7.0 | not used (one ruleset for all threads): OpenMoat's proxy thread must stay outside |
  | 9 | 7.1 | used: a pathname Unix socket made outside the sandbox cannot be connected or sent to |
  | 10 | 7.2 | not used yet (UDP): the `landlock` crate cannot ask for it; seccomp refuses UDP |
  | 11 | 7.3 | nothing to add (`no_new_privs` is set already) |
  | 12 | 7.4 | not used yet (capabilities, namespaces): seccomp refuses new namespaces |

  `openmoat doctor` shows the kernel's ABI and what applies (each step with
  `--verbose`), as do `openmoat sandbox show` and `openmoat run --verbose`, and every
  run writes the ABI Landlock reported when the agent's rules applied to the audit log,
  in its boundary row (rule `run-boundary`, [above](#the-runs-boundary-record)):

  ```bash
  openmoat doctor --verbose          # landlock  Landlock ABI 6 here: `openmoat run` applies ABI 4, 6; …
  openmoat sandbox show --format json | jq .lightweight.landlock.abi
  ```
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
  by port only, and `openmoat doctor` warns. `openmoat run --netns=require` refuses to
  start there instead (exit 64); the default, `--netns=auto`, is the behaviour above.
  A policy with `require.run: full-boundary` ([POLICY.md §9.3](POLICY.md#93-requiring-openmoat-runs-full-boundary-requirerun))
  refuses there too, whatever `--netns` says.
- **Files the launcher left open.** Landlock and Seatbelt check a path when it is
  opened, not a descriptor opened before, so a file, socket or directory that the
  shell, IDE or CI runner starting `openmoat run` left open (`exec 3<~/.ssh/id_rsa`)
  would read past every rule. Before the agent starts, `openmoat run` marks every
  descriptor from 3 up close-on-exec (`close_range` on Linux, else a walk of
  `/proc/self/fd` or `/dev/fd`; on macOS the walk), so the agent gets only standard
  input, output and error, and a read of another fails with `EBADF`. Where that cannot
  be done, `openmoat run` refuses to start the agent (ADR-088).

  ```bash
  bash -c 'exec 3<~/.ssh/id_rsa; openmoat run -- sh -c "cat <&3"'   # sh: 3: Bad file descriptor
  ```

  Process substitution is a descriptor too: `openmoat run -- tool <(cmd)` gives `tool`
  `/dev/fd/63`, which it can no longer open. Write the output to a file in the project
  first, or pipe it on standard input (`cmd | openmoat run -- tool -`).
- **Paths the policy denies inside the project (Linux, ADR-090).** Landlock can only
  grant access to whole directory trees, so a deny rule inside a granted tree needs
  something besides Landlock:
  - **With a network namespace** (bubblewrap installed and allowed), the namespace
    covers the project as `--isolate` does (below): every `.env` file there is hidden
    (`EACCES`), `.git`, `.moat` and the agents' configuration are bound read-only
    (`EROFS`), and a missing `.env`, `.envrc` or `.moat` directly in the project gets an
    empty placeholder for the session. `git commit` inside the run therefore fails, as
    under `--isolate` and on macOS: commit outside it. CI files and commit-hook
    managers' files stay writable, as on macOS. A match created after the start where
    nothing stood (`.env.local`, a `.env` in a new folder) stays open.
  - **Without one**, the project is granted entry by entry: the project folder only for
    listing, each entry at its top on its own, none for an entry whose reading the
    policy denies (`.env`), read-only for one whose writing it denies (`.git`, `.moat`),
    and the folders that hold an agent's settings (`.claude`, `.github`, `.moat`) the
    same way one level down. A tree that holds the project (a read root such as `/tmp`)
    is granted around it. So commands cannot read `.env` there, write `.git` or
    `.moat`, or create `.envrc`, `.moat` or a hook. **The cost:** they cannot create,
    rename or remove anything directly at the project's top either (a new file, a
    `target/` that does not exist yet, an editor's save through a new file and a
    rename); everything inside an existing folder works as before. Create what is
    needed before the run, or install bubblewrap. A `.env` in a subfolder, or a nested
    `.git`, lies in a folder granted whole and stays open.
  - **Opting out, on record.** Where you need new entries at the top and cannot install
    bubblewrap, `sandbox.project_top: writable` in your own policy
    ([POLICY.md §9.4](POLICY.md#94-the-projects-top-without-bubblewrap-sandboxproject_top))
    grants the project whole again in this case only: commands can then read and write
    `.env`, write `.git/hooks` and `.moat`, and create `.envrc` at the top. `openmoat
    run` says so before the agent starts, writes `run-project-top-open` to the audit log
    on every such run, and `openmoat doctor` warns. A repository policy cannot set it,
    and `require.run: full-boundary` still refuses to start without the namespace.

  ```text
  moat run: without bubblewrap the project is granted entry by entry: commands cannot create, rename or remove entries directly in it (create what they need before the run), `.env` files there stay unreadable and `.git` and `.moat` read-only. These paths the policy denies lie in a folder granted whole and stay open to commands: /home/me/proj/sub/.env. …
  ```

  Before the agent starts, `openmoat run` says which of these applies and names each
  path the policy denies in the project that stays open, up to eight and a count;
  `openmoat doctor` on Linux without a namespace names the same for the current
  directory. [EVIDENCE.md](EVIDENCE.md) shows both columns. The hook still decides the
  agent's own tool calls on all of them. `status` and `doctor` name `openmoat run
  --isolate` for an agent without a sandbox of its own. Outside the project, where the agent gets
  a network namespace, each existing file or directory a deny rule names without a
  glob inside a read root or a `--write` path is covered for the session as under
  `--isolate` (hidden, or bound read-only for a write deny): `~/.cargo/credentials.toml`
  stays unreadable and, with `--write ~/.claude`, `~/.claude/settings.json` unwritable.
  `openmoat run` grants a `--write` path where it resolves, so each deny is compared
  where it resolves too: with `~/.claude` a link to another folder, the mask is put on
  `settings.json` in that folder. Without a namespace these stay open, and `openmoat run` names them on every start;
  a `--write` path that holds what `kernel-self` protects (OpenMoat's state, an
  agent's hook settings, existing or not) or lies inside a tree it protects whole
  (`~/.codex/sessions`) refuses to start instead (exit 64), naming the paths. So does
  every `--write` path outside the project: `kernel-self` protects hook settings at
  any depth (`**/.claude/settings.json`), and any directory can hold another
  repository. Install bubblewrap and allow unprivileged user namespaces, or grant
  only paths inside the project.
- **Agents' configuration in the project.** Commands may not write the files an agent
  loads as its own hooks, MCP servers or extensions in its next session: a project's
  `.claude/hooks/`, `.mcp.json`, `.cursor/mcp.json`, `.codex/config.toml`,
  `.github/hooks/`, `.github/mcp.json`, `.openclaw/extensions/`, `.pi/extensions/`,
  `.pi/mcp.json`, `.pi/settings.json`, OpenCode's `opencode.json[c]` and its
  `.opencode/` plugins, tools and `opencode.json[c]`, at any depth. On macOS Seatbelt denies them
  after every grant, in either case on a case-insensitive disk (`.MCP.json` too), so
  this holds inside a `--write` path too, and also for a write the hook held for review
  and the person allowed: change one outside `openmoat run`. The folders that hold
  them directly in the project (`.github`, `.pi`, `.openclaw`, `.opencode`, besides `.claude`,
  `.codex` and `.cursor`) cannot be created, renamed or removed there either, since a
  folder renamed away and back would carry a hook written under the other name; create
  a missing `.github` outside `openmoat run`. CI files and commit-hook managers' files
  (`.github/workflows/`, `.husky/`, …) stay writable, since installs write them; the
  hook holds the agent's own tools' writes of them for review (`runs-later`). On Linux, where the
  agent gets a network namespace, each of them that exists in the project when the
  agent starts is bound read-only for the session, as are the agents' hook
  settings there (`.claude/settings.json`, `.cursor/hooks.json`, `.codex/hooks.json`,
  `.gemini/settings.json`, `.github/copilot/settings.json`, `.copilot/hooks/`), and
  each folder holding them directly in the project is bound onto itself so it cannot
  be renamed; `--isolate` does the same. A folder of an agent's configuration
  (`.claude/hooks/`, `.github/hooks/`, `.pi/extensions/`, `.openclaw/extensions/`,
  `.opencode/plugins/`, …) missing where the folder that holds it exists, or is made
  for the hook settings below (`.claude`, `.github`), is created empty for the session
  and bound read-only, so a hook written into it later is refused (`EROFS`); it is
  removed when the last session in the project exits if it is still empty (ADR-090).
  Where that folder is missing (`.pi`, `.opencode`, `.openclaw`, `.hermes`), a command
  can still create it and write there. If the project is too large to walk (more than a
  million entries) or holds a name that is not UTF-8, the namespace covers only the
  project's top and the folders directly in it, and `openmoat run` says so. Without a namespace the project is granted entry by entry (above): none
  of these can be created at its top or in `.claude`, `.github` and the other folders
  that hold them. A hook settings file that does not exist yet
  (`.claude/settings.local.json`, `.gemini/settings.json`,
  `.github/copilot/settings.local.json`, `.codex/hooks.json`, `.cursor/hooks.json`, …)
  would let a command turn the next session's hook off, so in the namespace and under
  `--isolate` `openmoat run` creates it for the session (`{}` for a JSON file, which
  every agent reads as settings that change nothing; a folder for `.copilot/hooks/`),
  with the folders above it, binds the file read-only and the folders onto themselves,
  and removes them when the agent exits while they are still as made. `git status`
  shows them during the session; leave them out of commits. An agent configuration
  file missing at the start (`.mcp.json`, `.cursor/mcp.json`), one in a folder created
  during the session, a hook settings file below a link, and, without a namespace, one
  inside a folder granted whole (`sub/.claude/settings.json`) stay writable; without a
  namespace `openmoat run` names, when the agent exits, each hook settings file that
  was missing at the start and exists now:

  ```text
  moat run: .gemini/settings.json did not exist when the agent started and does now; ...
  ```
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
  No other terminal is reachable: the sandbox opens only `/dev/tty` and the terminal
  devices `openmoat run`'s standard input, output and error are on, not the person's
  other terminals (`/dev/ttys*`, `/dev/pts/*`). A program that opens a new
  pseudo-terminal inside (`script`, `expect`, a terminal library such as `node-pty`)
  is not granted the new terminal's device either, so it can fail there; run it
  outside `openmoat run`.
- The agent and every command it starts may read the project, `sandbox.read_roots`,
  the temp directory and the agent's own executable; never the keychain. They may
  write the project, the run's own temp directory and each `--write` path (the agent's
  state). That temp directory is new for each run: `openmoat-run-<random>` (mode `0700`)
  inside the system's, given to the agent as `TMPDIR` and removed with everything in it
  when the run ends. The shared temp directory (`/tmp` on Linux, `/var/folders/…/T` on
  macOS) holds other programs' state and other sessions' files, so commands can neither
  write nor read it, whatever `sandbox.read_roots` lists for the host sandboxes (on macOS
  the per-user caches `/var/folders/…/C` and `/var/folders/…/0` stay readable, which
  system libraries read whatever `TMPDIR` says). To let a run read a file there, copy it
  into the project or name it with `--write`. A tool that honours
  `TMPDIR` (compilers, `npm`, `pip`, `cargo`, `go`, `mktemp`) works as before; a
  command that writes a fixed `/tmp/<name>` fails with "permission denied", as it did on
  macOS already:

  ```bash
  openmoat run -- sh -c 'echo x > "$TMPDIR/f" && echo ok'   # ok
  openmoat run -- sh -c 'echo x > /tmp/f'                    # Permission denied
  openmoat run -- sh -c 'cat /tmp/other-programs-file'       # Permission denied
  ```

  Kerberos ticket caches stay closed: `kerberos-tickets` denies `/tmp/krb5cc_*`, where MIT
  Kerberos and Heimdal keep them by default (`hook_only` for the host sandboxes), and
  `openmoat run` applies it in its sandbox and adds the cache `KRB5CCNAME` names
  (`FILE:` or `DIR:`) for the run. On Linux `/tmp` is no read root of the run, so Landlock
  refuses a cache there with or without a network namespace. A cache that is no file is
  closed as well: `KCM:` (the `sssd-kcm` socket) and `KEYRING:` by the seccomp filter on
  Linux, `KCM:` and `API:` on macOS because the profile allows no ticket service.
  Deny rules still win (`~/.claude/settings.json` stays unwritable; on Linux only where
  the agent gets a network namespace, above).
- **Agent logins.** The agent reads its own login inside the sandbox, so `openmoat run`
  finds which agent it starts (the command as typed, or the file it resolves to, by each
  agent's program names and install directories) and leaves that agent's login files
  out of `agent-credentials` for this sandbox, listed as `run.own-login`. Every other
  agent's login stays denied, inside a `--write` path too (on Linux where the agent gets
  a network namespace; without one Landlock lists it as `landlock.inside-grants`). For a
  program that is no agent OpenMoat knows (`npx …`, an MCP server under
  `openmoat mcp wrap --sandbox`), the login files inside its `--write` paths stay
  readable instead. The commands the agent runs share its login here; for an API-key
  login, [BROKER_LOGINS.md](BROKER_LOGINS.md) keeps the key out of the sandbox. The hook
  still denies the agent's own tools reading its login.
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
- A secret with `tls: terminate` (ADR-043) is put into HTTPS here and nowhere else:
  the run's proxy decrypts the agent's tunnel to that host with a certificate its own
  CA signs, puts the value in, refuses a request the secret's `allow` rules do not name
  and stops an answer before any brokered value in it. The CA is made by
  `openmoat proxy ca init` (a person at a terminal) in `~/.moat/proxy-ca/` and pinned in
  the lock; a policy with such a secret and no pinned CA makes `openmoat run` refuse to
  start. Only the commands the run starts trust it: `openmoat run` writes the
  certificate, and a bundle of the system's roots with it, to a private directory under
  the temp directory for the session and names the files in the run's environment
  (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
  `CARGO_HTTP_CAINFO`; `NODE_EXTRA_CA_CERTS` gets the certificate alone). Nothing is
  added to the system's or the person's trust store, and the standalone `openmoat proxy`
  of the Standard tier never terminates. `~/.moat/proxy-ca/` itself stays out of reach
  of sandboxed commands: `kernel-self` denies reading it, and every sandbox OpenMoat
  writes keeps it out (Seatbelt, Landlock and bubblewrap here, where the state directory
  is in no grant; Claude Code's `denyRead` and `Read(//…)` rules; Codex's and Cursor's
  sandboxes, which grant named paths only).
- Turn the agent's own sandbox off inside: sandboxes do not nest, so Claude Code's
  `sandbox.enabled` (which `openmoat init` turns on) fails there and Codex needs
  `--sandbox danger-full-access`. Credentials must not come from the keychain: use
  an API key or `apiKeyHelper`.
- Before the agent starts, `openmoat run` prints how many places the sandbox is stricter
  or wider than the policy; `openmoat run --verbose` lists each one (`openmoat sandbox show`
  prints the same for the current directory). Linux is wider than macOS in places (the
  paths inside the project created after the start, or below a folder granted whole
  without bubblewrap, and, without bubblewrap, the proxy's port on any host; `--isolate`
  closes the port and the deeper paths, below); see [THREAT_MODEL.md](THREAT_MODEL.md).

It is weaker per command than the Standard tier: the agent and its scripts share one
sandbox, so whatever the agent needs, `npm test` gets too. On macOS and Linux alike,
data can still leave through the hosts the policy allows: the proxy checks the host,
and the secrets broker blocks a brokered secret it can see, but it cannot read inside
HTTPS, except the tunnel to the host of a secret that says `tls: terminate`, which it
terminates (above, ADR-043). It applies the session's taint from the agent sessions whose hooks linked
themselves to the run ([THREAT_MODEL.md](THREAT_MODEL.md) §5, ADR-027).

The agent's hooks run inside the sandbox too, where `~/.moat` is closed to them. They
send each tool call to the `openmoat run` process over the proxy's port, with a token made
for the run (`MOAT_GUARD_SOCKET`, `MOAT_GUARD_TOKEN`), and that process decides and
records it outside the sandbox (ADR-028). Tool commands of the agents ADR-075 names do
not receive those variables: `openmoat run` starts them through a small wrapper from a
directory commands cannot write. A command cannot read them from the agent either: the
macOS profile denies `kern.procargs*` (`ps eww`), and on Linux no grant covers `/proc` and
a wrapped command gets a Landlock layer of its own. The relay itself needs no new rule:

- macOS: the profile's one way out stays `(allow network-outbound (remote ip
  "localhost:<port>"))`; no Unix socket is allowed.
- Linux: Landlock restricts connecting to a Unix socket by path only from ABI 9
  (Linux 7.1), which `openmoat run` adds where the kernel has it (ADR-082); below it
  ABI 6 scopes only abstract sockets, which is why the seccomp filter refuses Unix
  sockets and datagram socket pairs on every kernel. The relay uses the proxy's TCP port, so that
  filter and the Landlock port rule stay as they are, in the network namespace and
  under `--isolate` too.

If the token is wrong, the connection fails or no answer comes within the hook's
10 s, the hook denies the call.

[EVIDENCE.md](EVIDENCE.md) lists what `openmoat run` does to hostile project scripts on
macOS and Linux (reading keys and credentials, writing outside the project, direct
connections, DNS, symlinks out of the project, editing the policy), as CI asserts it on
every pull request, with the Linux gaps marked.

## `openmoat run --isolate` (Isolated tier, Linux)

On Linux the Isolated tier runs the agent in its own view of the machine, built with
[bubblewrap](https://github.com/containers/bubblewrap) (ADR-018). It is the default where
bubblewrap works; `--isolate` asks for it and refuses where it cannot start:

```bash
openmoat run --isolate --write ~/.claude --write ~/.claude.json -- claude
```

- **What it sees.** Only the project, `sandbox.read_roots`, the agent's executable,
  the `--write` paths and an empty temp directory, each at its usual path. The rest
  of the home directory (`~/.ssh`, `~/.aws`, other projects) does not exist in there.
- **What it hides inside them.** Every path the policy denies that exists when the
  session starts: a denied read (the project's `.env` files, `~/.cargo/credentials.toml`)
  is covered by an empty placeholder no one may open (`EACCES`), and a denied write
  (`.git`, `.claude/settings.json`) by the path itself, read-only; a folder that is
  read-only covers files created in it later too (a new hook in `.git/hooks` fails with
  `EROFS`). `.env`, `.envrc` and `.moat` directly in the project are covered even when
  they are missing: OpenMoat creates an empty placeholder file there for the session
  and removes it afterwards, and a `.env` the person writes there during the session
  stays unreadable to commands. So are the folders of an agent's configuration
  (`.claude/hooks/`, `.github/hooks/`, …) missing where their holder exists or is made
  for the hook settings (`.claude`, `.github`): each is created empty and bound
  read-only, so a hook written there later is refused, and removed afterwards while
  still empty and no other session in the project still runs (ADR-090). Where the
  holder is missing (`.pi`, `.opencode`, `.openclaw`, `.hermes`), a command can still
  `mkdir -p .pi/extensions` and write an extension there.
- **Writes** go only to the project, the temp directory (in memory, gone when the
  session ends) and the `--write` paths.
- **Network** goes only to OpenMoat's proxy: the agent has its own network namespace
  with nothing but loopback, where OpenMoat serves the proxy's port and relays each
  connection over a Unix socket to the proxy outside. A tool that ignores
  `HTTP(S)_PROXY` has no network; there is no DNS.
- **No files from the launcher.** bubblewrap passes every open descriptor on, so
  `openmoat run` marks those from 3 up close-on-exec before it starts bubblewrap, and
  again inside before the agent starts, as in the Lightweight tier (ADR-088).
- Inside, the Lightweight tier's Landlock rules and seccomp filter apply too, so
  Linux 6.7 or later is needed. The agent's own sandbox must be off, as under
  `openmoat run`.
- **No user namespaces of its own.** Where bubblewrap accepts `--disable-userns`
  (0.8 and later), OpenMoat passes it, so the agent cannot create further user
  namespaces inside. Only a bubblewrap that does not know the option (`Unknown option
  --disable-userns`, before 0.8) runs without it; any other failure with it refuses.

It needs `bwrap` in `/usr/bin`, `/bin` or `/usr/local/bin` (`apt install bubblewrap`, `dnf install bubblewrap`; never taken from `PATH`, since it starts outside the sandbox) and
unprivileged user namespaces; on Ubuntu 24.04 AppArmor restricts them unless
`kernel.apparmor_restrict_unprivileged_userns` is 0 or an AppArmor profile allows
`bwrap`. Where bubblewrap is missing or cannot create its namespaces, `openmoat run
--isolate` refuses (exit 64) and never falls back to the Lightweight tier; a plain
`openmoat run` says why and starts the Lightweight tier, on record (above).

macOS: tracked in [ADR-023](adr/ADR-023-isolated-tier-macos.md), first stub ships
here. On macOS `openmoat run --isolate` refuses with exit 64 and names what is missing:
Apple's `container` CLI if the toolchain is not installed (install hint included),
or "not yet implemented, see ADR-023" when it is. The ADR picks Apple's
`containerization` toolchain for the implementation (its note of 2026-10-12 corrects
what it assumed about that toolchain and lists open questions) and lists the follow-up PRs
under [#175](https://github.com/crocodile-labs/openmoat/issues/175). Never a silent
fallback to the Lightweight tier.

Limits:

- A match of a deny rule created after the session starts where no placeholder or
  read-only folder stood (`.env.local` written during the session, a `.env` in a new
  subdirectory, an agent configuration folder in a holder folder created during the
  session) is not hidden; the hook still decides the agent's own tool calls on it.
  ADR-090 designs, without building it yet, a copy workspace for unattended runs that
  would close this: the agent works in a copy or overlay of the project without the
  denied paths, and its changes come back only through a person, as `openmoat restore`
  brings back a snapshot (ADR-085).
- The agent and its commands still share one sandbox, as under `openmoat run`.
- Ctrl-C ends the whole session unless the agent reads the terminal itself (Claude
  Code's and Codex's interfaces do).
- A project with more than a million files and directories is refused: each is looked
  at to find what to hide.

### Agents OpenMoat writes no sandbox for

`openmoat status` and `openmoat doctor` print the command for each agent at `hook only`
that OpenMoat writes no sandbox for, with the directories that agent writes
(`os_sandbox` in `--format json`, ADR-076). On Linux `run` is `run --isolate`:

```text
OS sandbox: openmoat run --write ~/.gemini -- gemini (docs/SANDBOX.md)
```

| Agent | Command (macOS 13 or later; Linux adds `--isolate`) |
|---|---|
| GitHub Copilot CLI | `openmoat run --write ~/.copilot --write ~/Library/Caches/copilot -- copilot` (`~/.cache/copilot` on Linux) |
| Gemini CLI | `openmoat run --write ~/.gemini -- gemini` |
| pi | `openmoat run --write ~/.pi/agent -- pi` |
| OpenCode | `openmoat run --write ~/.local/share/opencode -- opencode` |
| Hermes Agent | `openmoat run --write ~/.hermes -- hermes` |
| Cline CLI | `openmoat run --write ~/.cline -- cline` |
| goose | `openmoat run --write ~/.local/share/goose --write ~/.local/state/goose -- goose` |
| Antigravity CLI | `openmoat run --write ~/.gemini/antigravity-cli -- agy` |

On macOS before 13, on Windows, and on Linux without a network namespace (where
`openmoat run` refuses a `--write` path outside the project) those commands name why
there is none. OpenClaw and the Continue CLI get no command: OpenClaw's Gateway serves a
local port, which the sandbox does not allow, and which directories `cn` writes was not
checked.

What the command does not do for you:

- The agent's install directory must be readable (`sandbox.read_roots`) and its API host
  allowed by the policy, as for the Cursor CLI below.
- A login kept in the system keychain or keyring (GitHub Copilot CLI, Gemini CLI, the
  Antigravity CLI) cannot be read inside; use an API key.
- These directories come from each agent's documentation. A directory it does not name
  shows up as a refused write when the agent runs; add it with another `--write`.
- CI starts a stand-in named as each agent with exactly this command; no real agent has
  been run under it here. The Antigravity CLI has not been run at all.
- A wrapped MCP server does not start inside `openmoat run` (ADR-049); its calls could not
  be checked there. `openmoat status` says so when the agent has one. An unwrapped server
  runs inside the agent's own sandbox.

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
