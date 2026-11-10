# Limits

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know what OpenMoat does not stop, before you rely on it.

**On this page:** [Approvals and prompts](#approvals-and-prompts) · [Sandboxes and allowed code](#sandboxes-and-allowed-code) · [What the hook does not see](#what-the-hook-does-not-see) · [When an agent skips or changes the check](#when-an-agent-skips-or-changes-the-check) · [Limits of single checks](#limits-of-single-checks)

OpenMoat checks the tool calls an agent's hook reports. It does not confine every call.
If its own check errors or hangs, OpenMoat blocks the call; the agents that still run a
call when the hook fails are listed under
[When an agent skips or changes the check](#when-an-agent-skips-or-changes-the-check).
Each agent's gaps and the reasons are in
[THREAT_MODEL.md §5](THREAT_MODEL.md#5-known-limitations).

## Approvals and prompts

- **A deferred call runs if your agent lets it.** In auto-approve modes
  (`--dangerously-skip-permissions`, Run Everything) only `deny` and `review` stop a call.
- **Some agents cannot prompt.** Codex, OpenCode 1, goose, the Cline CLI (where the deny
  also ends Cline's run), Cursor's file tools, pi in print and JSON mode, and Hermes Agent
  in YOLO mode receive a `review` as a deny that says how to approve the call
  (`openmoat`, or `openmoat allow --last`); GitHub Copilot CLI in autopilot turns it into
  a deny itself.
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

## Sandboxes and allowed code

- **Outside an OS sandbox, the hook decides alone.** For hook-only agents (OpenClaw,
  GitHub Copilot CLI, pi, Gemini CLI, OpenCode, Hermes Agent, the Cline CLI, goose, the
  Antigravity CLI, and
  Claude Code and Cursor on native Windows), an allowed call runs with your permissions,
  so a classifier mistake is a bypass. `openmoat status` and `openmoat doctor` name the
  `openmoat run` command that puts each of them in an OS sandbox, or say why there is none
  (macOS before 13, Windows, Linux without bubblewrap; OpenClaw's Gateway and the Continue
  CLI have no command, [SANDBOX.md](SANDBOX.md#agents-openmoat-writes-no-sandbox-for)).
  The command is proved with a stand-in program, not the real agent. Claude Code's sandbox covers only `Bash`,
  `PowerShell` and `Monitor`; its file tools, `WebFetch` and MCP servers run outside it.
  Cursor runs some commands outside its sandbox.
- **`require.run: full-boundary` is about `openmoat run`.** It refuses a run without an OS
  sandbox or, on Linux, without the Isolated tier (ADR-080). An agent started without
  `openmoat run` is not refused
  ([POLICY.md §9.3](POLICY.md#93-requiring-openmoat-runs-full-boundary-requirerun)).
- **`openmoat run` keeps an inherited variable from the agent only under
  `require.run: full-boundary`.** Otherwise every variable reaches it except brokered
  secrets, and one line warns. Under the setting an agent's own key stays on the list, so
  its commands can read that key, and a value kept in a file or keychain is outside it.
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
- **On Linux, the Lightweight tier does not protect files inside the project:**
  commands the agent starts can read and write `.env`, create `.envrc`, and write `.moat`
  and `.git/hooks`. `openmoat run` starts the Isolated tier (bubblewrap), which closes it,
  by default where bubblewrap works (ADR-080); the Lightweight tier runs with
  `--no-isolate` or where bubblewrap is missing or blocked, and then `openmoat run` says so
  when it starts, records it in the audit log and `openmoat doctor` warns. The Isolated
  tier shows the agent only the project, the read roots and `--write` paths, so an agent
  whose runtime lives elsewhere in the home (a `node` under `~/.nvm`) can fail to start in
  it until that directory is in `sandbox.read_roots`; this was not tried with every agent.
  An agent's hook settings in the
  project (`.gemini/settings.json`, `.claude/settings.local.json`, …) are protected where
  the agent gets a network namespace, missing ones by a read-only `{}` placeholder for the
  session; without a namespace a command can create one that turns the next session's
  hook off, and `openmoat run` only names it when the agent exits.
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
  from an allowed command: the proxy checks the host, not what is sent inside HTTPS.
- **A program that runs as you outside any sandbox** can change the policy and
  recompute the lock. Only the OS sandboxes stop that, so hook-only agents do not have
  this protection.
- **The check and the call are two moments.** OpenMoat decides on what the call names;
  a file or link that changes between the check and the command running, and hard
  links that already exist, are not seen. Inside `openmoat run` the OS sandbox still
  holds ([THREAT_MODEL](THREAT_MODEL.md), ADR-009).

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

- **Some agents run a call when the hook fails.** Codex, and Claude Code before
  2.1.295, run a call unchecked if `openmoat` is missing. Codex also skips untrusted
  hooks: after `openmoat init`, open Codex, run `/hooks` and trust the OpenMoat hook;
  `status` and `doctor` report missing trust and broken legacy entries. GitHub Copilot
  CLI and Gemini CLI run a call whose hook times out. OpenClaw, pi and OpenCode run calls
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
  something that is not JSON or is killed after 120 s, and under `--yolo`, which runs no
  hooks. goose runs calls unchecked when it does not load OpenMoat's plugin
  (`disabledPlugins`, `enabled: false` under `plugins` in `config.yaml`, or a project
  plugin named `openmoat`); `openmoat status` and `doctor` report both, for the directory
  they run in. The Antigravity CLI does not document what happens when a hook cannot start,
  crashes, times out or prints bad JSON, and has no documented setting that blocks then, so
  OpenMoat assumes the call runs there; `--dangerously-skip-permissions` approves its
  requests unseen, which OpenMoat cannot see, and a `review` under a saved
  `toolPermission: always-proceed` is a deny. Antigravity CLI is a preview host: its
  support is built from the documentation, and in the weekly check of 2026-11-10 a
  headless agy 1.5.5 turn started no hook from `~/.gemini/config/hooks.json` while the
  fake API received tool results for both of its calls (the host's `HOST.md`, "The first
  real run").

### If the hook fails

What each agent does with a tool call when OpenMoat's hook fails in a way the hook
cannot catch itself (its binary is gone, it is killed, the host's time limit runs out),
or is turned off. The time limit is the one `openmoat init` installs, or OpenMoat's
plugin's own. "Fails open" means the call runs unchecked in that case; `openmoat doctor`
names such an agent under its row with what to do: start it with `openmoat run`, whose OS
sandbox holds the boundary when the hook does not (`docs/SANDBOX.md`), and add
`require.run: full-boundary` to the policy so `openmoat run` refuses to start without it.
The weekly latest-agent job runs the real agents with the hook made to fail and fails
when an agent runs a call this table says it blocks (ADR-079). Generated from each host's
`HostSpec::hook_failure` (`OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test
docs`); do not edit the table.

<!-- generated:hosts-hook-failure -->
| Agent | Hook cannot start, crashes or exits non-zero | Hook times out | Time limit | Turned off (every call runs unchecked) | Fails open | Source |
|---|---|---|---|---|---|---|
| Claude Code | blocks the call from 2.1.295 (`openmoat init` asks for it); runs it before | blocks the call from 2.1.295 (`openmoat init` asks for it); runs it before | 600 s | `disableAllHooks: true` in a settings file (a project's included), `--settings '{"disableAllHooks": true}'`, or deleting the entry | before that version: cannot start, crashes or exits non-zero; times out | [1](https://code.claude.com/docs/en/hooks) |
| Codex | runs the call | runs the call | 600 s | `[features] hooks = false` in `config.toml` (or `requirements.toml`), turning the hook off in `/hooks`, or a hook Codex has not been told to trust | yes: cannot start, crashes or exits non-zero; times out | [1](https://learn.chatgpt.com/docs/hooks) [2](https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/hooks/src/engine/command_runner.rs#L417) |
| Cursor | blocks the call | blocks the call | 600 s | deleting the entry from `hooks.json`, or an entry without `failClosed: true` (`openmoat status` calls that not protected) | no | [1](https://cursor.com/docs/agent/hooks) |
| OpenClaw | blocks the call | blocks the call | 45 s | a Gateway that does not load the plugin (disabled in `openclaw.json`, or a load error, which leaves the Gateway running) | no | [1](https://docs.openclaw.ai/plugins/hooks/reference) |
| GitHub Copilot CLI | blocks the call | runs the call | 600 s | `disableAllHooks: true` in a hook file or in a repository's `settings.json`, or deleting the hook file | yes: times out | [1](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference) |
| pi | blocks the call | blocks the call | 45 s | `pi --no-extensions`, or an `extensions` entry in pi's or a trusted project's settings that turns the extension off | no | [1](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) |
| Gemini CLI | runs the call | runs the call | 600 s | `hooks` turned off in the user's or a project's `settings.json`, or a folder Gemini CLI does not trust (which runs no settings hooks) | yes: cannot start, crashes or exits non-zero; times out | [1](https://geminicli.com/docs/hooks/reference/) |
| OpenCode | blocks the call | blocks the call | 45 s | OpenCode 1's `--pure` or `OPENCODE_PURE`, OpenCode 2's `-openmoat` in `plugins` (a project's included), or an error loading the plugin | no | [1](https://opencode.ai/docs/build/plugins/server) |
| Hermes Agent | blocks the call | blocks the call | 30 s | the hook missing from `config.yaml` or from `shell-hooks-allowlist.json` (gateway, cron and ACP sessions), another profile, or `HERMES_SAFE_MODE=1` | no | [1](https://github.com/NousResearch/hermes-agent/blob/v0.22.5/agent/shell_hooks.py) |
| Cline CLI | blocks the call | runs the call | 120 s | `--yolo`, or `--config`, `--hooks-dir` or a moved `CLINE_DIR` OpenMoat did not install into | yes: times out | [1](https://github.com/cline/cline/blob/cli-v3.0.74/sdk/packages/core/src/hooks/hook-file-hooks.ts) [2](https://github.com/cline/cline/blob/cli-v3.0.74/sdk/packages/core/src/hooks/subprocess-runner.ts) |
| goose | blocks the call | blocks the call | 60 s | `disabledPlugins` in a `settings.json`, `enabled: false` under `plugins` in `config.yaml`, a project plugin named `openmoat`, or a `hooks.json` goose cannot read | no | [1](https://github.com/aaif-goose/goose/blob/v1.57.0/crates/goose/src/hooks/mod.rs) |
| Antigravity CLI | not documented; assumed to run the call | not documented; assumed to run the call | 600 s | `enabled: false` on the entry (a project's `.agents/hooks.json` included), or deleting it | yes: cannot start, crashes or exits non-zero; times out | [1](https://antigravity.google/docs/hooks?tab=cli) |
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
  `openmoat status` reports it.
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

- **After an upgrade, a policy edit or a move to another project, a long session's
  first calls may be refused.** OpenMoat works out the session's taint from its earlier
  calls again under the new version, policy or project, and a call it cannot decide in
  time is denied (`kernel-error`) rather than judged on part of the session. What it read
  is kept, so each try reads on; the agent's `PostToolUse` hook (Claude Code, the Cline
  CLI) reads on after a call ran too. A move to another folder of the same project
  starts over only when some of the session's calls were recorded without a working
  directory. `openmoat doctor` lists these denials of the last day
  ([ARCHITECTURE.md, "Session cache"](ARCHITECTURE.md)).

- **Injected input is linked only with Claude Code, the Cline CLI and wrapped MCP
  servers, and only for the same request.** Other agents report no call output (their
  wrapped MCP servers' results are read by the gateway). Another spelling of a planted
  address, a subdomain of a planted URL host and a planted command run through a wrapper
  are linked; a host by another name, a reworded command or a relative path is not
  ([POLICY.md §4.1.2](POLICY.md#412-injected-input)). Only the output of `Bash`,
  `WebFetch`, `WebSearch`, MCP resource reads and MCP tools is read, each kept up to fixed
  bounds, so a page full of decoys can push a planted host out. Fetches, searches and MCP
  calls themselves are not checked against it, and an install without the
  `PostToolUse` entry (`openmoat init` adds it) links nothing
  ([ADR-057](adr/ADR-057-injected-input-and-instruction-files.md)).
- **Sending what a session collected is recorded, not stopped.** A send after the session
  read many files outside the project, or packed them into an archive or an encoding,
  carries `@staging-egress` in the audit log and in `openmoat report`, but no default rule
  decides it yet. Only reads that went through OpenMoat's hook are counted, not files a
  script or program read on its own ([ADR-061](adr/ADR-061-staging-chain.md),
  proposed).
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
