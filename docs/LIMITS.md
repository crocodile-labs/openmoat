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
  GitHub Copilot CLI, pi, Gemini CLI, OpenCode, Hermes Agent, the Cline CLI, goose, and
  Claude Code and Cursor on native Windows), an allowed call runs with your permissions,
  so a classifier mistake is a bypass. Claude Code's sandbox covers only `Bash`,
  `PowerShell` and `Monitor`; its file tools, `WebFetch` and MCP servers run outside it.
  Cursor runs some commands outside its sandbox.
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
- **On Linux, plain `openmoat run` does not protect files inside the project:**
  commands the agent starts can read and write `.env`, create `.envrc`, and write `.moat`
  and `.git/hooks`. `openmoat run` says so when it starts and `openmoat doctor` warns about
  it; `openmoat run --isolate` (bubblewrap) closes it.
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
- **Unwrapped MCP servers start before any call is checked.** An agent starts its MCP
  servers when a session begins; for a server not wrapped with `openmoat mcp wrap`, a
  changed or new server's tool calls are denied, but its command has already run once,
  with your permissions. A wrapped server starts only from a definition you accepted, in
  `openmoat run`'s sandbox where it can sandbox. `openmoat status` lists the servers that
  start outside OpenMoat.
- **A browser goes where the page sends it.** A browser MCP call that only opens a page
  defers like `WebFetch`, and OpenMoat checks the URL it names, but not where the page's
  scripts, links and redirects lead next, nor where its name resolves. What the page says
  marks the session as untrusted, so writes to files that run later need review; installs
  and later pages do not.

## When an agent skips or changes the check

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
  they run in.
- **Agent settings can turn hooks off.** Codex runs a new or changed hook only once you
  trust it in its `/hooks` view, and settings such as `disableAllHooks` (Claude Code,
  Copilot CLI) or `[features] hooks = false` (Codex) turn hooks off. `openmoat status`
  and `openmoat doctor` report the settings they can see. An agent's write of a
  project's `.codex/config.toml`, `.pi/settings.json` or `opencode.json` that turns the
  hook off is denied (`project-settings`) when OpenMoat knows the content the write
  leaves: a whole-file write, an edit whose text is found in the file as it is, or an
  `apply_patch` that replays on it. Any other write of those files (a shell redirect,
  an edit or patch that does not replay exactly, a tool that sends no content) needs
  review, as every other change there does; an agent that answers reviews on its own
  (OpenCode 2 `--auto`) lets it through, and the next session started there runs
  without OpenMoat until `openmoat status` reports it.
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
