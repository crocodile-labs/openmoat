# ADR-040: OpenCode 1 and 2 through one plugin that pins the call it checked

Status: accepted · Date: 2026-10-27 · Builds on ADR-004 (exit codes), ADR-006 (policy
lock), ADR-025 (quiet by default) and ADR-033 (a plugin that runs `openmoat guard`)

## Context

OpenCode 2 (`@opencode/cli`, 2.0.0 from 2026-09-11) installs the same `opencode`
program and reads the same configuration directory as OpenCode 1 (`opencode-ai`), but
loads plugins through a new API. Read in its source at `v2.2.0` (and compared with
`v2.0.0`, `v2.1.0`; every claim with its file and line is in the research note
behind this PR):

- A plugin is a module whose default export is `{ id, setup(ctx) }`; `setup`
  registers `ctx.tool.hook("execute.before", fn)`, which receives `{ tool, sessionID,
  agent, messageID, id, input }`. OpenCode runs every callback in registration order on
  the same object and then picks the tool by `event.tool` and runs it with
  `event.input` (`core/src/tool.ts:105-113,305-314`, `core/src/plugin/hooks.ts:88-95`).
  A throw rejects that call only, and the model sees the message (2.1.0 and later;
  2.0.x turns it into a defect, which still stops the call).
- Plugins register in a fixed order (internal, SDK, instance plugins, then local and
  package plugins, discovered files before configured ones, then internal "post";
  `core/src/plugin/supervisor.ts:99-103`), but any plugin may register a hook at any
  time, so no position is guaranteed to be last. A plugin loaded after OpenMoat's can
  rewrite `tool` or `input` after OpenMoat checked the call, and a `shell`
  `create.before` hook can rewrite the command of a shell OpenCode is about to spawn.
- A configuration entry `-<id>` (or `-*`) in `plugins` (or the old `plugin`) removes a
  loaded plugin; only two built-in ids are exempt. A project's `opencode.json[c]` or
  `.opencode/opencode.json[c]` can therefore switch OpenMoat off, and so can
  `policies` that deny `integration.use` of `plugin:<path>`. `OPENCODE_CONFIG_DIR` in
  2.x *replaces* the global directory (1.x reads it as well).
- A plugin can ask the person: `ctx.permission.assert` prompts and waits, and a
  `permission` `evaluate` hook can force the effect to `ask`.
- OpenCode 1 reads a default export `{ id, server }` from 1.3.4 on and ignores other
  keys; 2.x reads `id` and `setup` and ignores the rest. Before 1.3.4 every export must
  be a function.

## Decision

- **One host id, one plugin file.** `opencode` covers OpenCode 1.3.4 and later and
  OpenCode 2. `integration/openmoat.js` exports `{ id: "openmoat", server, setup }`:
  OpenCode 1 calls `server`, OpenCode 2 calls `setup`. One file means an upgrade from 1
  to 2 (or back) keeps the protection with no `openmoat init`, which two files chosen
  at `init` would not. `InstallSpec::versions` (formerly `unsupported`) names the
  oldest version that loads it (1.3.4) and which hook each major runs through;
  `openmoat init` does not set up an older one, and `status` and `doctor` report it as
  not protected, and name the hook the version on the search path uses.
- **The call that runs is the call that was checked.** Before it runs the guard, the
  plugin clones `input` (`structuredClone`), deep-freezes the clone, and redefines
  `event.tool` and `event.input` as non-configurable accessors that return what was
  checked and throw on assignment. The guard sees exactly what dispatch will read; a
  later plugin that assigns either throws, which rejects the call. This is the
  strongest option the API offers: registering last is impossible (any plugin may
  register later), and a re-check at the latest point would still miss a rewrite
  made after it. For the agent's shell commands, OpenMoat's own `shell` `create.before`
  hook pins `command` and `shell` of the invocation whose command is one it just
  checked, so a shell hook registered after OpenMoat's cannot change them.
  OpenCode 1 keeps its frozen `args` (ADR-033's approach), which a later plugin cannot
  rewrite in place.
- **Asks reach the person on OpenCode 2.** The guard reads the plugin's envelope as
  `execute.before` (`HookEvent::PreToolUse`, which can ask) or OpenCode 1's
  `tool.execute.before` (`PreToolUseNoAsk`, an ask arrives as a deny with the
  `openmoat allow --last` hint, as before). On an ask, the 2.x plugin calls
  `ctx.permission.assert` with action `openmoat`, OpenMoat's reason as the message and
  the call's id as its source, and its `evaluate` hook forces that request to `ask`
  even when OpenCode's rules would allow it; a configured deny, a rejection or no
  answer blocks the call.
- **Removal by configuration.** The person's own `opencode.json`, `opencode.jsonc` and
  `config.json` with a `-openmoat` or `-*` entry, or a policy denying OpenMoat's plugin,
  make `status` and `doctor` report OpenCode as not protected; a project's make them
  warn that OpenCode 2 sessions started there run unchecked. `kernel-self` already
  denies the agent writing the global files and `runs-later` asks before it writes a
  project's; it now also denies the agent setting `OPENCODE_CONFIG_DIR`,
  `OPENCODE_CONFIG` or `OPENCODE_CONFIG_CONTENT`, writing the background service's
  `service*.json` or running `opencode service set|unset` (the service's environment)
  and `opencode plugin add|remove|update` (2.x writes the global configuration).
  When `OPENCODE_CONFIG_DIR` is set, `openmoat init` installs the plugin there, which
  both versions load.
- **The lock does not pin OpenCode's configuration files.** The guard verifies the
  lock, and a removed plugin no longer calls the guard, so a pin would not stop
  OpenCode; it would deny every other agent's calls each time OpenCode rewrites its own
  global file (`Config.update`). The plugin file stays pinned by its bytes.
- **Tools.** 2.x names: `shell`, `read`/`write`/`edit` (`path`), `patch`, `glob`, `grep`,
  `webfetch`, `websearch`, MCP `<server>_<tool>`, `read_mcp_resource`,
  `opencode_worktree_remove` (a write of its directory); `subagent`, `todowrite`,
  `question`, `skill`, `list_mcp_resources`, Code Mode's `execute`,
  `opencode_session_rename`, `opencode_worktree_list` and `opencode_models` are
  ungoverned; any other tool is checked by what its arguments name. 2.x expands `~`
  in paths, 1.x does not. MCP servers are read from `mcp.servers.<name>` and the 1.x
  `mcp.<name>`. On Windows the shell (`pwsh`, `powershell`, Git Bash, `cmd`) is left
  to OpenCode, as for 1.x.

## Consequences

- OpenCode 1.0 to 1.3.3 is no longer set up (it rejects an object export); those
  versions also carry published advisories, and `status` says to upgrade.
- A plugin that legitimately rewrites tool calls or shell commands (a command
  wrapper) makes those calls fail under OpenMoat, as frozen `args` already did on 1.x.
- Not closed, and said in HOST.md and THREAT_MODEL §5: another plugin runs in
  OpenCode's process with the agent's rights and can do anything that code can,
  including replacing a tool's implementation (`tool.transform`), renaming a tool so
  `event.tool` is not the tool that runs, changing a shell's working directory or
  environment, or a shell hook registered before OpenMoat's rewriting the command;
  `--auto` (and `--yolo`, `--dangerously-skip-permissions`) approves OpenMoat's asks
  as it approves OpenCode's own, and the plugin cannot tell; a project's removal is
  reported for the session directory and its project root only; plugin load failures
  fail open.
- The payloads are OpenMoat's own envelope, built from the 2.2.0 source, not captured.
