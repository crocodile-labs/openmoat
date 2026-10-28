# OpenCode (`opencode`)

OpenCode 1 (`opencode-ai` on npm, 1.3.4 and later), through its `tool.execute.before`
plugin hook, checked against the source of OpenCode 1.19.4; and OpenCode 2
(`@opencode/cli`, which installs `opencode` and `opencode2`), through its
`execute.before` tool hook, checked against the source of OpenCode 2.2.0 (and 2.0.0,
2.1.0 where they differ). OpenCode has no command hook: OpenMoat's one plugin
([`integration/openmoat.js`](integration/openmoat.js)) exports `{ id: "openmoat", server,
setup }`; OpenCode 1 calls `server`, OpenCode 2 calls `setup`, and either runs
`openmoat guard --host opencode` (ADR-040). Every fact here comes from
[`opencode.rs`](../opencode.rs) and [`doc.rs`](doc.rs); if they disagree, the code wins.

`openmoat init` asks `opencode --version` and does not set up a version before 1.3.4,
which loads a plugin only from a function export; `openmoat status` and `openmoat doctor`
report one as not protected, and name the hook a supported one runs OpenMoat through
(`opencode 2.2.0: OpenCode 2's `execute.before``). An upgrade from 1 to 2 needs no new
`openmoat init`.

## Hooks OpenMoat installs

| Event | Timeout |
|---|---|
| `tool.execute.before` (OpenCode 1, through the plugin) | 45 s (the plugin's own; OpenCode waits for a plugin without a limit) |
| `execute.before` (OpenCode 2, through the plugin) | 45 s (the same) |

OpenCode 1: the plugin sends the hook's `tool`, `sessionID`, `callID` and `args`. Before
it runs the guard it freezes `args`, the object OpenCode hands to every later plugin and
then to the tool, so a plugin that loads after it cannot change the call in place: a
write to it throws, which blocks the call.

OpenCode 2: the plugin sends the event's `tool`, `sessionID`, `agent`, `messageID`, its
`id` as `callID`, and `input`. OpenCode runs every plugin's hook on the same event and
then runs the tool `event.tool` names with `event.input`, and any plugin may register its
hook after OpenMoat's. So before it runs the guard the plugin replaces `tool` and `input`
with the checked name and a deep-frozen copy, as accessors that throw on assignment: what
the guard sees is what runs, and a later plugin that changes either throws, which blocks
the call. For a shell command it checked, its `shell` `create.before` hook pins the
command and shell when OpenCode starts the process.

Both add the instance's `directory` and `worktree`, the names of the configured MCP
servers (OpenCode 1's `config` hook; OpenCode 2's `mcp` transform) and `platform`. The
plugin returns for `allow` and no answer, and throws the reason for `deny`; anything it
cannot read throws too, and OpenCode blocks a call whose hook throws (the model sees the
error and goes on).

## Tools OpenMoat sees

- `bash` (1) and `shell` (2) (`Shell`, after a `cd` to `workdir`; on Windows, where it may
  be Git Bash, PowerShell or `cmd`, `ForeignShell`).
- `read`, `lsp` (1) (`FsRead`); `write`, `edit` (`FsWrite`); `apply_patch` (1), `patch` (2)
  (`Patch`); `opencode_worktree_remove` (2, `FsWrite` of the worktree it deletes). The path
  is `filePath` (1) or `path` (2); a relative one is in the instance directory; OpenCode 2
  expands a leading `~`, OpenCode 1 does not.
- `glob`, `grep` (`FsRead`, `ReadFiles`: `path`, else the directory, and where a pattern
  climbs to).
- `webfetch` (`Fetch`), `websearch` (`WebSearch`).
- MCP tools `<server>_<tool>` (`McpTool`, named `mcp__<server>__<tool>` by the configured
  server names; the longest one that begins the name when several do) and
  `read_mcp_resource`.
- Any other tool (a plugin's, a custom tool's, OpenCode 2's other `opencode_*` tools):
  `McpTool` of its own name, with every path, URL and command its arguments name checked.
- Ungoverned: `task` (1) and `subagent` (2) (a subagent, whose own calls reach the hook
  with its session id), `todowrite`, `skill`, `question`, `invalid` (1), `execute` (Code
  Mode; each tool call its script makes is checked on its own), `list_mcp_resources`,
  `list_mcp_resource_templates` (1), and OpenCode 2's `opencode_session_rename`,
  `opencode_worktree_list` and `opencode_models`.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

OpenCode 2: an `ask` is OpenCode's own permission prompt. The plugin calls
`ctx.permission.assert` with the action `openmoat`, the tool's name as the resource,
OpenMoat's reason as the message and the call's id as its source, and its `permission`
`evaluate` hook makes that request an ask even when OpenCode's rules would allow it. A
configured deny, a rejection, or `opencode run` (which rejects every ask unless `--auto`)
blocks the call. `--auto` (and the hidden `--yolo` and `--dangerously-skip-permissions`)
approves OpenMoat's ask as it approves OpenCode's own, and the plugin cannot tell. "Always"
saves nothing: approve a call for good with `openmoat allow --last --always`.

OpenCode 1 gives plugins no way to ask the person: its `permission.ask` hook is declared
but has not been called since 1.3.0. An `ask` arrives as a deny that says how to approve
the call (`openmoat`, or `openmoat allow --last`, then retry).

A call OpenMoat defers is left to OpenCode's own permission rules, which allow most tools
by default.

## Configuration and MCP files

- Configuration directory: `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode`
  (`%USERPROFILE%\.config\opencode` on Windows), or `OPENCODE_CONFIG_DIR` when it is set,
  which OpenCode 2 reads in place of that directory and OpenCode 1 reads as well. The hook
  file is OpenMoat's plugin itself, `plugins/openmoat.js`; both versions load every `.js`
  and `.ts` in `plugins/` and `plugin/` on start (OpenCode 2 in its background service:
  restart it with `opencode service restart`). `openmoat init` records the directory, and
  the XDG one OpenCode 1 also reads when `OPENCODE_CONFIG_DIR` is set; every rule naming
  `~/.config/opencode` covers them too, as found then and as the guard's environment names
  them: their plugin folders and configuration files are `kernel-self`'s, their tools and
  commands `runs-later`'s.
- OpenCode 2's background service keeps its settings, among them the environment it
  starts with, in `service*.json` there: `kernel-self` denies the agent writing them and
  running `opencode service set` or `unset`.
- Credentials: provider keys and OAuth tokens in `auth.json`, MCP sign-ins in
  `mcp-auth.json` and account tokens in `opencode.db`, all in `~/.local/share/opencode`
  on every OS. `agent-credentials` denies the agent's own tools reading or writing them,
  and `opencode auth export` (OpenCode 2), which prints them; `XDG_DATA_HOME` moving
  that directory is not followed.
- The agent running `opencode mcp add`, `opencode mcp auth` or `opencode mcp debug`
  asks (`runs-later`): they save a server, or start its OAuth sign-in, in which
  OpenCode 1.0.137 to 1.18.32 on Windows and WSL ran a command from the server's
  sign-in address. `openmoat status` and `openmoat doctor` warn when the `opencode` on
  the search path is a version with a published advisory (`advisories.rs`).
- MCP servers: `mcp.<name>` (and OpenCode 2's `mcp.servers.<name>`) in the global
  `config.json`, `opencode.json` and `opencode.jsonc`, and in a project's
  `opencode.json[c]` and `.opencode/opencode.json[c]` (JSON with comments, read as JSON5);
  each is pinned. Servers from `~/.opencode`, `OPENCODE_CONFIG`,
  `OPENCODE_CONFIG_CONTENT`, a remote `.well-known/opencode`, the parent directories
  OpenCode 2 also reads or managed configuration are not.
- Project settings: a project's `opencode.json[c]` and `.opencode/opencode.json[c]` add
  plugins, MCP servers and permission rules, and its `.opencode/plugins/` and
  `.opencode/plugin/` load at start, with no prompt; `openmoat status` and `openmoat
  doctor` warn about them.

## Removing OpenMoat's plugin by configuration (OpenCode 2)

OpenCode 2 reads `plugins` (and the old `plugin`) of every configuration file, and an
entry `-<id>` there removes a loaded plugin, `-*` every one; a later entry naming the id
turns it back on. A `policies` statement denying `integration.use` of
`plugin:<path of OpenMoat's plugin>` stops it loading. Either leaves every call unchecked.

- The person's own `opencode.json` and `opencode.jsonc`: `kernel-self` denies the agent
  writing them; `openmoat status` and `openmoat doctor` report OpenCode as not protected
  while one removes the plugin, and name the file and entry.
- A project's `opencode.json[c]` and `.opencode/opencode.json[c]`: writes ask
  (`runs-later`); `openmoat status` and `openmoat doctor` warn that OpenCode 2 sessions
  started there are not protected. Only the directory they run in and its project root
  are read, not the parent directories OpenCode 2 also reads.
- `OPENCODE_CONFIG`, `OPENCODE_CONFIG_CONTENT` and `OPENCODE_CONFIG_DIR`: `kernel-self`
  denies the agent setting them, and `opencode plugin add`, `remove` and `update`, which
  write the global configuration.
- The lock does not pin OpenCode's configuration files: the guard checks the lock, and a
  removed plugin calls no guard, so a pin would stop nothing in OpenCode, while OpenCode
  rewrites its global file itself.

## When the hook fails

OpenCode blocks the call when OpenMoat's plugin throws (`tool.execute.before` and
`execute.before` fail closed; OpenCode 2.0.x stops the call with an error of its own), and
the plugin blocks when `openmoat` is missing, crashes or does not answer within 45 s. The
call runs unchecked when OpenCode does not load the plugin: OpenCode 1's `--pure` or
`OPENCODE_PURE` (no external plugins), OpenCode 2's `-openmoat` or a policy denying the
plugin, an error loading it (OpenCode logs it and goes on), an OpenCode started with
another `XDG_CONFIG_HOME`, `OPENCODE_CONFIG_DIR` or `HOME`, or OpenCode before 1.3.4.

## Known gaps

No OS sandbox from OpenMoat; OpenCode 1 plugins cannot ask, so an ask is a deny that says
how to approve it; OpenCode 2's `--auto` approves OpenMoat's asks unseen; OpenCode before
1.3.4 is not supported; other plugins and custom tools run in OpenCode's process with the
agent's rights and can change what OpenMoat's plugin does, and a project's load at start
with no prompt: a plugin that rewrites a call OpenMoat checked makes that call fail, but
one can still replace a tool's implementation, advertise a tool under another name,
change a shell's working directory or environment, or rewrite a shell command from a
shell hook registered before OpenMoat's; a project's `-openmoat` turns OpenMoat off in
OpenCode 2 (reported, not prevented); a plugin tool that changes its own arguments fails,
since they are frozen; the person's `!` shell commands and the `` !`…` `` shell of a
command template are not checked; subagent calls carry the subagent's own session, so
taint and grants do not follow the parent session; calls run unchecked if OpenCode does
not load the plugin (`--pure`, `OPENCODE_PURE`, a load error; the agent is denied starting
OpenCode with the first two); a failed or slow hook blocks the call.

## Sandbox

None: hook only. Run OpenCode under `openmoat run` for an OS sandbox.
