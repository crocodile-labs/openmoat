# OpenCode (`opencode`)

OpenCode 1 (`opencode-ai` on npm), through its `tool.execute.before` plugin hook, checked
against the source of OpenCode 1.19.4. OpenCode has no command hook: OpenMoat's plugin
([`integration/openmoat.js`](integration/openmoat.js)) runs `openmoat guard --host opencode`.
Every fact here comes from [`opencode.rs`](../opencode.rs) and [`doc.rs`](doc.rs); if they
disagree, the code wins.

**OpenCode 2** (`@opencode/cli`, 2.0.0 and later) installs the same `opencode` program and
reads the same configuration directory, but loads plugins through another API and does not
run this one. It is not supported yet: `openmoat init` asks `opencode --version` and does
not set up a 2.x, and `openmoat status` and `openmoat doctor` report it as not protected.

## Hooks OpenMoat installs

| Event | Timeout |
|---|---|
| `tool.execute.before` (through the plugin) | 45 s (the plugin's own; OpenCode waits for a plugin without a limit) |

The plugin sends the hook's `tool`, `sessionID`, `callID` and `args`, and adds the
instance's `directory` and `worktree`, the names of the MCP servers in OpenCode's merged
configuration (`mcpServers`, from its `config` hook) and `platform`. Before it runs the
guard it freezes `args`, the object OpenCode hands to every later plugin and then to the
tool, so a plugin that loads after it cannot change the call in place: a write to it
throws, which blocks the call. It returns for `allow` and no answer, and throws the reason
for `deny`; anything it cannot read throws too, and OpenCode blocks a call whose hook
throws (the model sees the error and goes on).

## Tools OpenMoat sees

- `bash` (`Shell`, after a `cd` to `workdir`; on Windows, where it may be Git Bash,
  PowerShell or `cmd`, `ForeignShell`).
- `read`, `lsp` (`FsRead`); `write`, `edit` (`FsWrite`); `apply_patch` (`Patch`).
  A relative `filePath` is in the instance directory; OpenCode expands no `~`.
- `glob`, `grep` (`FsRead`, `ReadFiles`: `path`, else the directory, and where a pattern
  climbs to).
- `webfetch` (`Fetch`), `websearch` (`WebSearch`).
- MCP tools `<server>_<tool>` (`McpTool`, named `mcp__<server>__<tool>` by the configured
  server names; the longest one that begins the name when several do) and
  `read_mcp_resource`.
- Any other tool (a plugin's or a custom tool's): `McpTool` of its own name, with every
  path, URL and command its arguments name checked.
- Ungoverned: `task` (a subagent, whose own calls reach the hook with its session id),
  `todowrite`, `skill`, `question`, `invalid`, `execute` (Code Mode; each MCP call its
  script makes is checked on its own), `list_mcp_resources`,
  `list_mcp_resource_templates`.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

OpenCode 1 gives plugins no way to ask the person: its `permission.ask` hook is declared
but has not been called since 1.3.0. An `ask` arrives as a deny that says how to approve
the call (`openmoat`, or `openmoat allow --last`, then retry). A call OpenMoat defers is
left to OpenCode's own `permission` rules, which allow most tools by default.

## Configuration and MCP files

- Configuration directory: `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode`
  (`%USERPROFILE%\.config\opencode` on Windows). The hook file is OpenMoat's plugin itself,
  `plugins/openmoat.js`; OpenCode loads every `.js` and `.ts` in `plugins/` and `plugin/`
  on start. `OPENCODE_CONFIG_DIR` names a further directory OpenCode reads; it does not
  move this one. `openmoat init` records it when it is set, and every rule naming
  `~/.config/opencode` covers it too, as found then and as the guard's environment
  names it: its plugin folders and configuration files are `kernel-self`'s, its tools
  and commands `runs-later`'s.
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
- MCP servers: `mcp.<name>` in the global `config.json`, `opencode.json` and
  `opencode.jsonc`, and in a project's `opencode.json[c]` and `.opencode/opencode.json[c]`
  (JSON with comments, read as JSON5); each is pinned. Servers from `~/.opencode`,
  `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `OPENCODE_CONFIG_CONTENT`, a remote
  `.well-known/opencode` or managed configuration are not.
- Project settings: a project's `opencode.json[c]` and `.opencode/opencode.json[c]` add
  plugins, MCP servers and permission rules, and its `.opencode/plugins/` and
  `.opencode/plugin/` load at start, with no prompt; `openmoat status` and `openmoat doctor` warn about them. OpenCode 1 has no
  setting that removes a plugin, so no file turns OpenMoat's off.

## When the hook fails

OpenCode blocks the call when OpenMoat's plugin throws (`tool.execute.before` fails
closed), and the plugin blocks when `openmoat` is missing, crashes or does not answer
within 45 s. The call runs unchecked when OpenCode does not load the plugin: `--pure` or
`OPENCODE_PURE` (no external plugins), an error loading it (OpenCode logs it and goes on),
an OpenCode started with another `XDG_CONFIG_HOME` or `HOME`, or OpenCode 2.

## Known gaps

No OS sandbox from OpenMoat; OpenCode 1 plugins cannot ask, so an ask is a deny that says
how to approve it; OpenCode 2 is not supported yet; other plugins and custom tools run in
OpenCode's process with the agent's rights and can change what OpenMoat's plugin does, and
a project's load at start with no prompt; a plugin tool that changes its own arguments
fails, since they are frozen; the person's `!` shell commands and the `` !`…` `` shell of
a command template are not checked; subagent calls carry the subagent's own session, so
taint and grants do not follow the parent session; calls run unchecked if OpenCode does
not load the plugin (`--pure`, `OPENCODE_PURE`, a load error; the agent is denied
starting OpenCode with the first two); a failed or slow hook blocks the call.

## Sandbox

None: hook only. Run OpenCode under `openmoat run` for an OS sandbox.
