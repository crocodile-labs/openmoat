# goose (`goose`)

goose, the open-source agent from Block (repository `aaif-goose/goose`, formerly
`block/goose`), through the `PreToolUse` command hook of a plugin, checked against the
source of v1.57.0. The CLI (`goose`) and the desktop app (which runs its agent as
`goosed`) share the agent code, the plugin directories and the hooks. Every fact here
comes from [`goose.rs`](../goose.rs) and [`doc.rs`](doc.rs); if they disagree, the code
wins.

## Hooks OpenMoat installs

`openmoat init` writes OpenMoat's plugin, `~/.agents/plugins/openmoat/hooks/hooks.json`:

| Event | Matcher | Timeout | On failure |
|---|---|---|---|
| `PreToolUse` | none (every tool) | 60 s | `block` |

goose runs the command with `sh -c` and sends `event`, `session_id`, `matcher_context`,
`tool_call_id`, `tool_name`, `tool_input` (absent for a call with no arguments) and
`working_dir`, the session's directory. `{"decision": "block", "reason"}` on stdout, or
exit 2 with the reason on stderr, blocks the call and returns the reason to the model;
exit 0 with nothing on stdout, or `{"decision": "allow"}`, lets it run. goose asks the
person for its own approval (`GOOSE_MODE`) before it runs the hook.

goose loads plugins once, when it starts, from `~/.agents/plugins/` and from the
`.agents/plugins/` of the directory it starts in; a plugin's name is its directory's, and a
project plugin replaces the person's plugin of the same name. The plugin directory is
shared with other agents that read Open Plugins.

## Tools OpenMoat sees

- `shell` (`Shell`; `ForeignShell` on Windows, where goose runs `cmd` or `GOOSE_SHELL`).
- `write`, `edit` (`FsWrite`, with the content or the replacement for provenance);
  `tree`, `analyze` (`FsRead`); `read_image` (`Fetch` for an http(s) URL, else `FsRead`).
  goose has no file read or fetch tool of its own: it reads through `shell`.
- `execute_javascript` (Code Mode, off by default): the tools a script calls run without
  the hook, so the call needs review (`Unchecked`), which goose receives as a block.
- `load`, `delegate`, `load_skill`: `UnknownTool`, every path, URL and command they name
  checked. A `delegate` subagent's own calls fire the hook.
- Extension tools, `<extension>__<tool>` (the built-in `todo__…`, `extensionmanager__…`
  and the person's MCP extensions): `McpTool`, recorded as `mcp__<extension>__<tool>`.
- Ungoverned: `list_functions`, `get_function_details`.
- Any other tool: `UnknownTool`.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Reviews

goose hooks cannot prompt. A `review` reaches goose as a block whose reason says how to
approve it (`openmoat`, or `openmoat allow --last`), and the audit log keeps the review.

## Configuration and MCP files

- The configuration directory is `~/.config/goose` (`$XDG_CONFIG_HOME/goose`; on Windows
  `~\AppData\Roaming\Block\goose\config`); `GOOSE_PATH_ROOT` moves it to `<root>/config`
  and the plugins to `<root>/.agents/plugins`. OpenMoat finds goose by that directory.
- MCP servers: `extensions` in `config.yaml`, pinned without their `enabled` switch;
  their tools are `<extension>__<tool>`.
- Plugin settings: `disabledPlugins` in `~/.config/goose/settings.json`, or in a
  project's `.config/goose/settings.json` or `settings.local.json`, turns a plugin off;
  `openmoat status` and `openmoat doctor` report OpenMoat's plugin turned off. goose
  also records each plugin it finds under `plugins` in `config.yaml`, where
  `enabled: false` turns it off.

Credentials: `secrets.yaml`, where goose keeps provider keys when its keyring is off
(`GOOSE_DISABLE_KEYRING`), is `agent-credentials`'. The default policy's `kernel-self`
keeps the agent from changing `config.yaml`, the plugin settings and every
`.agents/plugins` directory; `.goosehints` and saved recipes are on the taint list.

## When the hook fails

With `on_failure: block`, which `openmoat init` sets, goose blocks the call when the
hook cannot start, times out, gets no payload, exits non-zero without a block or prints
anything but a decision. Without it, goose runs the call. On Windows goose needs `sh` on
the search path to run any hook; without it every call is blocked.

goose runs every call unchecked when it does not load OpenMoat's plugin: turned off in a
`settings.json` or in `config.yaml`, replaced by a project plugin named `openmoat`, or a
`hooks.json` goose cannot read (it then skips the whole file with a warning).

## Known gaps

No OS sandbox from OpenMoat; Code Mode's `execute_javascript` needs review, since its tool
calls skip the hook; a project's `.agents/plugins/` can add hooks or replace OpenMoat's
plugin: run in a directory whose `.agents/plugins/openmoat` is not a byte-for-byte copy of
OpenMoat's hook file, `openmoat status` and `doctor` report goose not protected there and
name the directory to remove, and they warn about the other plugins' hooks and about a
project root's replacement seen from a subdirectory. They only see the directory they run
in, not one goose is started in later; the Windows shell is left
to goose; with `GOOSE_PATH_ROOT` the moved plugin is pinned by the lock but not named in
the default policy; a changed `hooks.json` is caught on the next call.

## Sandbox

None: hook only. `openmoat run goose` runs the whole agent in an OS sandbox.
