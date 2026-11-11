# Antigravity CLI (`antigravity-cli`)

Antigravity CLI (`agy`), Google's terminal agent, through its `PreToolUse` command hook.
Every fact here comes from the official documentation
([hooks](https://antigravity.google/docs/hooks?tab=cli),
[sandbox](https://antigravity.google/docs/sandbox/),
[permissions](https://antigravity.google/docs/permissions/),
[MCP](https://antigravity.google/docs/mcp?tab=cli),
[settings](https://antigravity.google/docs/settings?tab=cli),
[install](https://antigravity.google/docs/install?tab=cli),
[CLI reference](https://antigravity.google/docs/cli/reference)), read 2026-11-09; those
pages state no version. **A preview host.** In the weekly `latest agents` job of
2026-11-10 (run 42922045984), with agy 1.5.5 (the version the installer's manifest named
that day), the fake API received tool results for both `run_command` calls of the turn,
and neither OpenMoat's `PreToolUse` entry nor the job's own `PostToolUse` capture, both
in `~/.gemini/config/hooks.json`, started; see "The first real run" below.
Implementation: [`antigravity_cli.rs`](../antigravity_cli.rs) and [`doc.rs`](doc.rs); if
they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout | File |
|---|---|---|---|
| `PreToolUse` | `*` | 600 s | `~/.gemini/config/hooks.json`, under the name `openmoat` |

The file is shared with the Antigravity app and IDE. OpenMoat's entry is
`{"openmoat": {"enabled": true, "PreToolUse": [...]}}`, with the guard command built by
`GuardCommand`. Hooks in `~/.gemini/antigravity-cli/settings.json` are stated as not loaded.

Input is `conversationId`, `workspacePaths`, `transcriptPath`, `artifactDirectoryPath`,
`modelName`, `lastUserInput`, `toolCall` (`name`, `args`) and `stepIdx`, in camelCase. It
names no event and no working directory: the first of `workspacePaths` stands in as it
does for Cursor's `workspace_roots`.

## Answers

`decision` is required, so an OpenMoat `defer` answers `allow` (which the documentation
defines as deferring to the next hook or the default policy); a `review` answers
`force_ask`, which always prompts and ignores cached permissions, so a saved "Always
Allow" cannot answer it. `auto_approve`, `ask`, `deny_unless_prior_grant` and `overwrite`
are never sent.

## Tools OpenMoat sees

- `run_command` (`Shell`; `CommandLine` after a `cd` to `Cwd`; needs review with a
  `RequestedTerminalID`). `ForeignShell` on Windows.
- `view_file`, `list_dir` (`FsRead`); `write_to_file`, `replace_file_content`,
  `multi_replace_file_content` (`FsWrite`).
- `find_by_name`, `grep_search` (`FsRead`, `ReadFiles`), with the directory their
  `Pattern` or `Includes` names and where a `..` climbs to.
- `read_url_content` (`Fetch`), `search_web` (`WebSearch`), `generate_image`
  (`ReadFiles` of `ImagePaths`, else `UnknownTool`).
- `manage_task` with `send_input` (`Input` as `Shell`, needs review: typed input joins
  what was typed before, like Codex's `write_stdin`).
- `schedule`, `define_subagent`, `invoke_subagent`: `UnknownTool` that needs review, a
  deliberate choice: `schedule` runs a prompt later, unattended; a defined subagent takes
  a system prompt and tool grants for later; whether a subagent's own calls reach
  OpenMoat's hook is not documented, so starting one is never silent.
- `call_mcp_tool` (`McpTool` as `mcp__<server>__<tool>`); an eager MCP tool
  `mcp_<server>_<tool>` is decided as `McpTool` of that name, by its server prefix. The
  name a hook receives for an MCP tool is not documented.
- `send_message` and any tool not listed (a `browser_*` tool): `UnknownTool`.
- Ungoverned: `ask_question`, `list_permissions`, `ask_permission`, and `manage_task` /
  `manage_subagents` listing, reading a status or ending a task.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Configuration and MCP files

- `~/.gemini/config/hooks.json` holds OpenMoat's hook; `~/.gemini/antigravity-cli/` is how
  OpenMoat tells the CLI is installed. No variable moves either (none is documented).
- MCP servers: `mcpServers` in `~/.gemini/config/mcp_config.json` and a workspace's
  `.agents/mcp_config.json`, pinned as for every host.
- Project: a workspace's `.agents/hooks.json` and `.agents/plugins/<plugin>/hooks.json`.
  How they merge with the person's is not documented, so `openmoat status` and `doctor`
  warn about them, report a project entry that turns OpenMoat's hook off, and a write that
  would set one is denied; a plugin named `openmoat` is reported as if it replaced ours.
- `enabled: false` under OpenMoat's own entry shows as `not protected` in `status` and
  `doctor`, and `openmoat init` turns it back on. `/hooks` can also toggle hooks, in a
  place the documentation does not name: an edit of the file trips the lock; a toggle kept
  elsewhere would not.
- Credentials: the account's sign-in is in the OS keyring (not a file);
  `~/.gemini/antigravity/mcp_oauth_tokens.json` holds MCP OAuth tokens
  (`agent-credentials`). `kernel-self` covers the hook file, `settings.json`
  (`permissions`, `toolPermission`, `trustedWorkspaces`), the MCP files and plugins.

## When the hook fails

Not documented. What Antigravity CLI does when the hook cannot start, crashes, times out,
exits non-zero or prints bad JSON is not stated, and no fail-closed setting is
documented, so OpenMoat assumes the call runs and reports `hook only` with a limit line.
Every error `openmoat guard` can catch answers a `deny` and exits 2 first. The timeout is
written at 600 s so the guard's own 30 s budget always answers before the host's documented
30 s default would.

## The first real run

The weekly job installs `agy` with Google's installer
(<https://antigravity.google/cli/install.sh>), which takes the version from its manifest
and has no channel to choose; on 2026-11-10 that was 1.5.5. The
[changelog](https://antigravity.google/docs/changelog) lists CLI releases up to 1.5.3
(2026-11-07); its 2.x entries (2.31.0 on 2026-11-09) are the Antigravity app's, not the
CLI's. So the CLI was not older than the documentation.

In one `agy -p "run it" --dangerously-skip-permissions` turn against a fake Gemini API
(`modelProvider: gemini`, `GEMINI_API_KEY`, `GOOGLE_GEMINI_BASE_URL`), the API saw three
requests holding 0, 1 and 2 function responses: the fake API received tool results for
both `run_command` calls. No hook started, and OpenMoat's audit log stayed empty. What this rules out:

- the home directory: the API key is used only with `modelProvider: gemini` in
  `~/.gemini/antigravity-cli/settings.json` (the install page), so `agy` read that file
  under `$HOME`;
- one bad entry: OpenMoat's (timeout 600 s) and the capture's (30 s, the documented
  default) both failed. Both use the matcher `*`, which the hooks page documents as
  matching every tool.

What is left: hooks are not run under `-p`, under `--dangerously-skip-permissions`, or
in a `GEMINI_API_KEY` session (1.4.7 fixed "skills, rules, custom agents, plugins, plugin
MCP servers, and hooks not loading" for Application Default Credentials sign-ins, so
what `agy` loads has depended on the sign-in before); or `*` is compiled as a regular
expression after all. None of these is documented. The job now records what tells them
apart (`scripts/ci/latest-agents/agy_probe.py`, agy's `--log-file`, `agy -p /hooks`, the
files `agy` opens, what each tool result said, and a second run without the flag), and
`openmoat status`, `doctor` and the README show Antigravity CLI as a preview host until
a run shows the hook deciding a call.

## Known gaps

- **Preview host.** Fixtures are documented shapes, not captures, and in the one real
  run no hook started (above).
- MCP and subagent calls: whether hooks fire for them is not documented; the eager MCP
  tool name and the review of a subagent start are the safe reading of that silence.
- Injected input (ADR-057, ADR-063): the documented `PostToolUse` payload has `toolCall`,
  `stepIdx` and `error` but no output, so OpenMoat installs no `PostToolUse` hook and only
  session taint applies.
- `--dangerously-skip-permissions` auto-approves permission requests; OpenMoat cannot see
  the flag. A saved `toolPermission: always-proceed` is read from `settings.json` and a
  review there is a deny. Whether `force_ask` reaches a person there or under `-p`
  (headless) is not documented.
- A project's `.agents/hooks.json` or plugin can add a hook that rewrites a call's
  arguments (`overwrite`) after OpenMoat checked it; the hook ordering is not documented.
- A workspace the CLI does not trust (`trustedWorkspaces`): whether hooks run there is not
  documented.
- A multi-root session (`--add-dir`) is decided against the first workspace.
- User plugins in `~/.gemini/config/plugins` are written only by a person
  (`kernel-self`) and are not reported by `status`.
- The shell that runs hooks and `run_command` on Windows is not documented: commands are
  `ForeignShell` there, and a hook binary under a path with spaces may not start.

## Sandbox

None from OpenMoat: `hook only`. `agy` has its own OS sandbox (`enableTerminalSandbox`,
`toolPermission: proceed-in-sandbox`, `--sandbox`, off by default, and absent on Windows
before 11 24H2 and on Linux without unprivileged user namespaces). OpenMoat does not write
it: the settings name no paths or policy to translate, so
`openmoat run --write ~/.gemini/antigravity-cli -- agy` is the OS sandbox OpenMoat offers
and `openmoat status` names it (ADR-076). It is built from the documentation; `agy` has
not been run under it, and a sign-in kept in the OS keyring cannot be read inside.
