# Codex (`codex`)

The Codex CLI. It sends `PreToolUse` in Claude Code's format. Every fact here comes from
[`codex.rs`](../codex.rs) and [`doc.rs`](doc.rs); if they disagree, the code wins.

## Hooks OpenMoat installs

| Event | Matcher | Timeout |
|---|---|---|
| `PreToolUse` | `Bash\|apply_patch\|mcp__.*` | 600 s |

Codex runs a new or changed user hook only once the person trusts it: after
`openmoat init`, open Codex and trust OpenMoat's hook in `/hooks`.

## Tools OpenMoat sees

- `Bash` (`Shell`), `apply_patch` (`Patch`), `mcp__<server>__<tool>` (`McpTool`).
- Ungoverned: `update_plan` and any other tool.

The full table is in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

Codex hooks cannot ask: Codex rejects `permissionDecision: "ask"` and then runs the call,
so an ask is sent as a deny that the person approves with `openmoat allow --last`.

## Configuration and MCP files

- Configuration directory: `CODEX_HOME`, else `~/.codex`; hooks in `hooks.json` (nested
  layout).
- MCP servers: `config.toml` beside the hook file and a project's `.codex/config.toml`;
  tools are named `mcp__<server>__<tool>`.
- Project settings: a trusted project's `.codex/config.toml` and `.codex/hooks.json`, whose
  hooks run beside OpenMoat's; `[features] hooks = false` there or in the user's
  `config.toml` turns every hook off.

Credentials: `auth.json` (the ChatGPT tokens or API key, the default store) and
`.credentials.json` (MCP OAuth tokens without a keyring) in `CODEX_HOME` are
`agent-credentials`': the agent's own tools may not read them (`kernel-self` already
denies every write there). The keyring entries (`Codex Auth`, `Codex MCP Credentials`)
are read by `security find-generic-password -w` or `secret-tool lookup`, which
`secrets-paths` denies. `codex mcp add` and `codex mcp login` ask (`runs-later`);
`codex mcp add --url` starts the server's OAuth sign-in at once. `openmoat status` and
`openmoat doctor` warn when the `codex` on the search path is a version with a
published advisory (`advisories.rs`).

## When the hook fails

Codex runs the call when the hook is missing, cannot start, exits non-zero other than 2
(or 2 with nothing on stderr), or times out (default 600 s).

## Known gaps

Web search and hosted tools are not hooked; asks become denies; Codex skips a new or
changed hook until the person trusts it in `/hooks`, and `[features] hooks = false` turns
hooks off (`openmoat status` and `doctor` report that); calls run unchecked if the hook
binary is missing or crashes.

## Sandbox

OpenMoat writes its permissions profile into Codex's `config.toml`; the lock pins the part
OpenMoat owns. Codex's Linux sandbox does not refuse `TIOCSTI`, so only the kernel stops a
command typing into the terminal there (`openmoat doctor` warns).
