# Continue CLI (`continue`)

The Continue CLI (`cn`). It is a spec-only host: it speaks Claude Code's format
([claude_code](../claude_code/HOST.md)), so it has no adapter of its own. Every fact here
comes from [`continue_cli.rs`](../continue_cli.rs); if they disagree, the code wins.

## Hooks

`cn` merges hooks from `~/.claude/settings.json` and `.claude/settings.json` with its own
files and pipes them Claude Code's `PreToolUse` document. OpenMoat installs nothing for it:
the released `cn` runs no hooks yet, so OpenMoat does not check its calls.

## Tools OpenMoat sees

When `cn` runs the hook, its tool calls are Claude Code's and are mapped by Claude Code's
rows in [ARCHITECTURE.md](../../../../../docs/ARCHITECTURE.md) §3.

## Asks

`cn`'s hook runner blocks only on exit 2, `decision: "block"` or
`permissionDecision: "deny"`; an `ask` lets the call run. So `guard` tells a `cn` call
from a Claude Code one and answers `cn`'s asks as denies.

## Configuration and MCP files

- Found by its global directory, `CONTINUE_GLOBAL_DIR`, else `~/.continue`, or by `cn` on
  the search path.
- MCP servers: none read; `cn` reads its own configuration and fires no hook.

Credentials: the hub login older releases kept in `~/.continue/auth.json` and the MCP
sign-ins `mcp-remote` keeps in `~/.mcp-auth/` are `agent-credentials`' (`~/.continue/.env`
is `secrets-paths`'); `CONTINUE_GLOBAL_DIR` moving the directory is not followed. A write
of `~/.continue/config.yaml`, whose MCP servers `cn` starts, asks (`runs-later`).

## When the hook fails

`cn` runs the call when the hook is missing, cannot start, exits non-zero other than 2,
or times out (default 600 s).

## Known gaps

The released Continue CLI does not run hooks, so OpenMoat cannot check its tool calls;
run it under `openmoat run` ([SANDBOX.md](../../../../../docs/SANDBOX.md)).

## Sandbox

None from OpenMoat's hook path; `openmoat run` runs the whole agent in an OS sandbox.
