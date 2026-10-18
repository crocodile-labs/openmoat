# ADR-026: MCP server definitions are pinned in the lock, and an opt-in stdio proxy pins tool descriptions

Status: accepted · Date: 2026-10-18

## Context

Agent hosts start MCP servers from definitions in their configuration:

| host | user file | project file |
|---|---|---|
| Claude Code | `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`): `mcpServers`, and `projects.<path>.mcpServers` for local servers | `.mcp.json` |
| Codex | `config.toml` beside its hooks: `[mcp_servers.<name>]` | `.codex/config.toml` |
| Cursor | `mcp.json` beside its hooks | `.cursor/mcp.json` |

A server runs outside every sandbox, with the user's permissions, whatever its
definition says (`command`, `args`, `env`, `url`, headers). Two threats follow:

1. **An edited or planted definition.** A postinstall script, a `git pull`, or a cloned
   repository changes a definition or adds one. Claude Code asks once about a project's
   servers, by name, and does not ask again when the command behind that name changes.
   The hook already asks before the agent itself writes these files (`runs-later`), but
   it never sees writes made by other programs.
2. **A rug pull through tool descriptions** (#133, deferred by ADR-013). A server that was
   accepted later changes a tool's description or input schema, and the model reads the
   new text as instructions. The host shows a person nothing.

The policy lock (ADR-006) pins files whole, and drift denies every call. Neither part
fits here. `~/.claude.json` changes all the time (start counts, project history), and
one changed server is no reason to stop every tool.

## Decision

1. **Definitions are pinned per server, in the lock.** `policy.lock` gains
   `mcp_servers`, which maps `<file>#<JSON pointer>` to the SHA-256 of the entry in
   canonical JSON (keys sorted at every level), with the host, name and file. The pin
   also keeps a copy to show a person. In that copy the values of `env`, `headers` and
   `http_headers` are replaced by digests, and the rest is redacted like the audit log,
   so the lock holds no secret.
2. **Drift holds back only that server.** While a definition differs from its pin, or
   exists with no pin (added since), `moat guard` denies the tool calls of that server
   (`mcp__<name>__…`, the name as written or as Claude Code spells it) with rule
   `mcp-server-changed`. The reason names what changed and `moat mcp accept <name>`.
   Other servers and other tools are not affected, and lock drift of pinned files still
   denies everything as before. We chose deny over ask: an ask answered in the host
   records no accept, so the same question would come back on every call. A removed
   server is reported and holds back nothing. A configuration file that cannot be read
   hides which servers it starts, so it holds back every MCP call of that host.
3. **A new project server needs a person too.** A cloned repository that plants
   `.mcp.json` is the main way a server nobody reviewed gets started, so a project
   file's servers are pinned like the user's. The hook reads the files of the call's
   working directory and each directory above it, up to the project root. Accepting
   one project's servers leaves the pins of every other project as they are.
4. **Only a person accepts.** `moat mcp accept [<server>]` and `moat doctor --accept`
   show each change (a key-by-key diff, never a hidden value), ask `[y/N]`, and store
   the pins. Like `moat trust`, they need a terminal and an intact lock, and
   `kernel-self` denies them, `moat mcp wrap` and `moat mcp unwrap` to agents, pseudo-
   terminal wrappers included. Other re-pins (`moat allow`, `edit`, `trust`, `secret`,
   `sandbox sync`) carry the MCP pins over unchanged. `moat init` pins what it finds.
   A lock from before this change has no `mcp_servers`: nothing is enforced until
   `moat init` or `moat mcp accept` pins the servers, and `moat doctor` says so.
5. **`moat mcp proxy` pins tool definitions.** `moat mcp proxy --server <name> --
   <command…>` starts the server and relays its newline-delimited JSON-RPC.
   - It hashes each tool's name, description and input schema from `tools/list`.
   - The first time a server is seen, every listed tool is pinned
     (`~/.moat/mcp/<name>-<hash>.json`).
   - After that, a changed tool or a new one is held. The relay leaves it out of
     `tools/list`, and answers a `tools/call` for it, or for any tool never accepted,
     itself, with error -32602 naming `moat mcp accept <name>`. The call never reaches
     the server. `moat mcp accept` shows a diff of the description and schema.
   - Every `tools/call` is recorded in the audit log (host `mcp-proxy`, rules
     `mcp-proxy` and `mcp-tool-held`), without its arguments: the hook already recorded
     those, redacted. A call that cannot be recorded is refused, and so is every call
     when the pins cannot be saved.
6. **The proxy is opt-in per server.** `moat mcp wrap [<server>…]` (or `moat init
   --mcp-proxy` for every server) rewrites only the `command` and `args` of a stdio
   server in a user-level file to `moat mcp proxy --server <name> -- <original…>`.
   - The file is backed up first (`.moat-mcp-backup`), and `hosts.json` records the
     entry. `moat mcp unwrap` and `moat uninstall` restore the arguments after `--`.
   - Project files are never rewritten: the path of this machine's `moat` means nothing
     in a shared repository.
   - A server whose definition has an unaccepted change is skipped, so that a re-pin
     cannot accept the change unseen.

   Pinning (1–4) is on by default because it is quiet: it changes no host file and holds
   back only a server whose command a person has not seen, which must never run
   silently. The proxy stays opt-in for three reasons. It rewrites a file the host keeps
   rewriting itself. It puts OpenMoat in the path of every MCP message. Its first sight
   trusts whatever the server lists.
7. **Confinement is available, not the default.** `moat mcp proxy --sandbox [--write
   PATH]` (`moat mcp wrap --sandbox`) starts the server as `moat run -- <command…>`: the
   Seatbelt or Landlock profile made from the policy, with network only through `moat
   proxy` to the hosts the policy allows. Many servers need writes (package caches) and
   hosts that the default policy does not grant, so this is the person's choice per
   server.

## Consequences

- The hook cannot stop a changed server from starting. The host starts servers when a
  session begins, before any tool call. OpenMoat refuses the server's tool calls and
  reports the change in `moat doctor` and `moat status`. A definition whose
  command does harm when it starts is only contained by `--sandbox` or `moat run`.
- Servers are matched by name in every project of `~/.claude.json`, so a changed local
  server also holds back a server with the same name in another project until accepted.
- The proxy trusts first sight. It does not pin prompts, resources, `outputSchema`,
  annotations or tool results, and it does not cover remote (HTTP) servers, plugin
  servers (`~/.claude/plugins/`) or managed MCP configuration.
- The tool pins in `~/.moat/mcp/` change while agents run, so the lock does not pin them.
  The `kernel-self` deny on `~/.moat/**` keeps the agent's own tools from editing them.
  A program outside the hook's view (one the agent's sandbox does not confine) could,
  just as it could edit `~/.moat/mcp/` before this change.
- `--sandbox` cannot be used inside `moat run`: Seatbelt does not nest (ADR-018).
- On Windows, server ids keep the path as the host config names it. CI covers it.
