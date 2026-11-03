# ADR-049: `openmoat mcp proxy` starts only an accepted definition, wrapped servers are sandboxed by default, and servers that start outside OpenMoat are named

Status: accepted · Date: 2026-11-03 · Builds on ADR-026, ADR-032 and ADR-045

## Context

An agent starts every MCP server in its configuration when a session begins, with the
person's permissions. ADR-026 pins each server definition in the policy lock and denies the
tool calls of a new or changed one until a person runs `openmoat mcp accept`, but by then
the server's command has already run once: a definition a cloned project plants in its
`.mcp.json`, or a changed `command` in the person's own file, runs before OpenMoat sees
anything. `openmoat mcp wrap` and `openmoat init --mcp-proxy` put `openmoat mcp proxy`
in front of a stdio server, but the proxy started the server unconditionally, and its
`--sandbox` (the server under `openmoat run`) was opt-in. `openmoat status` and `doctor`
said nothing about the servers that start outside the proxy.

## Decision

1. **Check before start.** `openmoat mcp proxy --server <name> … -- <command…>` compares
   its own command line with the accepted definitions before it starts anything. The
   command line is what it would run, so that is what is checked (no file is read again
   between the check and the start). It reads the definitions of every agent whose hook is
   set up, as `openmoat mcp accept` does (the person's files and, from the proxy's working
   directory, the project's), keeps those whose `command`/`args` give exactly this command
   line read by the proxy's own grammar (server name, `--sandbox`, `--write`, the server's
   command), and drops those that set an environment variable this process does not have:
   they cannot be the one that started it. It starts the server only when at least one
   definition is left and every one left matches its pin in the lock, the same pin
   (SHA-256 of the whole entry, environment values included) `openmoat guard` checks the
   server's tool calls against. So `openmoat mcp accept` is the one way to accept a server,
   for its start and its calls alike. Otherwise nothing starts: every request the agent
   sends is answered with JSON-RPC error -32001 naming the definition as new or changed and
   `openmoat mcp accept <server>`; the refusal is written to the audit log (host
   `mcp-proxy`, rule `mcp-server-changed`, tool `mcp__<server>`) and to standard error; the
   proxy exits 1 when the agent closes its input. A lock that cannot be read, drift the
   guard would deny on (`kernel-integrity`), a policy that cannot be read, a lock that pins
   no MCP definitions yet and an agent MCP file that cannot be read all refuse the start.
   `mcp.trust_first_sight` does not apply: it is about a server's tools (ADR-032), and a
   definition is pinned whatever it says, as the guard already required for tool calls.
   `openmoat init` pins the current definitions before `--mcp-proxy` wraps them, and the
   wrap re-pins what it wrote, so servers that ran before keep starting. An `init` without
   a person at a terminal leaves new and changed definitions unpinned and unwrapped, as
   before.
2. **Sandbox by default.** `openmoat mcp wrap` and `openmoat init --mcp-proxy` write
   `--sandbox` wherever `openmoat run` can sandbox (macOS 13 or later, Linux); elsewhere
   they wrap without it and say why. `--no-sandbox` (`--mcp-no-sandbox` for `init`) opts
   out; `--sandbox` is still accepted. Wrapping an already wrapped server keeps its choice
   unless one of the flags is given, which switches it (turning the sandbox off drops
   `--write`); the switch is re-pinned as a person's change.
3. **Honest reporting.** `openmoat status` and `openmoat doctor` warn about each server
   the set-up agents read that starts outside what OpenMoat checks: a server with a local
   command that is not wrapped (the person's, or a project's, which `wrap` does not
   change), a wrapped one without the sandbox, and a project's server the agent starts
   without asking. Which settings do that is a host fact (`McpSpec::auto_start`): for
   Claude Code, `enableAllProjectMcpServers` or `enabledMcpjsonServers` in the person's,
   the project's or the local settings file, or in the project's entry of `~/.claude.json`,
   unless `disabledMcpjsonServers` lists it. These are warnings: the exit code of `status`
   and the problem count of `doctor` do not change.

## Consequences

- A planted or changed wrapped definition never runs its command, and the agent shows the
  reason in its MCP server list. A planted twin of an accepted definition (same command
  line, plus `NODE_OPTIONS` or another variable) refuses the start whenever it may have
  started this process.
- An unwrapped server still runs once before its tool calls are denied; only wrapping
  closes that, and the status and doctor warnings say which servers are not wrapped.
- Project definitions are found from the proxy's working directory, which agents set to
  the session's directory. An agent that started a project's server elsewhere would hide
  that project's definitions from the check; their tool calls are still held by the guard.
- Environment variables an agent sets for every server from somewhere other than the
  definition (its own settings' `env`) are not part of a definition; the project settings
  warnings name a project file that sets them.
- `openmoat mcp proxy` run by hand, or by a client whose configuration OpenMoat does not
  read, now starts nothing: such a server needs a definition in an agent OpenMoat set up.
- Inside `openmoat run` the proxy cannot read OpenMoat's state directory, so a wrapped
  server refuses to start there; it could not have its calls checked there before either
  (ADR-045 needs the audit log). Unwrapped servers run inside the agent's `openmoat run`
  sandbox.
- A sandboxed server reaches the network only through OpenMoat's proxy and writes only
  where the policy lets `openmoat run` write; a server that needs more is wrapped with
  `--no-sandbox` or given `--write`.
- Where `openmoat run` cannot sandbox (Windows, macOS 12 and older), wrapped servers run
  unconfined unless `--sandbox` is asked for, in which case they do not start.
