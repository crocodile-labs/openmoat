# ADR-033: OpenClaw through a plugin that runs `moat guard`

Status: accepted · Date: 2026-10-19 · Builds on ADR-004 (exit codes), ADR-006 (policy
lock) and ADR-025 (quiet by default)

## Context

Every host OpenMoat supported ran a command before each tool call. OpenClaw has no
command hook: an extension sees a tool call before it runs only as an in-process
plugin, through the typed `before_tool_call` hook
(<https://docs.openclaw.ai/plugins/hooks/tool-policy>). A handler receives the tool
name, its params, the call and run ids and the session's ids, and returns `block` with
a reason, `requireApproval` (OpenClaw asks the person through its approval routes and
blocks when no one answers), rewritten `params`, or nothing. A handler that throws or
times out (15 s by default, `plugins.entries.<id>.hooks.timeouts` up to 600 s) blocks
the call (<https://docs.openclaw.ai/plugins/hooks/reference>). Plugins load from
`plugins.load.paths` in `openclaw.json` (JSON5; `OPENCLAW_STATE_DIR` and
`OPENCLAW_CONFIG_PATH` move it), and a standalone file's plugin id is its file name.

## Decision

- OpenMoat ships a dependency-free plugin, `crates/openmoat-cli/integrations/openclaw/openmoat.mjs`.
  For every tool it runs `moat guard --host openclaw` with the event, the context's
  ids, the agent's workspace, the configuration path and the platform on stdin. It
  maps exit 2 with a deny to `block`, an ask to `requireApproval` (allow once or
  deny), allow or no output to no decision, and everything else (no `moat`, a crash,
  another exit code, an unreadable answer, 45 s without one, a cancelled call) to
  `block`. It never rewrites params.
- `moat init` writes the plugin, with the binary's path filled in, to
  `<state dir>/openmoat/openmoat.mjs`, adds it to `plugins.load.paths`, enables
  `plugins.entries.openmoat` with a 60 s `before_tool_call` timeout, adds `openmoat`
  to an existing `plugins.allow` and removes it from `plugins.deny`. It refuses a file
  that turns plugins off or is not plain JSON. Both files are pinned in the lock;
  `moat uninstall` restores `openclaw.json` and deletes the plugin.
- `openmoat-hosts` reads the plugin's envelope as host `openclaw`. OpenClaw can ask,
  so `Host::answer` keeps an `ask`. A `defer` is no decision, so OpenClaw's own exec
  approvals and tool policy decide, as without OpenMoat. Tools that change what the
  Gateway loads (`plugins` install, enable, disable, uninstall, reload) are decided as
  a write to `openclaw.json`, which `kernel-self` denies.
- `kernel-self` adds `~/.openclaw`, `~/.openclaw/openclaw.json` and the plugin
  directory; `runs-later` adds OpenClaw plugin directories (`extensions/`).

## Consequences

- OpenClaw's calls are checked whenever the Gateway loads the plugin; when it does not
  (plugins turned off, the entry removed, another configuration file), OpenClaw runs
  them unchecked, and OpenMoat notices only on the next call the plugin sends or in
  `moat status` (THREAT_MODEL.md §5).
- The payload is OpenMoat's own envelope around OpenClaw's documented event, not a
  captured one; the fixtures say so until a run against a real Gateway replaces them.
- Another plugin can still rewrite params after OpenMoat saw them; plugins are trusted
  code inside the Gateway.
