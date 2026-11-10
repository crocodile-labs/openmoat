# ADR-076: A named way to an OS sandbox for hook-only agents, and MCP servers wrapped on first asking

Status: accepted · Date: 2026-11-09 · Builds on ADR-018, ADR-028, ADR-045, ADR-049, ADR-064 and ADR-075

## Context

`docs/COVERAGE.md` names two limits that come from what OpenMoat tells a person, not from
what it can enforce. A hook-only agent has no OS layer unless it runs under `openmoat run`,
and `status` and `doctor` said only `hook only`. An unwrapped MCP server's command runs
before any check, and wrapping every server was opt-in.

## Decision 1: each hook-only agent names its way to an OS sandbox

1. **A host fact.** `HostSpec::run` is `RunFacts::Known { program, args, writes }` or
   `RunFacts::Unknown { why }`. `writes` are the directories the host's own documentation
   or source says it writes outside the project; `tests/contract.rs` refuses the base value
   for any host with no OS sandbox of its own, and a program that is not one of the host's
   process names, since `openmoat run` tells the agent by that name (ADR-070).
2. **`status` and `doctor` say one of three things** for an agent at `hook only` that
   OpenMoat writes no sandbox for (`os_sandbox` in `--format json`):
   - the exact command, for example `openmoat run --write ~/.gemini -- gemini`
     (`--isolate` on Linux, where plain `run` leaves paths inside the project open);
   - why there is none on this system: macOS before 13, Windows, or Linux without a
     network namespace, where `openmoat run` refuses every `--write` path outside the
     project;
   - why none is offered for this agent.

   `init` does not print it: the person has just been told what `init` did.
3. **A wrapped MCP server does not start inside `openmoat run`** (ADR-049: the proxy
   cannot read OpenMoat's state there). The command's line says so when the agent has one.

### What each host's facts come from

| Host | Program | Writes | Source |
|---|---|---|---|
| GitHub Copilot CLI | `copilot` | configuration directory; `~/Library/Caches/copilot` or `~/.cache/copilot` | [configuration directory reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference) |
| Gemini CLI | `gemini` | `.gemini` | [configuration reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md) |
| pi | `pi` | the agent directory | its documentation names the agent directory, and `HOST.md` what it holds; the page read does not list every file |
| OpenCode | `opencode` | `~/.local/share/opencode` | [troubleshooting](https://opencode.ai/docs/troubleshooting), the log and the database; a cache directory is not named there |
| Hermes Agent | `hermes` | the Hermes home | its MCP documentation, which names files in `~/.hermes` |
| Cline CLI | `cline` | `~/.cline` | [configuration](https://docs.cline.bot/cline-cli/configuration.md): "The primary root is `~/.cline/`" |
| goose | `goose` | `~/.local/share/goose`, `~/.local/state/goose` | [logs](https://github.com/block/goose/blob/main/documentation/docs/guides/logs.md) |
| Antigravity CLI | `agy` | `~/.gemini/antigravity-cli` | [MCP](https://antigravity.google/docs/mcp?tab=cli), which names what the CLI writes there; `agy` itself has not been run |
| OpenClaw | none offered | | its Gateway serves a local port ([gateway](https://docs.openclaw.ai/cli/gateway)), and `openmoat run`'s sandbox allows no listening socket |
| Continue CLI | none offered | | which directories `cn` writes outside the project was not checked |

## Consequences of decision 1

- Sandbox facts are a claim about another program. A directory its documentation does not
  name shows up as a refused write when the agent runs; it never widens anything. Only a
  real agent can show that a list is complete (`docs/SANDBOX.md` says so).
- The end-to-end test starts a stand-in named as each agent with exactly the spec's
  command: a write outside the project and a write to the policy fail, its own write
  works, and the relay decides a hook call for that host. It proves the launch shape, not
  the agent. CI runs it; it does not run on macOS 12 or Windows.
- A login kept in the system keychain or keyring, as GitHub Copilot CLI, Gemini CLI and
  Antigravity CLI do, is not readable under `openmoat run`; the agent must use an API key.
  The agent's install directory must be in `sandbox.read_roots` and its API host allowed
  by the policy, as for any agent under `openmoat run`.
- goose records each plugin it finds in `config.yaml`, which the policy keeps unwritable;
  what goose does when that write is refused is not known.

## Decision 2: `init` offers to wrap, and a later definition is held and reported

### When a host runs a server's command

No hook runs before a host starts a server, so this decides what a check can do. From the
hosts' documentation, as read for this decision; "not stated" means the page read does not
say, not that it never happens.

| Host | When the command runs | A project's servers |
|---|---|---|
| Claude Code | no general rule stated; the docs state session start for plugin servers and a restart on the next tool call in `claude -p` | prompts in an interactive session first; `claude -p` and the SDK load them without asking; committed `enabledMcpjsonServers` is ignored in an untrusted folder |
| Codex | not stated exactly; the docs imply startup, when it first lists the tools | trusted projects only |
| Cursor | not stated | no approval described before start |
| Gemini CLI | at startup ("When Gemini CLI starts, it performs MCP server discovery") | stdio servers are connected only in a trusted folder |
| GitHub Copilot CLI | not stated | a folder trust prompt at session start; whether it gates the servers is not stated |
| OpenCode | "Servers connect automatically", time not stated | no approval step described |
| Hermes Agent | at startup, and on `/reload-mcp`; `lazy: true` waits for the first tool call after the first run | no project file |
| OpenClaw | the Gateway owns the connections; the first is made on demand | no project file |
| goose | not stated | no project file read |
| Cline CLI | not stated | no project file read |
| pi | not stated by pi; community MCP adapters differ and several default to first use | a trusted project's `.pi/mcp.json` |
| Antigravity CLI | not stated | no approval described |
| Continue CLI | `cn` reads its own configuration; OpenMoat reads none of it | |

Nothing above was checked against a running host.

### What is built, in the order of preference asked for

1. **`init` wraps by default, when a person says so.** At a terminal, after the agents
   are set up, `init` lists the stdio servers in the agents' user configuration that are
   not wrapped, says what wrapping does and how to undo it, and asks
   `Run them through OpenMoat? [Y/n/d]` (`d` shows the diff; Enter is yes, as for every
   `init` question). Yes wraps them as `--mcp-proxy` does: backed up, recorded for
   `uninstall`, re-pinned as a person's change, sandboxed where `openmoat run` can
   sandbox. **Opt-out:** `--no-mcp-proxy`, or `n`, remembered per definition in
   `hosts.json`, so a person who said no is not asked again about it; a new definition
   is asked about. Without a person (`--yes`, a script, an `init` an agent starts, or
   over an existing lock without a terminal) nothing is rewritten: `status` and `doctor`
   keep reporting each server, as before. An existing unwrapped server is therefore never
   rewritten without its owner answering.
2. **A definition that appears later** (a project's `.mcp.json`, one added to a file
   after `init`) is not wrapped: OpenMoat does not rewrite a project's files, whose path
   of this machine's binary would mean nothing to the rest of the repository (ADR-049).
   Its tool calls are denied (`mcp-server-changed`) until a person runs `openmoat mcp
   accept` (ADR-026), and `status` and `doctor`, run in that project, name it as new and
   as starting outside OpenMoat. OpenMoat reads the definition and never starts it.

### What cannot be closed

- **The host starts the server itself, and a hook cannot stop that.** A definition that
  is not wrapped (a project's, one added after `init`, one the person declined, or any
  host's file `init` cannot rewrite) can run its command once before any check, with the
  person's permissions. Under `openmoat run` that command runs inside the agent's own
  sandbox instead (decision 1), but it still runs.
- **Wrapping and `openmoat run` do not combine.** A wrapped server refuses to start
  inside `openmoat run` (ADR-049), so a person who uses both loses that server there.
- **Not every host can be wrapped by `init`.** Hermes Agent's `config.yaml` is named with
  what to set by hand and left alone, as `openmoat mcp wrap` does. `wrap` does not read
  OpenCode's `"command": [...]` or goose's `cmd` as a stdio command: OpenCode's servers
  stay reported as starting outside OpenMoat, and goose's are not reported at all, which
  is a gap of the existing report that this does not close.

## Consequences of decision 2

- `init` at a terminal asks one more question when there is an unwrapped server to ask
  about. A wrapped server's tools stay hidden until `openmoat mcp accept` after its first
  start (ADR-032), which the question says.
- Amends ADR-049, where wrapping was opt-in only.
