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
