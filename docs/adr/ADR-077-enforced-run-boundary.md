# ADR-077: `openmoat run` can be required to start only with its full boundary

Status: accepted · Date: 2026-11-10 · Builds on ADR-018, ADR-028, ADR-049, ADR-064 and ADR-076

## Context

`require:` (ADR-064) sets the least protection level of each agent. It says nothing about
`openmoat run` itself, which degrades quietly in two ways. On Linux without a usable
bubblewrap the default `--netns=auto` restricts the network by port only and warns: a
command can reach any host on the proxy's port. And an inherited variable reaches the
agent unless it holds a brokered secret, cloud credentials included. A person or team
that has decided these are not acceptable could say so only with a flag on every run.

## Decision 1: `require.run: full-boundary`

```yaml
require:
  run: full-boundary
```

1. **Part of `require:`, not a new system.** The setting is read wherever `require:` is
   read: the person's policy, a repository policy and a pack. Any one source turns it on
   and none turns it off (`Policy::run_boundary_required`), as levels only rise. It is
   protected as `require:` is (ADR-064 section 7).
2. **What it refuses.** Before anything starts: a system with no OS sandbox OpenMoat can
   generate (macOS before 13, a missing backend, Windows). After the sandbox is built and
   before the agent starts: a Linux system where the agent would get no network namespace.
   The refusal names the policy that asks and how to get the namespace. `--netns=auto`, the
   default, and an explicit `--netns=auto` do not lower it.
3. **It applies to every program `openmoat run` starts,** agent or not, and so to an MCP
   server started through `openmoat mcp proxy --sandbox`, which is `openmoat run` around
   the server.
4. **`status` and `doctor`** report whether it holds on this system, and an unmet
   requirement is a problem (exit 64). `--format json` of `status` has `run_boundary`
   (`by`, `met`, `gaps`), `null` without the setting. Without the setting nothing changes.

## Decision 2: an environment allowlist for `openmoat run`

1. **When it applies.** Under `require.run: full-boundary`, only an allowlist of inherited
   variables reaches the program. Without the setting everything still does, and one line
   gives the count and the first three names that look like credentials. The list becomes
   the default at 1.0, or earlier in a release whose notes say so, once the `doctor` row
   and real runs show the base and the hosts' names are complete; it is not the default
   now because a wrong removal stops a working agent.
2. **What is on it.** A base (`PATH`, `HOME`, `TERM`, locale, temp directories and so on,
   `commands/run/env.rs`), the platform's own (`BASE_ENV` in `macos.rs`, `linux.rs`), the
   host's names (`HostSpec::run_env` and the variable that moves its configuration
   directory), the person's `sandbox.env_allow` and `--env NAME` for one run. What the
   run itself sets or removes is never withheld or reported: the list is applied after all
   of it, so a proxy setting or a CA file cannot be lost, and a brokered secret stays gone
   even if its name is added.
3. **Names, not values or patterns.** `sandbox.env_allow` and `--env` take a name only
   (`env_name_problem`); `NAME=value` and any wildcard are errors, so nothing can be written
   that lets every variable through. `sandbox.env_allow` is read from the person's own
   policy, which the lock pins. A repository policy and a pack have no `sandbox:` section,
   so they can turn the requirement on and cannot add a name to the list.
4. **A sandboxed MCP server keeps what its definition sets.** `openmoat mcp proxy --sandbox`
   starts `openmoat run` around the server, and the proxy passes `--env` for each name the
   accepted definition sets. Those come from the same check that let the server start
   (ADR-049); no file is read again.
5. **A wrong removal says so.** The run prints how many it withheld, `--verbose` names them
   and `doctor` lists them; none of these ever shows a value.

### What each host's names come from

Read on 2026-11-10. "Not checked" means no list was found to read, so nothing is added and
a person adds the name; nothing was tried against a running agent.

| Host | Names | Source |
|---|---|---|
| Claude Code | `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `CLAUDE_CODE_OAUTH_TOKEN` | [environment variables](https://code.claude.com/docs/en/env-vars) |
| Codex | `OPENAI_API_KEY`, `CODEX_ACCESS_TOKEN` | [authentication](https://learn.chatgpt.com/docs/auth), which shows them piped to `codex login`; it does not say the CLI reads them itself |
| Cursor | `CURSOR_API_KEY` | [authentication](https://cursor.com/docs/cli/reference/authentication) |
| Gemini CLI | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` | [configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md) |
| GitHub Copilot CLI | `COPILOT_GITHUB_TOKEN` | [authentication](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli), which also names `GH_TOKEN` and `GITHUB_TOKEN`; those are general GitHub tokens, so a person adds them |
| goose | `GOOSE_PROVIDER`, `GOOSE_MODEL`, `GOOSE_PROVIDER__API_KEY` | [environment variables](https://github.com/block/goose/blob/main/documentation/docs/guides/environment-variables.md); keys of named providers are not listed there |
| OpenCode | `OPENROUTER_API_KEY`, `OPENCODE_CONFIG_DIR` | [providers](https://opencode.ai/docs/providers); other providers' names were not listed there |
| Cline CLI | `CLINE_DATA_DIR` | [configuration](https://docs.cline.bot/cline-cli/configuration.md), which names no key variable |
| pi | the provider table, less `AWS_BEARER_TOKEN_BEDROCK`, `GOOGLE_CLOUD_API_KEY` and `CLOUDFLARE_API_KEY` | [providers](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/providers.md) |
| OpenClaw | ten provider keys, and its path variables | [environment](https://docs.openclaw.ai/help/environment), which names more providers than are listed here |
| Hermes Agent, Continue CLI, Antigravity CLI | only the configuration directory variable | not checked |

Cloud account credentials are left out on purpose, Amazon Bedrock's and Google Cloud's
included, even where an agent can use them: they are what the list exists to withhold. A
person who runs Claude Code on Bedrock adds those names.

## Limits of decision 2

- **It is the environment at the start.** A value the agent reads from a file, a keychain
  or a helper is outside it, and the agent's own login still works where the sandbox lets
  it read that login (ADR-054).
- **An agent's own key is on the list for that agent,** so it reaches every command the
  agent starts unless the host keeps it from them. The list narrows what is inherited; it
  does not separate the agent from its commands.
- **The host lists can be incomplete.** A variable an agent needs and its documentation
  does not name is withheld, and the agent fails until a person adds it. Only a real run
  can show a list is complete.
- **Only exact names.** A tool that reads a family of variables (`NPM_CONFIG_*`) needs each
  one named.
- **`doctor` reads its own environment,** which may differ from the shell `openmoat run` is
  started from.

## Limits of decision 1

- **It is about `openmoat run`.** An agent started without it is not refused: no OpenMoat
  code runs at that point. `require.protection: hook-and-os-sandbox` is what denies such
  an agent's calls (ADR-064), and the two can be used together.
- **On Linux the full boundary does not mean `--isolate`.** Plain `openmoat run` leaves
  paths inside the project open to commands (Landlock grants whole trees, `tier.rs`), and
  the setting does not change that; `openmoat run` still says so when it starts. Requiring
  `--isolate` would refuse every system without a working bubblewrap and every run that
  needs the rest of the machine readable, and was not asked for here.
- **The check is of this system at this moment.** `status` reads what `openmoat run` would
  find; bubblewrap removed afterwards is refused by the run, not by `status`.
