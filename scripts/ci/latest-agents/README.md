# Latest agents

The weekly `latest agents` workflow runs `scripts/ci/latest-agents.sh <agent>` for every
entry of [`agents.json`](agents.json): the agent's latest release in a throwaway home
(HOME, MOAT_HOME and each agent's configuration directory inside it, checked before
every step that writes), `openmoat init --hosts <id> --yes`, `openmoat status` and
`openmoat doctor`, the real agent loading OpenMoat's hook where it can without an
account, and one allowed and one denied payload in the agent's format through
`openmoat guard`. No job has a secret or an account; the fake model APIs listen on
loopback only. CONTRIBUTING "Latest agents, weekly" describes the workflow.

## What each agent's run proves

"Real load" means the real agent read OpenMoat's hook or plugin from the file `init`
wrote, ran it for a tool call, and OpenMoat's decision held: the audit log has the
agent's `cat ~/.ssh/id_rsa` denied by `secrets-paths`, and the fake key is in none of
the agent's output.

| Agent | Install | Real load | Not proven |
|---|---|---|---|
| Claude Code (`claude-code`) | npm, scripts off; the platform package's native binary (the postinstall only links it) | `claude -p` against `tests/differential/fake_api.py`: one `Bash` call | interactive prompts; the `ConfigChange` hook |
| Codex (`codex`) | npm, scripts off | `codex exec` with a custom Responses-API provider at `fake_openai.py`: one shell call | Codex's persisted hook trust (`/hooks`): the run uses `--dangerously-bypass-hook-trust`, as Codex's own hook tests do |
| OpenCode 1 (`opencode-1`) | npm, scripts off; the platform package's native binary (the postinstall only links it) | `opencode debug info` lists `plugins/openmoat.js`; `opencode run` with an OpenAI-compatible provider in `opencode.json` at `fake_openai.py`: one `bash` call | interactive sessions |
| OpenCode 2 (`opencode-2`) | npm, scripts off; the platform package's native binary | one `opencode serve`, `GET /api/plugin` polled until the location's plugins have activated: OpenMoat's plugin `active`, a state OpenCode 2 sets only once the plugin's `setup` ran | a tool call: OpenCode 2's provider settings are not driven yet, so the denied call is not proven in the real agent |
| Gemini CLI (`gemini-cli`) | npm, scripts off | `gemini -p` with its own model test double (`--fake-responses`): one `run_shell_command` call, in a folder trusted for the run (`--skip-trust`; an untrusted folder runs no settings hooks) | a run against Google's API; folder trust as a person grants it |
| GitHub Copilot CLI (`copilot-cli`) | npm, scripts off | `copilot -p` with its own provider setting (`COPILOT_PROVIDER_BASE_URL`, no GitHub sign-in) at `fake_openai.py`: one `bash` call | a signed-in session's tools (the GitHub MCP server is off offline) |
| pi (`pi`) | npm (`@earendil-works/pi-coding-agent`), scripts off | `pi --mode json` with a `models.json` provider at `fake_openai.py`: one `bash` call, reported blocked | interactive mode |
| OpenClaw (`openclaw`) | npm, scripts off (its first start replays them itself) | `openclaw plugins inspect openmoat --runtime`: the plugin imported with its `before_tool_call` hook; `openclaw agent exec` with a provider at `fake_openai.py`: one `exec` call | the gateway and its channels |
| Hermes Agent (`hermes`) | its own installer, latest tag | `hermes hooks list` (allowlisted), `hermes hooks doctor`, `hermes hooks test pre_tool_call`: OpenMoat's hook run through the code a session uses, and the block it returns | a model turn dispatching to the hook |
| Cursor (`cursor`) | the package Cursor's install script names (no checksum is published; its sha256 is logged) | none: every `cursor-agent` run needs a Cursor account | that `cursor-agent` loads `hooks.json` at all |
| Continue CLI (`continue`) | `npm pack`, read only | not set up: the released `cn` runs no hooks | the job fails once `cn` calls its `PreToolUse` hook, so that `continue_cli.rs` can get an install |

Every agent but the Continue CLI also gets: the installed version beside the one the
adapter was checked against (`checked` in `agents.json`; newer is reported, not
failed); `status` and `doctor` calling it protected by its hook, with doctor healthy;
its configuration files parsing (JSON; JavaScript with `node --check`; OpenClaw's
`config validate`; Hermes Agent's own `hooks list`); and the two payloads.

## When it fails

The `report` job opens or updates one issue per agent, `latest <agent> <version> breaks
OpenMoat`, with the failed step; the `latest-agent-<agent>-<OS>` artefact holds every
log. Re-run one agent from Actions → latest agents → Run workflow. When an adapter is
then checked against the new release, change the version in the file its record names
and in `agents.json` in the same pull request (`check.py records` in the quality gate
fails otherwise).
