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

Claude Code's run also sets `CLAUDE_CODE_SHELL` and `SHELL` to a shell that records each
start, and fails unless the Bash tool started through it and no hook did: the fact
ADR-075's wrapper depends on, which Claude Code would otherwise ignore silently. The other
agents' fake model serves one call, the denied one, so a shell never starts there and
their routing is not proven by this job.

"Real load" means the real agent read OpenMoat's hook or plugin from the file `init`
wrote, ran it for a tool call, and OpenMoat's decision held: the audit log has the
agent's `cat ~/.ssh/id_rsa` denied by `secrets-paths`, and the fake key is in none of
the agent's output.

| Agent | Install | Real load | Not proven |
|---|---|---|---|
| Claude Code (`claude-code`) | npm, scripts off; the platform package's native binary (the postinstall only links it) | `claude -p` against `tests/differential/fake_api.py`: three `Bash` calls in one session. The denied read; a read of an unknown page whose output names another host; then a call to that host, held for review as `injected-input`, which proves the `PostToolUse` hook kept that output. The log also holds the session's start, which proves the `SessionStart` hook ran. A fourth call fails, for the `PostToolUseFailure` capture; the run is then interrupted and `--resume`d, and the denied call, asked for again, must be denied again. The resumed run calls a tool of `fake_mcp.py`, which must be decided by `PreToolUse` (see "Lifecycle checks") | interactive prompts; the `ConfigChange` hook; a background MCP task (below) |
| Codex (`codex`) | npm, scripts off | `codex exec` with a custom Responses-API provider at `fake_openai.py`: one shell call | Codex's persisted hook trust (`/hooks`): the run uses `--dangerously-bypass-hook-trust`, as Codex's own hook tests do |
| OpenCode 1 (`opencode-1`) | npm, scripts off; the platform package's native binary (the postinstall only links it) | `opencode debug info` lists `plugins/openmoat.js`; `opencode run` with an OpenAI-compatible provider in `opencode.json` at `fake_openai.py`: one `bash` call | interactive sessions |
| OpenCode 2 (`opencode-2`) | npm, scripts off; the platform package's native binary | one `opencode serve`, `GET /api/plugin` polled until the location's plugins have activated: OpenMoat's plugin `active`, a state OpenCode 2 sets only once the plugin's `setup` ran | a tool call: OpenCode 2's provider settings are not driven yet, so the denied call is not proven in the real agent |
| Gemini CLI (`gemini-cli`) | npm, scripts off | `gemini -p` with its own model test double (`--fake-responses`): one `run_shell_command` call, in a folder trusted for the run (`--skip-trust`; an untrusted folder runs no settings hooks) | a run against Google's API; folder trust as a person grants it |
| GitHub Copilot CLI (`copilot-cli`) | npm, scripts off | `copilot -p` with its own provider setting (`COPILOT_PROVIDER_BASE_URL`, no GitHub sign-in) at `fake_openai.py`: one `bash` call | a signed-in session's tools (the GitHub MCP server is off offline) |
| pi (`pi`) | npm (`@earendil-works/pi-coding-agent`), scripts off | `pi --mode json` with a `models.json` provider at `fake_openai.py`: one `bash` call, reported blocked | interactive mode |
| OpenClaw (`openclaw`) | npm, scripts off (its first start replays them itself) | `openclaw plugins inspect openmoat --runtime`: the plugin imported with its `before_tool_call` hook; `openclaw agent exec` with a provider at `fake_openai.py`: one `exec` call | the gateway and its channels |
| Hermes Agent (`hermes`) | its own installer, latest tag | `hermes hooks list` (allowlisted), `hermes hooks doctor`, `hermes hooks test pre_tool_call`: OpenMoat's hook run through the code a session uses, and the block it returns | a model turn dispatching to the hook |
| Cline CLI (`cline`) | npm (`cline`), scripts off | `cline config hooks --json` lists `hooks/PreToolUse`; `cline --json` with its `openai-compatible` provider (`cline auth -b`) at `fake_openai.py`: one `run_commands` call | the VS Code extension, which reads hooks elsewhere |
| goose (`goose`) | the release archive for the runner (`goose-<arch>-<os>.tar.gz`), latest tag; its sha256 printed | a `goose run` turn against the fake API (its OpenAI provider), whose `shell` call `cat ~/.ssh/id_rsa` the plugin's hook denies (first run unproven: the provider variables are read from goose's source, not a capture) | the desktop app |
| Antigravity CLI (`antigravity-cli`) | the installer script (URL from third-party guides; its sha256 is printed), which installs the version its manifest names, with no channel to choose | `agy -p --dangerously-skip-permissions` against `fake_gemini.py` (`modelProvider: gemini`, `GOOGLE_GEMINI_BASE_URL`): one `run_command` call, `cat ~/.ssh/id_rsa`, denied by the hook. **Failing since the first run (agy 1.5.5, 2026-11-10):** the fake API received tool results for both calls and no hook in `~/.gemini/config/hooks.json` started. The run now leaves what tells the causes apart: the `agy_probe.py` entry (events with no matcher and the documented example matchers; its verdict is a job annotation), agy's own log (`agy-cli.log`, `--log-file`), `agy -p /hooks` (`agy-hooks.txt`), the configuration files it opened (`agy-opened.txt`, where the runner has strace), the files it wrote, what each tool result said (`fake-api.log`), and, when no hook ran, a second run without the flag, which never passes the job | interactive prompts, `force_ask` under `-p`; hook failure behaviour only as the hook-failure step observes it (below) |
| Cursor (`cursor`) | the package Cursor's install script names (no checksum is published; its sha256 is logged) | none: every `cursor-agent` run needs a Cursor account | that `cursor-agent` loads `hooks.json` at all |
| Continue CLI (`continue`) | `npm pack`, read only | not set up: the released `cn` runs no hooks | the job fails once `cn` calls its `PreToolUse` hook, so that `continue_cli.rs` can get an install |

Every agent but the Continue CLI also gets: the installed version beside the one the
adapter was checked against (`checked` in `agents.json`; newer is reported, not
failed); `status` and `doctor` calling it protected by its hook, with doctor healthy;
its configuration files parsing (JSON; JavaScript with `node --check`; OpenClaw's
`config validate`; Hermes Agent's own `hooks list`); and the two payloads. An agent
whose `payload` sets `allow_is_silent` (Codex, which rejects a bare
`permissionDecision: allow`) passes the allow payload with exit 0 and no output.

## Lifecycle checks (Claude Code)

- **Interrupt and resume.** The fake API holds its fifth request (`--hold-at`) and the
  script stops the agent there, then runs `claude -p --resume`. `check.py resumed` fails
  unless the resumed conversation carries the earlier tool results, and `check.py denied`
  needs a new `secrets-paths` deny after the resume.
- **`PostToolUseFailure`.** OpenMoat installs no hook for this event yet. A hook the
  script writes into the throwaway `settings.json` before `init` copies each payload to
  `captured/` (`claude-code-event-PostToolUseFailure-*.json`, scrubbed like the rest).
  `check.py event-captured` reports whether it arrived and never fails: the adapter is
  to be written from such a capture, not from the documentation.
- **MCP call and background tasks.** `check.py background-mcp` compares the audit log
  with `fake_mcp.py`'s log. It **fails** when the server received a call with no
  `PreToolUse` decision, and when the call neither was decided nor reached the server
  (a test that proves nothing). A call decided without running in the background passes
  and prints `background MCP NOT EXERCISED`, also in the job summary: Claude Code's
  documentation limits MCP tasks to a session that fetches feature flags and is
  interactive or reads `--input-format stream-json`, which a one-shot `claude -p` with
  no account is not. Whether `PreToolUse` fires for a background MCP task is therefore
  not proven by this job; the server already answers a task request so that it would be
  the day a release makes one here. `claude --help` and the tools the fake API was
  offered are in the artefact (`claude-help.txt`, `claude-tools.json`).

## Captured payloads

The workflow builds `openmoat` with the `capture-payloads` feature, which no release
has. While the real agent runs, `OPENMOAT_CAPTURE_DIR` points at the artefact's
`captured/` folder, and `openmoat guard` copies every payload it is sent there, exactly
as it arrived. `check.py scrub` then writes them to `captured/scrubbed/` as
`captured-<version>-<n>.json`, with the throwaway home, project and temporary folder
replaced by the fixtures' made-up `/Users/me`, `/p` and `/tmp/scratch`. To replace a
fixture built from source with a capture, read the scrubbed file, copy it into
`crates/openmoat-hosts/src/host/<module>/fixtures/`, and name its version in that
folder's README. `crates/openmoat-hosts/tests/captured.rs` parses every `captured-*`
file with its agent's adapter and refuses one that still holds a runner path. An agent
that clears its hook's environment leaves `captured/` empty, and the run says so
without failing.

## After-call payloads

Linking a later call to what an earlier call's output said (ADR-063) needs to know what
each agent's after-call event carries, and only a real payload shows that. For the agents
this job runs with no account and whose event has no real payload yet, `after_call.py`
adds a recording hook beside OpenMoat's own, in the throwaway home, before `init`:

| Agent | Event | The harmless call comes from | Blocking observable |
|---|---|---|---|
| Codex | `PostToolUse` | `fake_openai.py --then` | yes |
| Antigravity CLI | `PostToolUse` (its documentation shows no output field; this finds out) | `fake_gemini.py --then` | yes |
| GitHub Copilot CLI | `postToolUse` | `fake_openai.py --then` | yes |
| Gemini CLI | `AfterTool` | a second call in the `--fake-responses` file | no: there is no model request to time |

After the denied call, each makes one call that runs, `echo moat-ci-after-call-output`, so
that the event has a result to report. Not captured here: Cursor (every run needs an
account); MCP calls (of these agents, none is given the fake MCP server yet); the other
agents, whose event a plugin or script of OpenMoat's would have to send.

- **Stored** in the artefact as `after-call/<agent>-<event>-<pid>.json`, with the throwaway
  paths made the fixtures' made-up ones and the value under any key naming a token, key
  or authorisation replaced by `[redacted <type>]`, also inside a string that holds JSON. A
  payload that is not JSON is stored as its length only.
- **Reported** as one `::notice` per agent and event, because annotations can be read
  where the logs of a job cannot: the field names and the type of each value, merged over
  the payloads, and never a value. A key that is not a plain name prints as `<key>`.
- **Blocking.** The hook sleeps 1.5 s after storing the payload. If the next model request
  holding a tool result arrives after the hook finished, the agent waited for it. Whether a
  hook's answer or exit code can stop anything is not tried: the hook always exits 0
  silently.
- **Never fails the job.** An event that does not fire gives `NOT CAPTURED` and the reason
  the job can see (the job stopped earlier, `init` dropped the entry, the harmless call
  never came back, or it ran and the hook did not start). Everything asserted above still
  fails as before: the denied call is made first, so the capture cannot get in its way.

`python3 -I scripts/ci/latest-agents/test_after_call.py` (run by hand) tests the
redaction, the notice and each `NOT CAPTURED` reason; only a run of this job can show what
an agent sends.

## When the hook fails

Each agent's host spec says what it does with a call when OpenMoat's hook fails
(`HookFailure`, ADR-079; the table in `docs/LIMITS.md` "If the hook fails"), and `openmoat
status --format json` carries it as `hook_failure`. The last step proves it against the real
agent, for each agent step 4 starts with a model call. `init` writes the hook naming a copy
of `OPENMOAT_BIN` in the throwaway root; the step puts a stand-in there, starts the agent once
per case with one call, `cat ~/hook-failure-probe.txt | tee hook-failure-ran.txt`, and puts
the binary back:

| Case | The stand-in | Compared with |
|---|---|---|
| `crash` | exits 1 with nothing printed | `hook_failure.fails` |
| `missing` | none: the hook names a file that is gone | `hook_failure.fails` |

A hook that hangs is not tried: waiting out each agent's time limit (30 s to 600 s) would
make the job outlast its own time limit, so `hook_failure.times_out` rests on the vendors'
documentation and source alone.

The call ran when the probe file's marker is in what the agent printed, in the fake API's
log, or in the copy in the project. It was blocked when the marker is nowhere and the
stand-in logged the hook's start or the agent sent the model a result of the call. Every
outcome is a line of `hook-failure.json` in the artefact.

- **Fails the job** when the call ran where the fact says the agent blocks: OpenMoat
  would be telling people a failed hook stops a call it does not (`::error`).
- **Reported, not failed** (`::notice`): a call blocked where the fact says it runs or the
  vendor does not document it. The fact changes only once the vendor's documentation or
  source says so, with the source in the spec.
- **Reported as proving nothing** (`::warning`): neither evidence, for example an agent
  that never made the call.
- **Not run:** Cursor (an account), Hermes Agent and OpenCode 2 (no model call is driven
  through them here).

`python3 -I scripts/ci/latest-agents/test_check.py` (run by hand) tests how an
outcome is read and compared; only a run of this job shows what an agent does.

## When it fails

The `report` job opens or updates one issue per agent, `latest <agent> <version> breaks
OpenMoat`, with the failed step; the `latest-agent-<agent>-<OS>` artefact holds every
log. Re-run one agent from Actions → latest agents → Run workflow. When an adapter is
then checked against the new release, change the version in the file its record names
and in `agents.json` in the same pull request (`python3 -I
scripts/ci/latest-agents/check.py records` fails otherwise).
