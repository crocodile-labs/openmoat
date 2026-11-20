# ADR-104: Hook liveness: saying when an agent runs without its hook

Status: accepted · Date: 2026-11-20 · Builds on ADR-042 (plugins report loading), ADR-059
(`openmoat watch`), ADR-099 (the hosts' own plugin channels)

## Context

Protection can stop without anyone being told. An agent update reads its hooks from
another place or drops an event, a setting turns hooks off (`disableAllHooks`, Codex's
`[features] hooks = false`), an edit loses OpenMoat's entry, a session started before
`openmoat init` keeps the hooks it read at start. In each case the agent keeps working
and its tool calls run unchecked. `openmoat status` reads the hook file, so it catches a
lost entry and the settings it knows; it does not catch an agent that no longer runs an
entry that is still there.

ADR-042 answers this for the agents that run OpenMoat through a plugin (OpenClaw, pi,
OpenCode): the plugin reports as it loads, and `status` and `doctor` compare the report
with the last change that could have stopped it loading. `heartbeat::check` returned
nothing for a host that runs a hook command, which is every other agent: Claude Code,
Codex, Cursor, GitHub Copilot CLI, Gemini CLI, Hermes Agent, Cline, goose, Antigravity
CLI, Qwen Code and Crush.

A hook host has no load step to report from. But the guard records the host of every
call it decides, and most hosts write a file for each session they run.

## Decision 1: the same judgement, from a hook host's facts

For a hook host, `heartbeat::check` judges as ADR-042 does (`Loaded::{Reported, NotYet,
Missing}`), from these facts:

- **Since**: the newest of
  - OpenMoat writing the hook file (`HookWritten`: the lock pins the file and it still has
    the pinned contents, whatever its time; `init` may write it after the lock or in the
    same instant, and for Claude Code, Gemini CLI, Qwen Code and Hermes Agent the hook
    file is the settings file);
  - the hook file, or a settings file the spec names whose change can turn hooks off
    (Codex's `config.toml`), no longer matching its pin (`SettingsChanged`). A file the
    lock does not pin is OpenMoat's when it is no newer than `policy.lock`, someone
    else's otherwise;
  - the host's program on the search path changing (`HostUpdated`; the first of the
    spec's process names, the link and the file it names, as ADR-042).
- **Signal**: a decision the guard recorded for the host at or after that time
  (`Store::host_seen_since`). None of the hosts has a session-start event OpenMoat
  installs, so a call is the only signal; a later session-start hook would count the same
  way, through the audit log.
- **Activity**: the host's own session files written since, from a new spec fact,
  `InstallSpec::liveness` (`Liveness { settings, sessions }`), where `sessions` is
  `Sessions::Known(&[Activity])` (directories of the configuration directory, `*` for
  every directory at a level, and the end of a session file's name) or
  `Sessions::Unknown(why)`. A spec test requires every host with an install to have
  exactly one of `heartbeat` (plugin) and `liveness` (hook), and a `Known` place to name
  a file ending, an `Unknown` one to say why.

A call since the change is `Reported`. No call, and sessions written since, is `Missing`
with their count. No call and no sessions, or an unknown place, is `NotYet`.

## Decision 2: where each host writes its sessions

| Agent | Sessions (under its configuration directory) | Settings that turn hooks off |
|---|---|---|
| Claude Code | `projects/*/` `*.jsonl` (the `transcript_path` its hooks receive) | the hook file |
| Codex | `sessions/*/*/*/` `*.jsonl` (`<yyyy>/<mm>/<dd>/rollout-…`) | `config.toml` |
| Cursor | `chats/*/*/` `store.db` (the Cursor CLI; the editor's chats are elsewhere) | the hook file |
| GitHub Copilot CLI | `session-state/*/` `events.jsonl` | the hook file |
| Gemini CLI | `tmp/*/chats/` `*.json` | the hook file |
| Qwen Code | `projects/*/chats/` `*.jsonl`, and Gemini CLI's `tmp/*/chats/` `*.json` | the hook file |
| Cline | unknown: where the CLI writes a task under `data/` was not checked, and `CLINE_DATA_DIR` moves it | the hook file |
| goose | unknown: one database in its data directory, which commands without a session open too | the hook file |
| Hermes Agent | unknown: gateway, cron and ACP sessions are stored with the rest and never run the shell hook | the hook file |
| Antigravity CLI | unknown: its documentation does not say where `agy` writes a conversation | the hook file |
| Crush | unknown: a database in each project's `.crush`, not its configuration directory | the hook file |

A wrong or missing place fails quiet: the directory is empty, so the host stays
`NotYet` and no warning is given. A place that is wrong can only lose warnings, never
add them.

## Decision 3: no crying wolf

A session file without a call is not proof the hook did not run. The cases where it is
not:

- **A session with no tool call.** A question answered from the model alone writes a
  transcript and calls nothing. So a session is counted only once it started at least ten
  minutes ago (its file's creation time; where the system keeps none, its last write, so
  it is counted later, never sooner), and the warning counts the sessions and says what
  was seen, with a condition: "Claude Code ran 3 sessions since its settings changed
  (…), and OpenMoat saw no call from it: if they used tools, the hook did not run and the
  calls were not checked".
- **Another machine.** A configuration directory shared or synced between machines
  carries sessions whose calls went to another machine's audit log. The count says
  sessions, not calls; the fix starts with what to check.
- **The clock.** Times are file times against the audit log's times on the same machine;
  a file restored from a backup or written with a skewed clock can look new. Any later
  call clears the warning.
- **A session that predates the change and still runs.** This one is real: most hosts
  read their hooks when a session starts. The fix says to restart the agent first.

A hook host's warning never lowers its protection level (`not_loaded` stays a plugin
host's): the level is what the files say, and a session that needed no tool is no
reason to call an agent "not protected". `required:` in a policy is not affected.

## Decision 4: where it shows

- `openmoat status`: a `Missing` hook host is a warning under "needs attention" with the
  fix: restart the agent, then `openmoat init` and a check of what turns its hook off
  (the spec's `HookFailure::turned_off_by`), and the agent's own trust step where it has
  one (Codex `/hooks`). `Reported` and `NotYet` are not shown there, to keep `status`
  short; `status --format json` lists every hook host under `hooks`, beside `plugins`.
- `openmoat doctor`: every state, a note for `Reported` ("hook runs: last call …") and
  `NotYet` (which for an unknown place says why OpenMoat cannot tell more), a warning with
  the fix for `Missing`. The exit code is unchanged.
- `openmoat watch`: every thirty seconds it looks at the set-up agents and prints one
  line when an agent becomes `Missing` (plugin or hook) and one when its calls come back,
  never while the state stays.

Nothing decides on it: no call is held, denied or allowed because of it.

## Consequences

- An agent that stops running OpenMoat's hook is named within ten minutes of a session
  that used tools, where its sessions are known, in `status`, `doctor` and `watch`.
- Five hook hosts give only the note; a host whose session place is checked later gets
  the warning by changing its spec.
- `status` and `doctor` read up to 4096 directory entries per host (ADR-042's caps).
- A hook file the host itself rewrites (a model choice in Claude Code's `settings.json`)
  moves "since" forward; the next call clears it, and sessions before it no longer count.
