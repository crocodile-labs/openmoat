# ADR-042: OpenMoat's plugins report that their host loaded them

Status: accepted · Date: 2026-10-27 · Builds on ADR-004 (exit codes), ADR-033 (OpenClaw
plugin) and ADR-025 (quiet by default)

## Context

OpenClaw, pi and OpenCode (1 and 2, one plugin, ADR-040) have no command hook; OpenMoat
runs in each as a plugin the
host loads. Each host keeps running when it cannot load a plugin, and with no handler of
OpenMoat's every tool call runs unchecked:

- OpenClaw records the plugin with `status: "error"` and starts the Gateway
  (`src/plugins/loader-records.ts` 250–285 at `bd6a4e4`; only a reload throws,
  `throwOnLoadError: params.loadIntent === "replacement"` in `src/gateway/server-plugins.ts`
  463); with no `before_tool_call` handler the call runs (`policy.ts` 152–153).
- OpenCode 1.19.4 publishes "Failed to load plugin …" as a session error, or only logs a
  plugin function that throws, and skips it (`Plugin.state` in `src/plugin/index.ts`
  186–242).
- pi turns it into a diagnostic, "Failed to load extension", and starts the session
  (`loadExtension` in `src/core/extensions/loader.ts` 637–706, `main.ts` 803–806).

`openmoat status` and `doctor` checked that the plugin file was installed and current, so
an installed plugin that never loaded looked protected. Hermes Agent, the other host
whose hook can be skipped, records consent in a file `status` already reads.

## Decision

- `openmoat guard --heartbeat --host <id>` records that `<id>`'s plugin loaded: it
  writes `loaded/<id>.json` in the state directory, owner-only and atomically, holding
  the host id, the time and the OpenMoat release, nothing from the host. It reads no
  stdin, writes no stdout, decides nothing and records nothing in the audit log. It
  refuses (exit 2, the one failure code `guard` has) a host that runs a hook command and
  a state directory that does not exist. Inside `openmoat run` (the guard relay
  configured) it does nothing: the sandbox holds no state directory.
- Each plugin runs it, detached and unwaited, as its host loads it: OpenClaw's in
  `register` when `registrationMode` is `full` (not for listing the CLI's commands),
  pi's extension factory, OpenCode's `server` (OpenCode 1) and `setup` (OpenCode 2),
  each of which OpenCode calls when it loads the plugin. A heartbeat that cannot run never
  fails the load.
- The host spec says what is needed to judge it (`InstallSpec::heartbeat`: the host's
  program, and the folders it writes only for a session, which may be none), and the
  contract test requires it of every host with a plugin and the call in the plugin's
  source.
- `status` and `doctor` take `since`, the later of the plugin file's modification time
  and the host program's on the search path (the link and the file it names, the newer
  counting: an update can stop the plugin loading), and judge:
  - **loaded**: a report, or a decision the audit log holds for the host, at or after
    `since`;
  - **not loaded yet**: neither, and no file in the host's session folders newer than
    `since`. A note: a fresh `init` shows it until the host starts;
  - **missing**: neither, but such a file is newer: the host ran without the plugin, or
    a process from before is still running. A warning, and the protection level is
    `not protected` with the reason.
  Only pi names a session folder (`sessions/<cwd>/`); OpenClaw and OpenCode keep their
  sessions in databases that commands loading no plugin write too, so for them the state
  never goes past "not loaded yet". `status --format json` adds `plugins`; `doctor`'s
  rows keep their shape (a `note` or `warning`).
- Separately, `status` and `doctor` report an entry of OpenMoat's that lacks the host's
  fail-closed key set to `true` (Hermes Agent's `fail_closed`, Cursor's `failClosed`) as
  `not protected` with that reason, instead of "out of date": the host would run a call
  whose hook failed.

## Alternatives

- **Compare the report's age with the host's activity.** A long-running OpenClaw Gateway
  reports once, at start, and then works for weeks; any age limit is a false alarm. The
  report is compared with what could have stopped the plugin loading instead.
- **Count only decisions in the audit log.** A host that loaded the plugin and has not
  made a tool call yet would look unloaded.
- **Relay the report through `openmoat run`.** It would extend the relay protocol of
  ADR-028 for a note; the run's own decisions already show the plugin loaded once a
  call is made.

## Consequences

- An installed plugin that has not loaded no longer looks protected without a word: pi
  is reported not protected once it ran without the extension, the others get a note
  until their plugin reports.
- The report is information, not a check, and no decision reads it. An agent that
  already runs unchecked could forge one with its shell, which only hides the note.
- A plugin that loaded once and stops loading without its file or the host's program
  changing (a Node update; a configuration that drops it is caught by the lock or
  reported by `status` on its own) shows only as "loaded" with an old time; for pi, a session written after
  the last report then makes no difference unless `since` moved. The lines say "last
  report or call" with the time so a person can judge.
- A heartbeat starts one more short `openmoat` process per plugin load.
