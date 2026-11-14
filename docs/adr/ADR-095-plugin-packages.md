# ADR-095: Packages for each agent's own plugin channel, generated from the host specs

Status: accepted · Date: 2026-11-14 · Builds on ADR-033 (OpenClaw's plugin), ADR-042
(plugin heartbeat), ADR-071 (the state directory on the hook's command line), ADR-091
(agent configuration from host specs)

## Context

Installing OpenMoat takes three steps from zero: the binary, `openmoat init`, a new
agent session. Most agents now have a one-step channel of their own for extensions:
Claude Code and Cursor marketplaces, Gemini CLI extensions, GitHub Copilot CLI plugins,
npm packages for OpenCode and pi, ClawHub for OpenClaw, Hermes Agent's Plugin Catalog,
`agy plugin install`. OpenMoat had no package in any of them.

A package in such a channel installs only the hook side. The binary, the policy and the
lock still come from OpenMoat: a package that downloads and runs the binary would do what
the default policy's `pipe-to-shell` and `runs-later` rules exist to stop, and a package
that decided without the lock would weaken invariant 9. A person may also install both a
package and `openmoat init`'s hook for the same agent, which then runs both for every
call: each call would be decided, recorded and folded into its session twice, and a
`review` put to the person twice.

## Decision

1. **Each host spec says how its channel installs OpenMoat** (`HostSpec::plugin`,
   `contract/plugin.rs`): a `PluginSpec` (channel, the install command, the publish
   steps, the official pages the layout follows, the marketplace file that lists it, the
   files) in `host/<module>/plugin.rs`, or `Plugin::None` with the reason (Codex: its
   directory refuses plugins that carry hooks; Cline: its SDK plugins wait 3 s and fail
   open; goose: no registry, and `init` already writes an Open Plugins folder).
2. **`plugins/` is generated** from those specs (`openmoat_hosts::plugin::files`), never
   edited: `cargo test -p openmoat-hosts --test plugins` fails when it differs, and
   `OPENMOAT_TEST_UPDATE_PLUGINS=1` rewrites it. The facts are not copied: a hook-command
   package's hook file is the host's own `HookFile` layout writing the entries `init`
   writes (`InstallSpec::hooks`), with the package's guard script in place of the
   binary; a plugin-loading host's package is `init`'s `OwnedFile` with `openmoat` and an
   empty state directory filled in; the deny a package prints is the host adapter's
   rendering of the guard's own `kernel-error` deny. The packages carry the workspace
   version, so a release regenerates the folder.
3. **No binary, no download.** A hook-command package runs `hooks/openmoat-guard`, a
   POSIX `sh` script, with the arguments `init`'s hook gives the binary. It runs the
   `openmoat` on the search path, or in a folder OpenMoat's installers use
   (`~/.cargo/bin`, Homebrew's prefixes), with `--plugin` added, and passes on its answer.
   With no `openmoat`, or when it exits other than 0, or 2 without an answer, the script
   prints the host's deny and exits 2, the message naming the one install command
   (`openmoat_hosts::NOT_INSTALLED`). The JavaScript plugins (pi, OpenCode, OpenClaw)
   block with the same words when `openmoat` cannot be started, and Hermes Agent's Python
   plugin returns a block for every failure, since Hermes skips a callback that raises.
4. **`openmoat guard --plugin` decides as `init`'s hook does**, lock first: no lock, a
   drifted lock or no state directory denies and names `openmoat init`, which stays the
   only way to write the policy and its lock.
5. **The package stands aside for `init`'s hook, never the other way round.** Before
   deciding, `--plugin` checks whether `init`'s hook decides this call: the lock is
   intact (no deny from `integrity::check`), it pins the hook file the host reads in the
   hook's environment (the agent's), OpenMoat's entry there is `Installed` for the binary
   the lock names, and for a host that runs `init`'s plugin, that plugin has reported
   loading since it last changed (ADR-042). Then the guard answers the host's "no
   decision" (`StandAside::NoDecision`) and records nothing; for Cursor, whose hooks have
   no such answer and whose answers merge deny over ask over allow whatever their source,
   it answers `allow` (`StandAside::Allow`), which leaves `init`'s answer as it is. In
   every other case the package's guard decides. `init`'s hook is kept because it is the
   one the lock pins and runs the binary by the path the lock records; the package's
   runs whatever `openmoat` the search path holds.
6. **`openmoat doctor` reports the package.** `--plugin` writes `plugins/<id>.json` in the
   state directory (host, time, release, whether it stood aside), at most once a minute
   while nothing changes. `doctor` prints it beside `init`'s hook, and for an agent with
   no hook of `init`'s it prints it in place of "hook missing". `--plugin --heartbeat`
   writes only this record: it never stands for `init`'s plugin having loaded.
7. **Every package is a preview** until it is listed in its channel; publishing is a
   person's step, listed per package in `plugins/README.md`.

## Consequences

- One command in the agent's own channel installs the hook side; the binary and
  `openmoat init` stay two steps, and the package's block message names them.
- With both installed, the protection is `init`'s: the package's answer cannot change a
  deny, and on Cursor `allow` merged with `init`'s answer is `init`'s answer. A fake
  `openmoat` placed earlier on the search path can make the package's guard answer
  anything, but not `init`'s hook, which runs the binary by its pinned path; a person who
  relies on the package alone has the protection of their search path.
- A package installed in a channel is outside the lock: the agent may update it, and
  the person may turn it off, without OpenMoat seeing either, as with any plugin.
  `openmoat init` remains the recommended setup and adopts nothing from the package.
- The guard scripts are POSIX `sh`: on native Windows the hook-command packages cannot
  run, and their agents then block or ignore the hook as each does for a hook that cannot
  start; Windows uses `openmoat init`.
- Under `openmoat run` the guard inside the sandbox has no state directory, so a package
  there does not stand aside and both hooks relay their calls.
- Formats come from each channel's official pages, cited in the spec; where a page leaves
  a detail open (Gemini CLI's extension `hooks/hooks.json` wrapper, Copilot CLI's plugin
  hook working directory before 1.0.111, OpenCode's npm plugin export, ClawHub's scoped
  names), the package follows the host's own hook file or plugin and the publish steps
  say to check it against a real agent first.
