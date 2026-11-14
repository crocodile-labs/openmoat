# ADR-099: Packages for each agent's own plugin channel, generated from the host specs

Status: accepted · Date: 2026-11-14 · Builds on ADR-033 (OpenClaw's plugin), ADR-042
(plugin heartbeat), ADR-071 (the state directory on the hook's command line), ADR-091
(agent configuration from host specs) · Numbered 099: 095 to 098 are taken by branches
open at the time of writing

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

A package's hook also runs with whatever environment the agent has, and a repository can
set part of it (a project `.env`, a settings file's `env`). `init`'s hook names its binary
and state directory on its own command line (ADR-071); a package cannot, because it is
written before `init` runs and is the same for every machine.

## Decision

1. **Each host spec says how its channel installs OpenMoat** (`HostSpec::plugin`,
   `contract/plugin.rs`): a `PluginSpec` in `host/<module>/plugin.rs`, or
   `Plugin::None` with the reason. A `PluginSpec` names:
   - the channel, the install command, the publish steps and the official pages its
     layout follows;
   - the marketplace file that lists it, where the channel has one;
   - the exit code its guard script blocks with (`deny_exit`);
   - the folder where the host keeps the package once installed (`installed`);
   - its files.

   The hosts without a package: Codex (its directory refuses plugins that carry hooks),
   Cline (its SDK plugins wait 3 s and fail open) and goose (no registry, and `init`
   already writes an Open Plugins folder).
2. **`plugins/` is generated** from those specs (`openmoat_hosts::plugin::files`), never
   edited: `cargo test -p openmoat-hosts --test plugins` fails when it differs, and
   `OPENMOAT_TEST_UPDATE_PLUGINS=1` rewrites it. The packages carry the workspace
   version, so a release regenerates the folder. The facts are not copied:
   - a hook-command package's hook file is the host's own `HookFile` layout writing the
     entries `init` writes (`InstallSpec::hooks`), with the package's guard script in
     place of the binary;
   - a plugin-loading host's package is `init`'s `OwnedFile` with an empty state
     directory, which makes it run as a package;
   - the deny a package prints is the host adapter's rendering of the guard's own
     `kernel-error` deny.
3. **No binary, no download, and the lock's binary first.** A hook-command package runs
   `openmoat-guard`, a POSIX `sh` script, with the arguments `init`'s hook gives the
   binary, plus `--plugin`.
   - **Which binary:** the one the policy lock pins (`binary` in `~/.moat/policy.lock`,
     the absolute path `init` recorded). A lock that names no absolute, runnable
     program (or one the script cannot read without JSON escapes) blocks the call.
   - **Without a lock:** a folder OpenMoat's installers use (`~/.cargo/bin`, Homebrew's
     prefixes), then the search path. The agent's environment decides the search path,
     so it comes last, and only where the guard denies every call anyway.
   - **Blocking:** with no program, or when it exits other than 0, or 2 without an
     answer, the script prints the host's deny and exits with the host's block code,
     naming the one install command (`openmoat_hosts::NOT_INSTALLED`). That code is 2
     for most hosts. For Antigravity CLI it is 0, because its build-plugins guide says a
     hook must exit 0 with its JSON and any other exit is ignored. The guard's own deny
     (exit 2 with its answer) is passed on with that code too.
   - **The other packages:** the JavaScript plugins (pi, OpenCode, OpenClaw) find the
     program in the same order and block with the same words. Hermes Agent's Python
     plugin does too, and returns a block for every failure, since Hermes skips a
     callback that raises.
4. **`openmoat guard --plugin` decides as `init`'s hook does**, lock first. No lock, a
   drifted lock or no state directory denies and names `openmoat init`, which stays the
   only way to write the policy and its lock. The guard also denies a `MOAT_HOME` that
   names any directory but the default `~/.moat`: a package has no `--home` of its own,
   and the environment may be a repository's.
5. **The package stands aside for `init`'s hook, never the other way round.** Before
   deciding, `--plugin` checks that `init`'s hook decides this call. Every one of these
   must hold:
   - the lock is intact (no deny from `integrity::check`);
   - it pins the hook file the host reads in this environment. That file comes from the
     host's own variable, else its default under the home directory
     (`HostConfig::for_environment`), never from `hosts.json`, which records where
     `init` ran, perhaps for another copy of the agent;
   - OpenMoat's entry there is `Installed` for the binary the lock names;
   - no settings file the host reads turns that hook off by name, neither the person's
     nor the project's for the payload's or the hook's working directory
     (`project_settings::hook_switched_off`);
   - for a host that runs `init`'s plugin, that plugin has itself reported loading
     (`guard --heartbeat`) since its file or the host's program last changed
     (`heartbeat::reported_since_change`).

   When they hold, the guard answers the host's "no decision" (`StandAside::NoDecision`)
   and records nothing. Cursor's hooks have no such answer, and Cursor merges answers
   deny over ask over allow whatever their source, so for Cursor it answers `allow`
   (`StandAside::Allow`), which leaves `init`'s answer as it is. In every other case the
   package's guard decides.
6. **A package's decisions are its own.** The events `--plugin` records are marked in the
   audit log's `package_events` table (schema 11, in the event's transaction), and
   `Store::host_seen_since` leaves them out. A call the package decided therefore never
   reads as `init`'s plugin having loaded, neither for standing aside nor in `openmoat
   status`.
7. **The installed package is `kernel-self`'s.** The folder each host keeps OpenMoat's
   package in, by OpenMoat's own folder or package name only (`PluginSpec::installed`),
   is written into `kernel-self`'s generated block (`tests/protect.rs`). Other plugins'
   folders keep the verdict they had. The settings that turn a package off are the
   host's own settings files, which that rule already names.
8. **`openmoat doctor` reports the package.** `--plugin` writes `plugins/<id>.json` in the
   state directory (host, time, release, whether it stood aside), at most once a minute
   while nothing changes. `doctor` prints it beside `init`'s hook, and for an agent with
   no hook of `init`'s it prints it in place of "hook missing". `--plugin --heartbeat`
   writes only this record: it never stands for `init`'s plugin having loaded.
9. **Every package is a preview** until it is listed in its channel; publishing is a
   person's step, listed per package in `plugins/README.md`.

## Consequences

- One command in the agent's own channel installs the hook side; the binary and
  `openmoat init` stay two steps, and the package's block message names them.
- **With both installed, the protection is `init`'s.** The package's answer cannot
  change a deny, and on Cursor `allow` merged with `init`'s answer is `init`'s answer.
- **With the package alone**, its limits are stated in every package's README, in
  `plugins/README.md` and in INSTALL:
  - it runs the binary the lock pins, found from the agent's `HOME`;
  - it decides only with the default state directory;
  - it is outside the lock: the agent may update it, and the person or a project's
    settings may turn it off, without OpenMoat seeing either. `kernel-self` keeps the
    agent's own tools from changing its installed folder, where the host's layout
    puts it under a name OpenMoat knows;
  - `openmoat init` remains the recommended setup and adopts nothing from the package.
- **The heartbeat is not per process.** A plugin's report that `init`'s plugin loaded
  stays valid until that plugin's file or the host's program changes. It does not prove
  that the process now running loaded it, because no plugin reports its process.
- **Windows:** the guard scripts are POSIX `sh`. On native Windows the hook-command
  packages cannot run, and their agents then block or ignore the hook as each does for a
  hook that cannot start; Windows uses `openmoat init`.
- **Under `openmoat run`:** the guard inside the sandbox has no state directory, so a
  package there does not stand aside, and both hooks relay their calls. The run's own
  records of relayed calls are not marked as a package's.
- **Formats** come from each channel's official pages, cited in the spec. Some pages
  leave a detail open, and there the package follows the host's own hook file or plugin,
  and the publish steps say to check it against a real agent first:
  - Gemini CLI's extension `hooks/hooks.json` wrapper;
  - OpenCode's npm plugin export, and where OpenCode, pi and OpenClaw keep an installed
    npm or ClawHub package (covered by the package's own name wherever an npm folder
    holds it);
  - the folder Cursor keeps a Marketplace install in;
  - Copilot CLI's direct-install source id;
  - ClawHub's scoped names.
