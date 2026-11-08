# ADR-068: `status` and `doctor` read the agents' system-wide settings

Status: accepted · Date: 2026-11-08 · Builds on ADR-034

## Context

Three agents read settings an administrator deploys for the whole machine before the
person's own, and those settings win:

- Claude Code's managed settings (`managed-settings.json` and the drop-ins of
  `managed-settings.d/`): `disableAllHooks` there turns every hook off, and
  `allowManagedHooksOnly` runs only the hooks they list.
- Gemini CLI's system settings and system defaults: `hooksConfig` there turns hooks off
  as it does in the person's file.
- Codex's `requirements.toml`: `[features] hooks = false` forces every hook off, and
  `allow_managed_hooks_only` runs only the managed `[hooks]`.

The default policy already denies an agent's writes there (`managed-settings`, ADR-034).
But an administrator, an installer or another tool can still write them. When one does,
OpenMoat's hook is installed, pinned and current, and still never runs. `openmoat status`
and `openmoat doctor` then called the agent protected, because they read only the
person's own settings file for a key that turns the hook off.

## Decision

1. Each host spec names its system settings (`HostSpec::system_settings`): the files and
   the platforms that read them, the variable that moves one (Gemini CLI's
   `GEMINI_CLI_SYSTEM_SETTINGS_PATH` and `GEMINI_CLI_SYSTEM_DEFAULTS_PATH`), a drop-in
   folder, and the key that runs only the files' own hooks. Claude Code, Gemini CLI and
   Codex have one. The spec is the one place these facts live; the CLI reads it.
2. `status` and `doctor` read those files read-only, before the person's own settings.
   The host's own settings reader (`SettingsReader::switched_off`) judges each file, so
   the keys that turn hooks off are the same ones as in the person's file. A "managed
   hooks only" key counts only when no hook entry in those files runs `openmoat guard`.
   Its last value wins, so a drop-in can turn it off again.
3. A finding makes the agent `not protected`, with the file and the key named. This is
   the same "hook turned off by" reason the person's own file gives, so the home
   screen, `status --format json` and `doctor` show it unchanged.
4. A file that is missing, that this user cannot read, or that does not parse says
   nothing. Such a file cannot keep the hook from running for this user: the agent runs as
   the same user and cannot read it either. Nothing is written, created or locked, and the
   files are not pinned. An administrator changes them, not the person.

## Consequences

- An administrator's setting that turns OpenMoat off is visible where people already look.
  It needs no new command and no new state.
- Settings delivered another way are not read: Codex's macOS MDM profile, and Claude
  Code's managed settings from the server.
- A key these agents add later is not known until a host spec names it. The person's own
  file has the same limit.
