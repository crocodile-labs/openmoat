# ADR-092: Drift a hook file may take comes from the spec of the host the lock pinned it for

Status: accepted · Date: 2026-11-13 · Builds on ADR-006 (policy lock); refines the
settings-drift allowlist (#287, #288, #591) and Gemini CLI's relaxed keys

## Context

The policy lock denies every call when a pinned file changes. Two hosts rewrite their
own hook file for a person's choice: Claude Code its `settings.json` (theme, model,
display toggles, its own permission lists) and Gemini CLI its `settings.json` (model,
theme, sign-in method). Denying every call after `/model` would make OpenMoat unusable,
so the lock lets those keys drift while the guard keeps deciding.

Gemini CLI's keys were in its spec (`InstallSpec::relaxed_keys`). Claude Code's were
in the CLI (`integrity/relaxed.rs`), with `theme` left out of the digest by
`integrity/digest.rs`, and both were chosen by the file's name: any pinned file
named `settings.json` was read as Claude Code's. An agent added later whose hook file
is also called `settings.json` would have taken Claude Code's allowlist without anyone
deciding it, and its permission lists, model and display keys would have drifted
without stopping the guard.

## Decision

1. **The keys are host facts.** `InstallSpec` holds them all: `relaxed_keys` (each
   with a `KeyShape`: string, flag, scalar, any value, one of a list of values, or a
   list that still holds every rule OpenMoat wrote), `relaxed_check` (`Rest`: the lock
   pins the file without the keys and compares the rest, Gemini CLI; `ByKey`: the lock
   pins each top-level key, and each key of the one object the dotted keys are in,
   Claude Code with `permissions`), and `unpinned_keys` (top-level keys left out of
   the digest, Claude Code's and Gemini CLI's `theme`). Claude Code's list is in
   `host/claude_code/settings.rs`. The CLI has no host's key.
2. **The owner, not the name.** The lock records the host that owns each hook file it
   pins (`hook_owners`), from the same source that installed it. Only the owner's
   spec says which keys may drift and which are left out of the digest. A file the
   lock does not record as a host's hook file, or one of a host whose spec lists no
   keys, drifts on any change to its bytes.
3. **Older locks keep verifying, and migrate without keeping a guess by name.** A
   lock written before `hook_owners` is read as before until it is re-pinned: a file
   at a host's `<dir_name>/<config_file>` is that host's, and a file named like the
   `config_file` of the one host with such keys whose variable names the directory
   itself (Claude Code's `CLAUDE_CONFIG_DIR`) is that host's. The first re-pin
   (`openmoat init`, `doctor --accept`, `allow` and the other re-pinning commands,
   `uninstall`'s unpin) records an owner only where it is more than a name: a file
   this shell installed as that host's hook file, one exactly at its host's
   `<dir_name>/<config_file>`, or one the lock's pinned forms name. Any other file
   is recorded as no host's: pinned by its bytes, it drifts on any change until
   `openmoat init`, from a shell whose variables point at it, records its owner.
4. **The version gate is a spec fact too.** Whether `openmoat init` writes the flag that
   makes a host block a failed hook's call (`HookSpec::block_on_failure`, Claude Code's
   `onFailure`) is asked of every copy of the host's programs (`ProcessSpec::names` on
   `PATH`, and `bundled`) against the version its `hook_failure` names
   (`FailureOutcome::BlocksFrom`, `HookFailure::flag_since`), per host
   (`install/on_failure.rs`); debug builds read the version on `PATH` from
   `MOAT_<ID>_VERSION`.
5. **Matched by names, per host.** A relaxed key matches by its path's names: a
   top-level key matches only a path with no `.`, and `parent.key` only `key` inside
   the object `parent`, so a top-level key literally named `permissions.allow` is
   drift. The rules a `KeepsWrittenRules` list must keep are the ones OpenMoat wrote
   into that host's own hook file (`Recorded::written_rules`: the sandbox rules of the
   host whose `ClaudeSettings` sandbox lives in its hook file); any other host has
   none, so its list cannot change without denying.

## Consequences

- Adding a host with relaxed keys, or with a fail-closed flag gated on a version, is a
  spec edit; no CLI file changes. A host that lists none gets no relaxation.
- The lock grows one map. An older release reading a lock from this one ignores the
  unknown field and reads by name as it did.
- `ByKey` keys are at most one level deep, under one object, and only `ByKey` may use
  the rule-keeping list; a hosts contract test enforces it.
- Attack tests (`integrity/relaxed/tests.rs`): a `settings.json` pinned for a host
  without relaxed keys, or for no host, denies every call on a theme, language, model
  or permission-list change; Claude Code's keys follow the owner under any file name.
