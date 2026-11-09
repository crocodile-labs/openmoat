# ADR-072: a shell write of a project's hook settings is denied

Status: accepted · Date: 2026-11-09

## Context

A project file can turn an agent's hook off: `[features] hooks = false` in
`.codex/config.toml`, a `-openmoat` plugin entry in `opencode.json`, an `extensions`
exclusion in `.pi/settings.json`. The policy decides a write by its path, so those files
are a `review` (`runs-later`). The guard already denies a write whose content it can work
out and which turns the hook off (`project_settings/written.rs`): a whole-file write, an
edit, an `apply_patch`.

A shell command cannot be replayed. `printf … > .codex/config.toml` kept its `review`, and
an agent that answers reviews without a person (OpenCode 2 `--auto`) got the file written.
The next session started there ran without OpenMoat.

## Decision

1. **Deny a shell write whose content is not known.** A command that creates or replaces
   a host's project settings file is denied with `project-settings`. That covers every
   form the classifier reads as leaving content of the command's choosing: a redirect
   (`>`, `>>`, `>|`), `tee`, `dd of=`, `sed -i`, the destination of `cp`, `mv`, `ln`,
   `rsync`, `install`. `openmoat_core::replaced_files` lists them.
2. **Only where it can matter, so ordinary work is not stopped.**
   - The path must be one the host would load for a session in the working directory or
     at the project root (`project_settings::candidates`, what `status` and `doctor`
     read). A template or a test fixture of the same name keeps its verdict.
   - OpenMoat's hook file of that host must exist: a host OpenMoat is not set up for has
     no hook to lose.
   - A read, a removal, a move away, `touch`, `chmod` and `truncate` leave nothing the
     host reads as a setting and keep their verdict (`tables::NO_CONTENT_WRITES`).
3. **The file tools are unchanged.** Their content is known, so they stay judged by it:
   a benign edit keeps its `review`.

The deny message names the file tools as the way to make the change.

## Consequences

- `jq … opencode.json > t && mv t opencode.json` in a project set up for OpenCode is now
  denied, though it may be harmless. The agent can make the same change with its file
  tools, where the result is checked.
- A write through something the classifier cannot read keeps its `review`: a script, a
  PowerShell command, a whole directory copied over the folder, a path behind a glob or
  an unknown variable, a subfolder a later session might start in. `docs/LIMITS.md` lists
  them.
