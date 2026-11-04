# ADR-050: `openmoat policy check-diff` checks a change before merge with the policy's own rules, read as the base revision has them

Status: accepted · Date: 2026-11-04 · Builds on ADR-004, ADR-020 and ADR-022

## Context

OpenMoat decides each tool call as an agent makes it, on the machine where the agent
runs. What the agent wrote then leaves that machine as a pull request, and so does
work from people, from agents on machines without OpenMoat, and from forks. A pull
request that changes what runs or decides (a CI workflow, a commit hook, a package's
install script, an agent's settings or MCP servers, OpenMoat's own policy) or adds a
token does its harm once it is merged, or as soon as CI runs it. The policy already
names these files: the `deny` groups (`kernel-self`, `secrets-paths`, `agent-folders`),
the `ask` groups (`runs-later`, `git-internals`) and the paths session taint protects
(`taint.rs`, `taint.protected_writes`). The push check (POLICY.md §4.2) already searches
added lines for known token formats. Nothing applied them to a change under review.

## Decision

1. **One command, the engine's rules.** `openmoat policy check-diff` reads a change,
   either from git (`--base`, `--head`, default `HEAD`; the change is from their merge
   base to `--head`, as a pull request shows it) or as a unified diff on stdin. Each path
   the change writes (added, edited, deleted, renamed or copied from or to) is decided by
   `CompiledPolicy` as an `fs.write` inside a project, with session taint set as after
   reading untrusted content: a change under review is content nobody on the checking
   machine wrote. A `deny` is reported as `deny`, an `ask` (from an `ask` group or from
   taint) as `review`; `allow` and `defer` are not reported. The command holds no path
   list of its own.
2. **Strictest spelling.** Paths are compared without letter case, since the change may
   be checked out on macOS or Windows; each path is also decided with its names'
   trailing dots and spaces removed, as Windows opens it; `\` separates as `/` does;
   `.` and `..` are collapsed, and a path that leaves the repository or is absolute is
   `deny` (`diff-path`).
3. **What only a diff shows.** A symbolic link (mode `120000`) is `review`
   (`diff-link`), and where it points is decided as a write too (a target outside the
   repository is named as such). A submodule change (mode `160000`) is `review`
   (`diff-submodule`): the code it points to is not in the diff. An added line holding a
   known token format is `deny` (`diff-secret`, the push check's scanner); the value is
   never printed. With `--base`, paths come from git's own list of changed files as well
   as from the patch, so a name the patch spells in a way the parser misreads is still
   decided. A patch larger than the read limit has its paths decided and is `review`
   (`diff-unchecked`); input that is not a diff, or is cut inside a hunk, is an error
   (exit 64), never a clean result.
4. **The change cannot loosen its own check.** With `--base`, the policy files are read
   from the base revision with git (`--policy` when it is a relative path, and the
   repository's `.moat/policy.yaml`, merged untrusted as ADR-022 does: its deny and ask
   rules only). A change to any of them is reported (`diff-policy`), on top of what the
   policy says about the file (`kernel-self` denies `.moat/policy.yaml`). Without
   `--policy`, the shipped default policy is used, not the installed one, so every
   machine gives the same answer for the same change.
5. **Exit codes as `policy check`** (ADR-004): 0 nothing found, 2 something `deny`,
   3 only `review`, 64 the change or a policy could not be read. `--format` is `text`,
   `json` or `github` (workflow commands, `::error` for deny and `::warning` for review,
   then the text); `github` is the default when `GITHUB_ACTIONS=true`.
6. **The GitHub Action** is a composite `action.yml` at the repository root. It
   downloads the release the workflow pins (`version`, required), checks its sha256
   against the release's `sha256.sum` and its build attestation with
   `gh attestation verify`, as docs/INSTALL.md describes, and runs the command on the
   pull request's base and head. `fail-on` (`review`, the default, `deny` or `never`)
   maps exit codes to the step's result. It uses no other action, and inputs reach its
   scripts only through environment variables.
7. **git runs read-only** through the push check's runner (`push/git.rs`): no external
   diff or text conversion, no file system monitor, no pager or prompt; a revision that
   starts with `-` is refused; git is taken from an absolute `PATH` entry only.

## Consequences

- A change that edits CI, hooks, build or package files, or agent instructions needs a
  person's look by default; one that edits a file the policy denies to an agent
  (`.claude/settings.json`, `.env`) or adds a token fails with `fail-on: deny` too. A
  team that changes such files on purpose merges past the check or sets `fail-on`.
- It checks paths and added lines, not what a program does: a source file that runs
  later is code like any other and is not flagged, and neither is a script that a
  flagged file already names. Binary files are not searched. Renames are read as a
  deletion and an addition (`--no-renames`), so a renamed file's whole content is
  searched. Commit messages are not searched (the push check searches them).
- A dotfiles repository, whose files land in a home directory, is not modelled: `~/`
  rules do not meet repository paths. Windows short names (`GITHUB~1`) are not
  expanded.
- The command reads the change; it does not run under an agent's hook, and the default
  policy does not list it with OpenMoat's read-only commands, so an agent's own call of
  it is decided like any other run of OpenMoat's binary.
- Adding `diff-*` rule ids is additive; no public library API changes.
