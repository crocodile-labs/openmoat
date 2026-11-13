# ADR-091: An agent's files that run later come from its spec, and `openmoat run` protects all of its configuration

Status: accepted · Date: 2026-11-13 · Builds on ADR-018 (OS sandbox tiers), ADR-060
(editor configuration runs later), ADR-090 (project paths in every Linux tier)

## Context

The default policy's `runs-later` rule holds for review an agent's write of a file
that something runs later outside any sandbox: CI configuration, commit-hook
managers' files, the editors' and build tools' configuration, and each agent host's
own hooks, MCP servers, plugins, commands and subagents. `project-fs` leaves the
project's ones out of its grant, so the review is reached.

The hook sees only the agent's own tool calls. A command the agent runs (a script the
hook allowed, an install's `postinstall`) is confined by the OS sandbox of
`openmoat run`, which leaves `runs-later` files writable, since installs write CI
files and commit hooks (`husky`). The exception is an agent's own configuration in the
project (`AGENT_CONFIG` in `crates/openmoat-cli/src/sandbox/patterns.rs`): Seatbelt
denies commands writing it after every grant, the Linux tiers bind it read-only and
create a missing folder of it read-only for the session, and none of the tiers lets
the folders above it be renamed (ADR-090).

The host part of those lists was written by hand four times: `RUNS_LATER` and
`AGENT_CONFIG` in the CLI, and the policy's `runs-later` and `project-fs` lines. Only
`RUNS_LATER` and the policy were compared by a test. `AGENT_CONFIG` had drifted from
the rest: a command under `openmoat run` could write, on every tier,

- Cline's workspace hooks (`.clinerules/hooks/`, `.cline/hooks/`), every file of which
  Cline runs on each tool call with the person's rights;
- Gemini CLI's project policy files (`.gemini/policies/`, which can allow what
  OpenMoat leaves to Gemini CLI), custom commands (`.gemini/commands/`, whose shell
  runs when the person types the command) and subagents (`.gemini/agents/`);
- Claude Code's subagents, skills and slash commands (`.claude/agents/`,
  `.claude/skills/`, `.claude/commands/`) and GitHub Copilot CLI's custom agents
  (`.github/agents/`), whose frontmatter can carry hooks and shell;
- OpenCode's commands (`.opencode/commands/`, `.opencode/command/`) and the package
  file it installs plugin code from (`.opencode/package.json`).

The agent's own write of any of them was held for review; a command's was not, and
the host loaded the file in its next session, outside the sandbox.

## Decision

1. **Each host's spec names its files that run later.** `Protect::runs_later` in
   `crates/openmoat-hosts/src/contract/protect.rs` is a list of `RunsLater` entries:
   globs, the comment above them in the policy, and `agent_config`, set by
   `RunsLater::agent_config` for the host's configuration in a project (`**/…` globs
   only) and clear by `RunsLater::review` for its files in the home (the host's own
   state, which `openmoat run --write` may grant) and the folders above its
   configuration in a project.
2. **The default policy's host lines are generated from the specs.**
   `crates/openmoat-hosts/tests/protect.rs` writes the `runs-later` rule's host lines
   and `project-fs`'s `!${project}/…` exceptions for the hosts' project globs between
   two comment lines, as it does for `kernel-self`, `agent-credentials` and the taint
   list (`OPENMOAT_TEST_UPDATE_PROTECT=1`). The files no host owns (CI, commit-hook
   managers, editors, package managers and builds, git hooks outside `.git`, Python's
   start-up files, virtual environments, dev containers) stay hand-written in both.
3. **The CLI derives the host part.** `RUNS_LATER` is `NOT_AN_AGENTS` (the same
   hand-written files) and every host's project globs; `AGENT_CONFIG` is every glob a
   spec marks `agent_config`. A test asserts `RUNS_LATER` matches the policy's
   project globs and `project-fs`'s exceptions, and that `AGENT_CONFIG` is exactly
   the specs' marked globs; another asserts a marked glob names a project path and
   that a project path held for review only is a folder above the host's
   configuration.
4. **All of an agent's configuration is protected under `openmoat run`.** Every
   project glob a host loads as its configuration is marked, so every tier denies
   commands writing it as it already did for `.claude/hooks/` and `.mcp.json`: the
   Cline, Gemini CLI, Claude Code, Copilot CLI and OpenCode files above. A new host
   gets the same by marking its entries; no edit elsewhere is needed.

The set of files the policy reviews and `project-fs` leaves out is unchanged; only
the order of the policy's lines changed.

## Consequences

- Commands under `openmoat run` can no longer write the files listed in the context,
  nor create, rename or remove the folders that hold them directly in the project
  (`.cline`, `.clinerules`, `.gemini`). Change them outside `openmoat run`, or let the
  agent write them with its own tools, where the hook holds the write for review.
- `.clinerules` itself is now a folder above agent configuration: under `openmoat
  run` a command cannot create, rename or remove it (on macOS a `.clinerules` file,
  the older single-file form, is not writable by commands either), and without a
  network namespace on Linux nothing new can be created directly in it (ADR-090's
  holder folders). Rules files already in it stay writable.
- In the Linux bubblewrap tiers a missing `.claude/agents/`, `.claude/skills/`,
  `.claude/commands/`, `.github/agents/`, `.gemini/…` or `.opencode/commands/` folder
  whose holder exists is created empty and read-only for the session and removed
  afterwards, as `.claude/hooks/` already was.
- A host whose project configuration is not marked stays review-only in the hook;
  the specs' test fails on a project glob that is neither marked nor a folder above
  a marked one.
