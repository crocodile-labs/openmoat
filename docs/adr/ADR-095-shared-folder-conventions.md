# ADR-095: Folders several agents load by one convention are one fact, named by each host's spec

Status: accepted · Date: 2026-11-14 · Builds on ADR-057 (instruction files), ADR-091
(agent configuration from host specs), whose two open points it closes

## Context

ADR-091 left two OpenCode folders out of `runs-later`:

- the person's own agents and skills in `~/.config/opencode` (`agents/`, `skills/`, and
  the singular `agent/`, `skill/` and the `mode/`, `modes/` folders OpenCode 1.19.4
  also globs, `src/config/agent.ts`, `src/skill/index.ts`), which load into every later
  session with no prompt, an agent with its own permissions;
- a project's `.agents/skills/`, the Agent Skills folder (<https://agentskills.io>),
  which no spec named.

`.agents/skills` is not OpenCode's. By their own docs Codex
(<https://learn.chatgpt.com/docs/build-skills>), Cursor
(<https://cursor.com/docs/context/skills>), GitHub Copilot CLI
(<https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/create-skills>),
pi (`packages/coding-agent/docs/skills.md`), Gemini CLI
(<https://geminicli.com/docs/cli/skills/>), OpenCode (<https://opencode.ai/docs/skills>),
goose (<https://goose-docs.ai/docs/guides/context-engineering/using-skills>) and
Antigravity CLI (<https://antigravity.google/docs/skills>) load it, in a project and
(all but Antigravity CLI) in the home; Claude Code and Cline document their own folders
only. Since ADR-057 its globs sat in Codex's spec, in the taint list only, so a clean
session wrote a skill all of those hosts load next time, and `openmoat run` let a
command write it. Copying the globs into eight specs would list them eight times in the
generated policy and break the sandboxes' one-entry-per-file lists.

## Decision

1. **A convention is a value of its own.** `Convention` (`crates/openmoat-hosts/src/contract/convention.rs`)
   holds a name, `runs_later` entries and `taint` paths, written once; `AGENT_SKILLS`
   is the first. `HostSpec::conventions` lists the ones a host's docs say it loads, each
   with the doc it comes from.
2. **Generated once.** `tests/protect.rs` writes each convention some spec names after
   the hosts' own lines in `runs-later`, `project-fs` and the taint list, under a line
   naming those hosts; `every_runs_later()` gives the CLI's `RUNS_LATER` and
   `AGENT_CONFIG` the same entries. A test fails if a host lists a convention's glob
   itself.
3. **`AGENT_SKILLS`:** `**/.agents/skills/**` is agent configuration (review in the hook,
   denied to commands under `openmoat run`), `**/.agents` and `**/.agents/skills` are
   the folders above it (review), and the taint list holds all three, as it must
   every `runs-later` file (`protected_writes_cover_runs_later_and_the_kernel_config_files`). `**/` matches the home's folder too.
4. **OpenCode's own folders:** `~/.config/opencode/{agents,agent,modes,mode,skills,skill}/**`
   and those folders, with `commands`, `command`, `tools`, `tool`, need review; a
   project's `.opencode/{modes,mode,skill}/**` join its agent configuration.
5. **The architecture test** treats `.agents` as a shared folder, as it does `.config`
   and `.github`; a host's own files and folders in it (`.agents/hooks.json`,
   `.agents/mcp_config.json`, `.agents/plugins`) are still matched as that host's.

## Consequences

- ADR-057's "a clean session edits them freely" no longer holds for `.agents/skills`:
  every write there needs review, as `.claude/skills` has since ADR-091.
- Under `openmoat run`, a `git pull` or an install that adds `.agents/skills/` fails
  partway, as ADR-091 describes for the other agents' configuration.
- Creating, renaming or removing a project's `.agents` folder needs review; files
  directly in it that no host names stay ordinary project writes.
- Not covered: OpenCode 2's system directory (`/etc/opencode` and its macOS and Windows
  equivalents), skill folders a configuration's `skills.paths` adds, and the hosts
  whose `.agents/skills` support is not documented (Continue, OpenClaw, Hermes Agent).
