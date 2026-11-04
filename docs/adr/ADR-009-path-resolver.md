# ADR-009: Symlinked action paths checked through a caller-supplied `PathResolver`

Status: accepted · Date: 2026-10-05

## Context

Policy patterns name locations (`~/.ssh/**`, `${project}/**`), and the core normalises
action paths lexically (`paths.rs`). A symlink makes a path inside the project refer to a
location outside it: after `ln -s ~/.ssh ./s`, `cat ./s/id_rsa` read the private key and
was allowed by `project-fs` (audit 2026-10-05, P0-6; `DESIGN.md` T11). Resolving links
needs the filesystem, and `moat-core` must stay pure (ADR-008 solved the same problem for
program names).

## Decision

- `moat-core` defines `trait PathResolver { fn resolve(&self, path) -> Option<path> }`
  over normalised, slash-separated absolute paths. `None` means "same path or unknown".
  A path that does not exist yet resolves through its deepest existing ancestor, so a new
  file written into a symlinked directory resolves to where it would land.
- `CompiledPolicy::decide_with(action, &programs, &paths)` adds, for every `fs.read` and
  `fs.write` atom whose resolved path differs, a second atom of the same kind with the
  resolved path. Both are evaluated and the strictest verdict wins, so neither the literal
  nor the real location can be used to slip past a rule. `decide` uses `NoResolver`.
- The filesystem implementation lives in the CLI, next to the program resolver, and is
  used by `moat guard`. Conformance fixtures describe links with a `links:` map
  (`MapPathResolver`).

## Consequences

- Reads and writes through symlinks are checked at their target; fixture class T11.
- Resolution happens at decision time. A link swapped between the check and the command
  running (TOCTOU), hard links, and a link created by the same command that uses it are
  not visible; the last one still needs review because creating the link is a `review` action.
  OS enforcement (`moat exec`) is the complete answer.
- Core purity holds; the engine gains one parameter and no dependency.
