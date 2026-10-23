# ADR-021: OS layers may be wider than the hook only by listed allowances

Status: accepted · Date: 2026-10-06 · Refines ADR-019

## Context

ADR-019 says a backend narrows what it cannot express and never widens. The Standard
tier (ADR-018) showed where that cannot hold:

- The default policy asks for every read outside the project (`"*": ask`). Lowered to
  an OS layer, an `ask` is a deny, so every read of a toolchain (`~/.cargo`,
  `~/.rustup`), a system directory or the temp directory would be denied, and no build
  would run.
- The hosts need grants of their own: Codex's `:minimal` platform reads and a
  writable `:tmpdir`; Claude Code's sandbox writes the session's working directories
  and closes reads only under the user directories.
- A directory in Claude Code's `denyWrite` (and a denied directory in Codex) covers its
  whole subtree, so `kernel-self`'s directory-node rule (`**/.claude`: no rename or
  delete) would make `.claude/worktrees/*` read-only.

## Decision

- An OS layer may allow what the hook does not only through an **allowance**: an entry
  with its source (`sandbox.read_roots`, `codex.minimal`, …), the paths and the reason.
  Allowances are never silent: `moat sandbox show`, `moat sandbox sync` and
  `moat doctor` print them next to the losses.
- **`sandbox.read_roots`** (additive to schema v1) is the policy's own allowance: paths
  OS layers may read although no allow rule covers them. Plain paths only, never a
  glob, a filesystem root or the home directory. The IR carries it apart from its
  read rules (`Enforcement::allowances`), so the IR's own verdicts stay the hook's or
  stricter and the existing consistency tests keep proving it. `Checker::check_os`
  applies it after the deny rules: a deny rule still wins inside a root in every layer.
- The hook ignores allowances: a read under a root keeps the verdict the rules give
  it (ask by default).
- Writes get no policy allowance. A host's own write grants (temp, working
  directories) are listed as allowances of that backend.

## Consequences

- Sandboxed commands can read the read roots without a prompt; secrets inside them
  stay denied (`~/.cargo/credentials.toml`), verified against both hosts.
- A policy reviewer sees every widening in one list per host, and the differential
  suite (#170) can treat an allowance as an expected disagreement instead of a bug.
- A policy written before the key existed gets the default policy's list, and the
  tools say so; a policy that sets `sandbox: {}` gets none.

## Amendment 2026-10-06 (#203)

Decided by the maintainer. The policy keeps the project's `.git` from writes
(`!${project}/.git/**`), and Claude Code user settings cannot name the project, so
the generator denied every `.git` and `git commit` failed in Claude Code's sandbox.
Commits are a core Claude Code workflow, so the Claude Code backend now denies only
the paths that make git run code or read another repository's, and lists the rest of
`.git` as the allowance `claude-code.git-internals`:

- `/**/.git/hooks` (a directory in `denyWrite` covers its subtree) and `hooks/**`:
  hooks run on commit, checkout, merge and push;
- `/**/.git/config`: `core.hooksPath`, `core.fsmonitor`, `core.sshCommand`, filter,
  diff and merge drivers, aliases, `include.path`;
- `/**/.git/config.worktree`, `/**/.git/worktrees/*/config.worktree`: per-worktree
  config, read like `config`;
- `/**/.git/info/attributes`: selects filter and diff drivers;
- `/**/.git/worktrees/*/commondir`: points a linked worktree at another repository,
  whose config and hooks it then uses;
- the same paths under `/**/.git/modules/**`, the repositories of submodules.

Verified with Claude Code 2.1.290 on macOS (fake `HOME`, local fake API): `git commit`,
`git branch`, `git tag`, `git gc` work; writing any path above, `git config`, and
renaming `.git`, and renaming or deleting `.git/hooks` fail with `Operation not permitted`.

Residual risk: a sandboxed script can rewrite refs and objects (history tampering,
which `git log`, signatures and review can detect), write a rebase todo that a person
later continues, and write a `.git` file (`gitdir: …`) below the project, which the
hook allows too. It cannot install hooks or change config. The hook is unchanged: it
still asks for file-tool writes to the project's `.git`. Codex keeps `.git` read-only
by its own design, and that stays a listed loss.
