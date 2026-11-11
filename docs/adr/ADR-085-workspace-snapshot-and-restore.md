# ADR-085: Workspace snapshots in a shadow git store, and a person-only `openmoat restore`

Status: accepted · Date: 2026-11-10 · Builds on ADR-018 (`openmoat run`), ADR-031 (`kernel-self` reads), ADR-053 (review), ADR-056 (provenance)

## Context

OpenMoat decides before a call and records it, but cannot put files back after an allowed
call went wrong (a broad `rm`, a codemod, an install script rewriting files). Hosts' own
checkpoints miss shell-made changes: Claude Code says "A file that only Bash commands changed
isn't tracked and stays as it is" and that it skips symlinked and hard-linked files
(https://code.claude.com/docs/en/checkpointing). Cline and Docker Agent use a shadow git
repository separate from the project's history
(https://docs.cline.bot/core-workflows/checkpoints,
https://docs.docker.com/ai/docker-agent/features/snapshots/). APFS snapshots need root and an
entitlement (https://keith.github.io/xcode-man-pages/fs_snapshot_create.2.html); btrfs and
overlay are Linux-only. A git object store works on every system OpenMoat runs on, needs no
privilege, and stores unchanged files once.

## Decision

1. **Store.** One bare git repository per project at
   `<state directory>/snapshots/<first 32 hex characters of the SHA-256 of the project's real path>/`
   (`~/.moat/snapshots/…`, or under `MOAT_HOME`), created owner-only, with a file
   `openmoat-project` naming the project. Every git command starts from an empty
   environment: `GIT_DIR` is the store, `GIT_WORK_TREE` the project, `GIT_INDEX_FILE` an index
   in the store, `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_GLOBAL` the null device, `HOME` the store;
   `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `core.untrackedCache=false`,
   `gc.auto=0`, `commit.gpgSign=false` on the command line. git is the one the environment
   snapshot `openmoat init` recorded, by its absolute path. Only plumbing runs (`ls-files`,
   `update-index`, `write-tree`, `commit-tree`, `update-ref`, `for-each-ref`, `diff-tree`,
   `cat-file`, `gc`), none of which runs a hook; the store is created with `--template=` so it
   holds no sample hooks. The project's `.git` (config, hooks, index, `HEAD`, branches) is never
   read or written, so a `core.fsmonitor` or filter driver it names never runs, and a
   `.gitattributes` filter names a driver no configuration defines. The store's own
   `info/attributes`, which outranks every `.gitattributes`, sets `-text !eol -crlf -ident
   -filter !working-tree-encoding` for every path, so no attribute (one an agent planted
   included) changes the bytes stored: a restore writes back each file's bytes as they were,
   on any git version. Works whether or not the project is a git repository.
2. **What is captured.** The files `git ls-files --others --exclude-standard` lists against an
   empty index: the project's `.gitignore` files and its `.git/info/exclude` honoured (the
   person's global excludes file is not, since no global configuration is read). Left out,
   and named in the snapshot: every path for which the policy (the person's, OpenMoat's own
   binary, and the repository policy's deny rules) denies `fs.read` or `fs.write` (secrets such
   as `.env`, and OpenMoat's and the agents' own files), anything inside `.git` or `.moat`,
   nested git repositories, files over 5 MiB, what is not a file or a symbolic link, and names
   that are not UTF-8. A symbolic link is stored as a link, never followed; a hard link as a
   file. More than 100 000 files or 1 GiB to keep: no snapshot is taken, and the message says
   to ignore the generated folders. A snapshot is a commit without parent of the tree, on
   `refs/openmoat/snapshots/<ms>-<id>`; its message is JSON: version, reason (`run-start`,
   `run-exit`, `manual`, `pre-restore`), the run's session, file and byte counts, and the
   paths left out with why (at most 10 000 listed, the total always). When the files and
   left-out paths equal the newest snapshot's, none is added, except a run's start: each
   `openmoat run` records its own `run-start` snapshot, a new commit of the same tree (no file
   is stored twice), since a plain `openmoat restore` goes back to the newest one and must
   never reach back to an earlier run's.
3. **When.** `openmoat run` takes one before the agent starts and one when it exits, in its
   own process outside the sandbox, after pruning (§5). A run started from an agent (one is
   among its parent processes) takes none, and `--no-snapshot` takes none; both say so, and
   the audit log records each snapshot, each one that failed, and `--no-snapshot`. A snapshot
   that fails is said on stderr and the run goes on: snapshots repair, they do not decide.
   `openmoat snapshot` takes one by hand, `--list` lists them, `--prune` prunes.
4. **Only a person writes or reads the store.** `openmoat snapshot` (every form) and
   `openmoat restore` refuse when an agent or `openmoat run` is among their parent processes,
   as `openmoat allow` does; `restore` also needs an interactive terminal and an intact lock.
   `kernel-self` denies both commands to agents (also under pseudo-terminal wrappers), denies
   reading the store and, as for all of the state directory, writing, moving or deleting it.
   Every OpenMoat sandbox keeps the state directory out.
5. **Restore.** `openmoat restore [<id>] [--patch] [-- <paths>]` restores the named snapshot,
   by default the newest one `openmoat run` took before its agent started. It first takes a
   `pre-restore` snapshot of the files as they are, and compares the two: files changed, added
   back and deleted, each named (`--patch` prints the differences, with no external diff or
   text conversion), then asks `[y/N]` at the controlling terminal. A path the snapshot left
   out is never deleted or written; when the snapshot's list of left-out paths was cut, no
   path missing from it is deleted. Each snapshot also lists the paths that existed and that
   the project's ignore rules left out (`ls-files --others --ignored --directory`: a folder
   ignored as a whole is one entry); a restore never deletes one of them, or anything below
   one, even when the agent has since stopped ignoring it, and names it as left as is, not
   in the snapshot. When that list was cut at 10 000, no path missing from the snapshot is
   deleted. A file the undo snapshot could not keep (now ignored,
   large or denied) is named as written over without a copy. Writes never pass through a
   symbolic link or a file where the snapshot has a folder: such a path is skipped and named.
   Each file is written beside its place under a fresh name and renamed over it, so a link
   at the path is replaced, not followed. The audit log records the restore. `openmoat
   restore <undo id>` undoes it.
6. **Retention.** Per project the newest 50 snapshots, none older than 14 days, and always the
   newest; pruned at every `openmoat run` start and by `openmoat snapshot --prune`, then
   `git gc --prune=1.hour.ago` drops the files no snapshot holds, once they are an hour old.
   Taking, pruning and restoring hold the store's lock file (`openmoat.lock`, an OS file
   lock, waited for up to 10 s), a restore from its undo snapshot until the files are
   written, and each take stages into an index file of its own process, so two runs in one
   project, or a run and a person's `snapshot` or `restore`, never lose each other's objects
   or fight over one index.
7. **What it is not.** It does not undo network sends, pushes, database writes, files outside
   the project, ignored, denied or large files, empty folders, permissions other than the
   executable bit, extended attributes, or changes made while a restore runs. Docs say so
   first (LIMITS.md "Snapshots and restore").

## What this must never do

- Run inside `openmoat guard` or add to its latency.
- Copy a denied file into the store, or make the store readable to the agent.
- Restore, delete or overwrite without the person's yes at a terminal.
- Run the project's git configuration or hooks, or the person's global git configuration.
- Write through a link the agent left in the project.

## Corrections to the draft

- The draft said agents may run `openmoat snapshot` because it only adds. It does not only
  add: every snapshot counts against the retention, so an agent taking 50 would push the
  person's run-start snapshot out, and `--list` names files the agent deleted. Every form is
  person-only now, and a run started from an agent takes none.
- The draft said the store is unreadable to agents because of `~/.moat`. `kernel-self` named
  `~/.moat/**` for writes only; reading the store is now denied by name
  (`~/.moat/snapshots/**`, `**/.moat/snapshots/**`).
- `safe.bareRepository=explicit` is dropped: `GIT_DIR` is always explicit, so it never
  applies. The system and global configuration files are emptied instead, which the draft
  left in force (a person's global `filter.lfs` or `core.fsmonitor` would have run).
- Left out are paths a deny rule names for reading or writing, not reading only: writing back
  an agent's settings file or OpenMoat's own files is a pinned-file change for the person's
  own tools.
- Refs are `refs/openmoat/snapshots/<ms>-<id>` with JSON metadata instead of
  `refs/openmoat/<session>/<n>`: listing and pruning are one sorted ref walk.
- Added: per-snapshot file and byte limits (no partial snapshot), "unchanged" detection, the
  default restore target, the link-safe write, and the undo-without-copy warning.
- The draft's step 4 (a snapshot before a reviewed destructive call, taken by `openmoat run`'s
  relay service) is not built: it sits on the hook's decision path, whose review flow the
  remote-approval work (ADR-078) changes at the same time. It stays a next step, below.

## Answers to the draft's open questions

- Defaults: 5 MiB per file, 100 000 files and 1 GiB per snapshot, 50 snapshots and 14 days per
  project. Constants in this release; a policy setting needs a core schema change and is a
  next step.
- Provenance (ADR-056) naming the snapshot taken before a session's writes: not done; the
  audit log records the run session of each snapshot, which is enough to join them later.

## Consequences

- `openmoat run` start-up grows by the time of one snapshot. The first one hashes every file;
  later ones reuse the store's index and hash only changed files, as `git add` does. The
  time is printed with each snapshot and recorded in the audit log. No number for a
  100 000-file project is given yet: the machine this was built on runs every file write
  under a sandbox that makes plain `git update-index` of 5 000 files take minutes, so its
  timings say nothing about a person's machine. The limits above bound the worst case.
- The store holds old contents of the project's files (never denied ones) for up to 14 days.
  `openmoat uninstall --purge` deletes it with the rest of the state directory.

## Next steps

1. A snapshot before a reviewed destructive call inside `openmoat run`, with a time bound.
2. Policy settings for the limits and the retention.
3. After 1.0: an overlay review mode for `--isolate` (writes go to an upper directory; at exit
   the person accepts or drops them). Separate ADR.
