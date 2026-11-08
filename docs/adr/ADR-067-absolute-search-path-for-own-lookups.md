# ADR-067: OpenMoat finds the programs it runs in absolute PATH entries only

Status: accepted · Date: 2026-11-08 · Builds on ADR-008

## Context

ADR-008 resolves the program a shell command names through the search path `openmoat
init` recorded, so a poisoned `PATH` or a planted `git` cannot change which binary the
guard believes is about to run. That lookup mirrors the shell on purpose: a relative entry
(`.`, `node_modules/.bin`) is searched as the shell would search it, so a planted program
there resolves to the planted file and fails its pin.

OpenMoat also looks programs up for itself, outside that snapshot, and some of those
lookups ran the file they found or trusted it:

- `openmoat init`, `status` and `doctor` run `claude --version` and each host's program
  with `--version` (OpenMoat Bar runs `status` and `doctor` every minute);
- `init` pins the location of `sh`, `git`, `curl` and the other pinned programs;
- `init` records the path of its own binary in every hook, found through `PATH` when it
  was started by a bare name;
- `openmoat sandbox sync` lets Codex's commands read the `codex` on `PATH` (Linux);
- `openmoat run` starts the agent it is given by name; `provenance` and `policy diff`
  run `git`.

Each walked the whole `PATH`. With a relative entry and a working directory in a
repository, a file the repository holds (`./claude`, `./git`) was run, pinned as the real
one, written into a hook as a relative path, or granted to the sandbox.

## Decision

1. Every lookup OpenMoat makes for a program it runs, probes, pins, records or grants goes
   through one function, `environment::find_on_path`, which searches only the absolute
   entries of `PATH` (`environment::absolute_search_path`). The snapshot's pins are taken
   from its absolute entries only, and `Snapshot::program` (programs OpenMoat runs from
   the snapshot) already skipped relative entries.
2. The snapshot's resolution of a command's program for the guard (`ProgramResolver::
   resolve`) keeps the shell's order, relative entries included, as ADR-008 decided: it
   answers what the command would run, and a relative match fails the pin.
3. Codex's executable, which its Linux sandbox is granted, is found the same way: in
   absolute `PATH` entries only. Where it is installed is not checked: a check of
   installer locations refused Codex in version managers, `/opt` and CI caches, while a
   program in an absolute `PATH` folder is one the person put there (a write to such a
   folder by an agent already needs review, `persistence`).

## Consequences

- A program reachable only through a relative `PATH` entry is not found by these lookups:
  `openmoat run tool` refuses where the shell would have run `./tool` (name it by path),
  and a host installed only there is not detected.
- New code that looks up a program outside the snapshot uses `find_on_path`; the end-to-end
  test `a_relative_path_entry_never_runs_or_pins_a_planted_program` plants every host's
  program and the pinned ones in the working directory with `.` first on `PATH`.
