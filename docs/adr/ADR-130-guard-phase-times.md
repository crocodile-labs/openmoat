# ADR-130: The guard records how long each phase of a call took

Status: accepted · Date: 2026-11-25 · Builds on ADR-079 (the disturbance figures) and
ADR-120 (the guard's phases and deadline)

## Context

MoatBench's end-to-end test runs `openmoat guard` on the same GitHub runner types for
every release. The median call took 32 ms on 0.19.0 and 64 ms (Ubuntu) and 73 ms (macOS)
on 0.28.0. Measured on a macOS 12 machine:

- Process start and the guard's fixed path did not move: `openmoat --version` took
  15.9 ms on 0.19.0 and 15.8 ms on 0.28.0, and the guard with no state directory
  32.7 ms and 33.7 ms.
- Parsing, linting and compiling the default policy and deciding a first call grew
  step by step, from 26.5 ms to 36.5 ms.

So most of the growth is in the phases that read the state directory (`~/.moat`): the
lock check, the context loads, the taint and audit reads, the session cache and the
audit write. Those could not be measured on that machine, and nothing recorded them:
each audit row has one number, `latency_us`, the guard's time from its start to the
row's write.

One cost was found by reading the code: since 0.24 `Policy::parse` deserialized the
whole policy document twice, once only to read `version:` (about 3 ms a call).

## Decision

1. **The guard times its phases.** The guard already moves through named phases for
   its deadline (ADR-120): `stdin`, `relay`, `lock`, `context`, `compile`, `taint`,
   `approval`, `cache`, `record`, `answer` (`crates/openmoat-cli/src/hangs.rs`). Each
   move now also adds the time since the last move to the phase it leaves
   (`hangs/times.rs`); a phase entered twice (`record`, around `cache`) adds up.
2. **Every call's audit row carries them.** Schema version 13 adds the column
   `phases_us` to `events`: a JSON list of `[phase, microseconds]` for each phase the
   call went through, in the guard's order. The guard reads the times just before the
   row's write, so `record` holds the time up to the write and not the write itself, and
   `answer` comes after the row. A row from before version 13, or from another writer
   (the proxy, `openmoat run`, a deadline's row), has none: the column is `NULL`, the
   event's `phases_us` is `None`, and every reader takes that as no times.
3. **Durations only.** The store keeps only entries whose name is lowercase ASCII
   letters, at most 16 of them, and the guard passes only its fixed phase names; the
   values are microseconds. Nothing of the payload reaches the column.
4. **Outside the hash chain.** The chain and the audit key's MAC cover the same fields
   as before; `phases_us` is not hashed and not exported by `openmoat audit export`.
   The times are for finding a slow phase, not evidence of what was decided, and
   keeping them out leaves every chain, MAC and export format as it was. Someone who can
   write the database can change them without a chain break.
5. **`openmoat audit stats` reports them.** Its figures gain `phases`: per phase, the
   calls that went through it and the nearest-rank p50, p95, p99 and maximum, in
   microseconds in JSON and milliseconds in the text table ([DISTURBANCE.md](../DISTURBANCE.md)).
   `openmoat bench` prints one line with each phase's p50 and p95 for its ordinary work,
   so MoatBench's CI test shows the split on every run.
6. **One deserialize for the policy's version.** `Policy::parse` reads `version:` from
   its one full deserialize and probes the document for it only when that deserialize
   fails. The policy's `version` is a required number, so the probe would have read the
   same value; the errors, and their order, are unchanged.

## Consequences

- The next MoatBench runs on CI show which phase holds the growth. A CI budget check
  per phase comes after those numbers show which phase grew, as its own change; none is
  added now.
- A database at version 13 is refused by builds that know only version 12, as every
  schema step before it.
- Rows grow by a few dozen bytes per call.

## Amendment 2026-11-26: a finer split

The first split was too coarse to act on. An `openmoat bench` on a macOS machine
(main at `bfcad080`) gave, p50/p95 in µs: `stdin` 71/104, `lock` 13549/20054,
`context` 9123/14499, `compile` 44195/67997, `taint` 23375/36835, `cache` 524/965,
`record` 813/1396. In-process, `CompiledPolicy::compile` takes about 13 ms and a first
decision under 1 ms, so about 30 ms of `compile` was something else: that phase also
held the decision's path and program lookups on disk and the project settings check.
Likewise `lock` held the payload's parse and the placing, `context` the policy and the
secrets, and `taint` the audit log's open.

So each costly step is its own phase, in call order: `stdin`, `relay`, `parse` (the
payload, `Home::locate`), `lock` (`integrity::check`), `placed` (placing the call and
its MCP server's pin check), `context` (`eval_context`, the decoy keys), `policy`
(`effective_policy`), `secrets` (`secrets::known_with`, the required level), `snapshot`
(`Snapshot::load_in`), `compile` (`CompiledPolicy::compile` only), `decide`
(`decide_with`, the project settings check), `audit` (`open_audit`), `taint` (the
session's lookups and checks), `approval`, `cache`, `record`, `answer`. `secrets` comes
after `policy` because it reads the policy's secrets. Each move is one `hangs::enter`:
no I/O, and no decision changes.

Rows written with the first split keep their names; `openmoat audit stats` reports the
names a row has, the known ones in the guard's order and any other after them, so a
window holding both kinds counts the older rows' wider `lock`, `context`, `compile` and
`taint` under those names.
