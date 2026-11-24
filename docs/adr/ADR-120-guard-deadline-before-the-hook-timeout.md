# ADR-120: The guard's deadline, before every hook time limit

Status: accepted · Date: 2026-11-23 · Builds on ADR-004 (exit codes), ADR-079
(hook-failure facts), ADR-109 §4 (fail-safe hook commands)

## Context

ADR-109 §4 made a missing or killed guard a block for Codex, Gemini CLI, Qwen Code and
Crush. It left timeouts open: Codex, GitHub Copilot CLI ("Command hook timeouts are
always fail-open, even for preToolUse"), Gemini CLI, Qwen Code, Crush, the Cline CLI
(120 s, not settable) and the Antigravity CLI (not documented) run a call whose hook
outlived its limit. Their `HookFailure::times_out` said `Runs`, and `docs/LIMITS.md`
listed "yes: times out" for each.

The guard already denied on its own after 30 s (`GUARD_BUDGET_S`) from a thread, and
`openmoat init` already writes a hook time limit far above that wherever the agent's
documentation has a key for it (600 s for Codex's `timeout`, Copilot CLI's
`timeoutSec`, Gemini CLI's `timeout` in milliseconds, Qwen Code's, Crush's and the
Antigravity CLI's `timeout` in seconds). Four things were still weak:

- The 30 s was one number for every host. Hermes Agent's plugin callback limit
  (`plugins.hook_callback_timeout`, 30 s by default) equals it, so the guard's deny
  and Hermes's own timeout raced; nothing tied a future short limit to the guard.
- The watchdog started after the state directory was pinned, which reads the file
  system; a hung file system there had no deadline.
- Its deny was in the default event's format, not the payload's (Copilot CLI's camel
  case, a settings-change veto).
- It wrote no audit row, so the log showed nothing for a call the agent saw denied.

## Decision

1. **A deadline per host, from its spec.** `HostSpec::guard_deadline_s` is
   `GUARD_BUDGET_S`, or the shortest limit the spec gives the host, less
   `DEADLINE_MARGIN_S` (5 s), where that is earlier: `HookFailure::timeout_s` and each
   hook entry's `timeout` as `openmoat init` writes them. The margin covers the 2 s the
   guard waits for its side-file line before it exits (a host reads the answer when
   the process ends), starting the process and a loaded machine's scheduling. Hermes
   Agent gets 25 s; every other host keeps 30 s. A contract test keeps every host's
   deadline between `MIN_DEADLINE_S` (10 s) and 30 s and below each of its limits by
   the margin.
2. **A watchdog that waits for nothing the decision holds.** `openmoat guard` starts
   it first, before it reads a file (`commands/guard/deadline.rs`); a guard that cannot
   start the thread denies (`kernel-error`). At the deadline it writes the deny and
   exits, whatever the main thread is doing: the audit database's lock, a slow file
   system, a long session to fold, an approver's wait. Every answer goes through one
   gate that holds its lock while it writes, so the decision's answer and the
   deadline's never interleave and only the first is written. The deny is in the form
   of the payload's event once it was read (and of the host that sent it), else the
   default event's; exit 2, or 0 where the spec's `deny_exit` says so.
3. **What it records.** The answer carries `kernel-error` (its words and page) and
   `hook-deadline`, with the phase the guard was in. The side file
   (`guard-hangs.log`) gets its line first; then, on the same thread and within the
   same 2 s, the audit log gets a row with rule `hook-deadline` alone (tool `guard`,
   counted with the hangs, not again as a `kernel-error`). The row is best effort: what
   is stuck may be the log.
4. **The facts.** A new `FailureOutcome::GuardDenies(Unanswered)` says the host would
   run the call (`Runs`) or does not say (`NotDocumented`), but the guard's deny comes
   first. Codex, Copilot CLI, Gemini CLI, Qwen Code, Crush, the Cline CLI (`Runs`) and
   the Antigravity CLI (`NotDocumented`) take it for `times_out`; it is not counted as
   failing open (`runs()` is false), and its words name the deadline and what remains.
   An approver's wait (ADR-093) ends before the host's deadline, and treats such a
   host as one that may run the call.
5. **Hook time limits.** No new setting: every agent above already gets 600 s from
   `openmoat init` where its documentation has the key, and the Cline CLI's 120 s has
   none. Hermes Agent's `plugins.hook_callback_timeout` stays the person's (ADR-109):
   it bounds every plugin, and Hermes blocks the call when it runs out.

Debug builds read `MOAT_TEST_GUARD_DEADLINE_MS` (the deadline) and
`MOAT_TEST_STALL_AT=<phase>` (stop for good on entering a phase), so the end-to-end
tests show the deny arrives from any stuck step in a second; release builds read
neither.

## Consequences

- A slow decision is a deny before any agent's timer fires; "times out" no longer
  fails open for those seven agents in `docs/LIMITS.md`, `doctor` or `audit stats`.
- What remains, under Codex, Copilot CLI, Gemini CLI, Qwen Code, Crush, the Cline CLI
  and the Antigravity CLI: a guard that cannot answer at all before the agent's limit,
  because its process was stopped (a debugger, `kill -STOP`, a machine starved for the
  whole limit) or killed together with the command the agent started, so no tail or
  plugin reports it. The agent's own timeout then runs the call. A guard the operating
  system kills alone (out of memory, `SIGKILL`) is a crash, which ADR-109's tail and
  each agent's `fails` fact cover. A person who lowers the agent's limit below the
  deadline reopens the case; `openmoat init` writes the limit back, and the lock pins
  the file.
- Hermes Agent's calls are denied after 25 s instead of 30 s.
- The audit log gains `hook-deadline` rows; older builds read them as any deny.
