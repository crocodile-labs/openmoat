# What OpenMoat costs your work

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know, from your own audit log, how often OpenMoat stopped or slowed your agents, or how the project measures the same thing.

**On this page:** [Get your numbers](#get-your-numbers-openmoat-audit-stats) · [What each number means](#what-each-number-means) · [What the log cannot tell](#what-the-log-cannot-tell) · [The numbers CI measures](#the-numbers-ci-measures)

A check that runs before every tool call is only useful if people leave it on. These
numbers show how much it gets in the way: how long each decision takes, how often a
call is held or denied, and what happens when the check itself fails. They come from
records OpenMoat already keeps; nothing new is collected and nothing is sent anywhere.

## Get your numbers: `openmoat audit stats`

```bash
openmoat audit stats                      # the last 7 days, per agent and over all
openmoat audit stats --since 30d          # a longer window (all, today, 12h, 2w, YYYY-MM-DD)
openmoat audit stats --since 2026-11-01 --until 2026-11-08
openmoat audit stats --host <agent>       # one agent
openmoat audit stats --format json        # the same figures for a script
```

It opens the audit log (`~/.moat/audit.db`) read-only and reads the guard's hangs file
(`~/.moat/guard-hangs.log`); it opens no connection and writes nothing. The log holds
what it always held, redacted as it was recorded, and the command prints only counts,
times and each agent's documented facts, never a command or a path. Run it from your
own terminal: an agent's sandbox may block reading the log. It exits 0, or 64 on a
usage error such as a window it cannot parse.

The text output is one table row per agent with calls in the window, a row over all
agents when there are several, a table of the time per guard phase over the calls in
the table (when their rows have phase times), then a line per agent with its held
calls, the guard's own failures and what the agent does when the hook fails. `--format json` prints a
document with `"format": "openmoat-stats-v1"`, the `window`, `overall`, `agents` (one
object per agent, with `host`, `name` and the figures below) and `other_rows`.

## What each number means

| Number | JSON field | What it counts |
|---|---|---|
| calls | `calls` | Tool calls the guard decided and recorded for the agent in the window. Rows that are not an agent's tool call (the proxy's connections, `openmoat run`'s links, a remote approval's own row, live delivery's rows) are left out and counted in `other_rows`. |
| p50, p95, p99 | `latency.p50_us`, `p95_us`, `p99_us`, `max_us` | The time `openmoat guard` spent on a call, from its start to the moment it recorded the decision (`latency_us` in every row), nearest-rank percentiles. The text shows milliseconds; JSON gives microseconds. The agent's own time to start the hook process is not in it. No calls, no percentiles: the field is `null`, not `0`. |
| time per guard phase | `phases`: one object per phase with `phase`, `calls`, `p50_us`, `p95_us`, `p99_us`, `max_us` | The same decision time split by the steps `openmoat guard` takes, in that order: `stdin` (reading the tool call), `relay`, `lock` (checking the policy lock), `context` (loading the policy and its context), `compile` (compiling the policy and deciding), `taint` (reading the session's earlier calls), `approval` (waiting for an approver on another device), `cache` (writing the session cache), `record` (writing the audit log) and `answer`. Each row records the microseconds the call spent in each step it went through (`phases_us`, beside `latency_us`, [ADR-130](adr/ADR-130-guard-phase-times.md)); `calls` is how many calls went through that step. `record` counts only up to the moment the row is written, since the row cannot hold the time of its own write, and `answer` comes after the write, so it is never in a row. Rows an older build wrote have no phase times and are left out of this table: the list is empty when no row has them. Only durations and the step's fixed name are recorded, nothing from the call. |
| allow, defer, review, deny | `verdicts` | Calls per verdict. `defer` leaves the call to the agent's own permission prompt, exactly as without OpenMoat ([POLICY.md](POLICY.md)). |
| per 100 calls | `per_100_calls` | The same per 100 calls, to two decimals. `review` per 100 calls is the number of prompts OpenMoat added; `deny` per 100 calls is how often it stopped a call outright. |
| approved | `approved` | Calls that ran because you approved them: `openmoat allow` for the session (`approved-session`) or an approval from another device (`approved-remote`). |
| denies / reviews later allowed | `denies_later_allowed`, `reviews_later_allowed` | Denies and reviews whose same call (same agent, same session, same recorded action) the log shows allowed later in the window, for example after you allowed a site or changed the policy. The nearest sign in the log of a deny or review you did not want. |
| kernel-error | `kernel_errors` | Calls the guard denied because it could not check or record them (rule `kernel-error`): it fails closed ([ARCHITECTURE.md](ARCHITECTURE.md)). |
| no decision in time | `guard_timeouts` | Calls the guard denied itself because no decision came within its 30 s budget, from the hangs file: the audit log cannot hold them, since what hung may be the log itself. `openmoat doctor` reports the same file. |
| if the hook fails / times out | `hook_failure.fails`, `times_out`, `timeout_s` | What the agent does with the call when the hook cannot start, crashes or does not answer within its time limit. These come from each agent's spec and the vendor documentation behind it, not from your log; the full table with sources is in [LIMITS.md](LIMITS.md#if-the-hook-fails), and [PROTECTION.md](PROTECTION.md) has it per agent. |

## What the log cannot tell

- **A deny you later approved.** A deny is absolute: no approval turns it into an
  allow. What the log can show is the same call allowed later in the same session
  (`denies_later_allowed`), which happens only after the policy changed. A deny you
  disagreed with but did not act on leaves no trace.
- **What you answered at the agent's own prompt.** For a `review` or a `defer` the
  agent asks you itself; OpenMoat does not see the answer, so a review you approved
  there is not in `approved`. Only approvals given through OpenMoat are.
- **Time outside the guard.** The agent starts a process for each hook; that start is
  not measured. A call the agent never sent to the hook (a hook turned off, an agent
  that fails open on a crash) leaves no row at all.

## The numbers CI measures

Published numbers come from runs anyone can repeat, not from estimates.

`openmoat bench` sends every MoatBench scenario as each agent's real hook payload to
`openmoat guard` in a throwaway home ([MOATBENCH.md](MOATBENCH.md)). Against OpenMoat
its report now ends with `ordinary work`: the figures above, computed by the same code
as `openmoat audit stats`, over the steps of the `benign` and `workflows` scenarios
(everyday development, where the only reviews are the ones the policy intends, such as
an install or a push), read back from the throwaway audit log. `--format json` gives
them as `ordinary_work`, in the shape `openmoat audit stats --format json` uses. The
text adds one line with each guard phase's p50 and p95 in microseconds, for example
`by guard phase (p50/p95 µs): stdin 80/120, lock 900/2400, …`, and the JSON has the
same as `ordinary_work.overall.phases`, so every CI run shows which phase the decision
time went to.

CI's end-to-end test `moatbench_mini_openmoat_meets_every_expectation`
(`crates/openmoat-cli/tests/e2e/moatbench.rs`) runs `openmoat bench --format json` on
Linux, macOS and Windows, prints the report, and fails unless ordinary work had no
deny and no `kernel-error`, and every step has a recorded decision time. The decision
times in that log are the CI runner's; they are measured, not tuned, and vary with the
runner's load. To get the same figures on your machine, run `openmoat bench`; to get
them for your own work, run `openmoat audit stats`.

What these numbers do not show: the scenarios were written by OpenMoat's authors, so
zero denies on them shows the policy and the scenarios agree, not that no ordinary
call anywhere is ever denied. Your own log is the better measure of your own work.
