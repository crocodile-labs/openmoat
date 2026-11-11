# ADR-080: The Isolated tier by default on Linux, the guard's latency budget, and a long-session bench

Status: accepted · Date: 2026-11-10 · Amends ADR-018 and ADR-077

## Context

On Linux `openmoat run` started the Lightweight tier unless `--isolate` was given. That
tier is Landlock, which only grants: inside the project it grants whole, a command the
agent starts can read and write `.env`, create `.envrc` and write `.moat` and
`.git/hooks` ([EVIDENCE.md](../EVIDENCE.md)). `openmoat run` said so on every start and
`doctor` warned, but the safer tier needed a flag a person had to know about, and
`require.run: full-boundary` (ADR-077) did not ask for it.

## Decision 1: `openmoat run` on Linux starts the Isolated tier where bubblewrap works

1. **The tier is chosen before anything starts** (`commands/run/isolation.rs`), from
   what the platform offers, the flags and whether a policy requires the full boundary.
   The platform's answer is one probe of the system's bubblewrap (never one on `PATH`),
   made once per process and used again to build the sandbox.

   | Linux | bubblewrap works | bubblewrap missing or blocked |
   |---|---|---|
   | no flag | Isolated | Lightweight: says why on every start, row `run-isolation-unavailable` |
   | `--isolate` | Isolated | refused, as before |
   | `--no-isolate` | Lightweight, row `run-no-isolate` | the same |
   | `require.run: full-boundary` | Isolated; `--no-isolate` refused | refused |

   `--isolate` and `--no-isolate` together are a usage error.
2. **A run weaker than the default is on record before the agent starts.** The row is
   written in the run's own audit session (host `moat-run`, tool `isolation`, verdict
   `allow`, with the rule above and the reason). A row that cannot be written stops the
   run, as a call that cannot be recorded is not allowed. The tool name is no host id, so
   the run's taint lookup, which reads link rows in the same session by their tool
   (ADR-027), passes it by.
3. **On Linux the full boundary is the Isolated tier.** ADR-077 left the Lightweight tier
   allowed under `require.run: full-boundary`. Now the requirement refuses a system where
   the Isolated tier cannot start, with the policy that asks and why, and refuses
   `--no-isolate`: a flag cannot lower what a policy requires, as `--netns` cannot.
   `status` and `doctor` report that gap (`run_boundary.gaps`).
4. **When the default cannot be built** for another reason than bubblewrap (a grant that
   would show the state directory, say), the run stops with that reason and the line
   "`openmoat run --no-isolate` starts the Lightweight tier instead"; it does not fall
   back on its own, since that reason is about this run, not the system. Under the
   requirement the line is left out.
5. **`openmoat doctor`** has one row for the tier: on Linux "starts the Isolated tier",
   or a warning that it cannot and starts the Lightweight tier, or under the requirement
   that it refuses. The old warning that plain `openmoat run` leaves the project open is
   gone; the run itself still prints it when it starts the Lightweight tier.
6. **macOS and Windows do not change.** macOS has no Isolated tier yet (ADR-023):
   `--no-isolate` is accepted there, changes nothing and writes no row; `--isolate` is
   refused as before.
7. **What uses `openmoat run` follows the default.** `openmoat mcp proxy --sandbox` starts
   a server in the Isolated tier on Linux where bubblewrap works. `openmoat bench --report`
   keeps measuring the Lightweight tier (`--no-isolate`): the Isolated tier applies the
   same Landlock rules and seccomp filter inside bubblewrap's narrower view, so what holds
   in the Lightweight tier holds there.

### Migration

A Linux user with bubblewrap installed and unprivileged user namespaces allowed now gets
the Isolated tier from a plain `openmoat run`. The agent then sees only the project, the
read roots, its executable, the `--write` paths and an empty temp directory. An agent
whose runtime is elsewhere in the home (a `node` under `~/.nvm`) can fail to start until
that directory is in `sandbox.read_roots`; `openmoat run --no-isolate` restores the old
behaviour for one run, on record. Without bubblewrap nothing changes but one more line on
start and the audit row. Not tried with every agent: only CI's `/bin/sh` payloads and the
stand-in agents of the e2e suite run in the Isolated tier.

## Limits of decision 1

- The probe says bubblewrap can create its namespaces; it does not try the run's own
  mounts. A run that fails later stops with the reason (point 4).
- The rows say which tier a run started; they cannot say that nothing changed the system
  during the run.
- `doctor` reads this system now; bubblewrap removed afterwards is found by the run.

## Decision 2: a 20 ms p95 budget for the hook decision, and a latency check that measures the guard, not the runner

### What the check measures today

`scripts/ci/guard-latency.py` starts one `openmoat guard` process per call, as a host
does, and reads two times: end to end (spawn to exit) and `latency_us`, the guard's own
time from the start of `decide_and_respond` to before its audit row is written (the
session cache write, which commits before that point, is inside it).
`scripts/ci/guard-session-latency.py` does the same late in a 5,000-call session. The
budget was 15 ms; a run with one binary failed above 45 ms of the guard's own p95.

What CI measured on `main` (job annotations, the guard's own time, median / p95 in ms):

| Commit | Guard path changed since the row above | `ubuntu-latest` | `macos-15` | macOS result |
|---|---|---|---|---|
| ac648940 | — | 14.0 / 14.3 at 5,000 calls | p95 47.7 allow, 54.3 deny (per call) | failed |
| 48390091 | yes | 16.1 / 16.5 at 5,000 | 36.7 / 66.2 at 100 calls, 25.9 / 36.7 at 5,000 | passed |
| 8fc05242 | yes | 16.3 / 17.3 at 5,000 | 16.8 / 18.5 at 100 calls, 21.8 / 26.8 at 5,000 | passed |
| 483d740e | no | 16.3 / 16.8 at 5,000 | p95 42.0 allow, 62.0 deny (per call) | failed |
| f7d9ce06 | no | 19.7 / 20.0 at 5,000 | p95 62.2 allow, 53.2 deny (per call) | failed |

A failed run stops before the session step, so its macOS row is the per-call step's.

### Root cause of the intermittent macOS failures

**The runner, measured against a fixed limit.** 483d740e and f7d9ce06 change nothing on
the guard's path after 8fc05242 (`git diff --stat` over `commands/guard*`, `integrity/`,
`taint/`, `openmoat-core/src`, `openmoat-audit/src` and the default policy is empty), and
the same guard measured a p95 of its own time of about 27 ms on one `macos-15` runner and
53 to 62 ms on the next two. Linux varies too, 14 to 20 ms median for nearly the same
code, but around a lower base. The guard's own time is CPU-bound work done afresh in
every process: reading and checking the lock, parsing the policy, compiling it and
deciding. On this development Mac (x86-64, macOS 12, loaded by parallel builds) the
default policy alone took at best 17.4 ms to parse, 16.5 ms to compile and 7.8 ms for the
first decision, with medians two to five times that under load, so the time scales with
whatever share of a CPU the process gets. A three-core shared macOS runner gives a varying
share, so a fixed limit on one binary measures the runner. The other causes the brief
names were checked against the code: the timer is `Instant` (monotonic, sub-microsecond on
both systems); the binary's digest is cached by size, time and inode, so no call hashes it
(`integrity/binary.rs`); the audit log is WAL with `synchronous=NORMAL`, so a commit does
not wait for the disk except at a checkpoint, one call in hundreds; the per-call script
discards ten warm-up calls, and the cold first runs are not the slow ones (the failing rows
are whole batches). Pull requests did not see this, since they already timed the base
commit in turn on the same runner (`latency_ab.py`).

**Fix in the measurement.** CI builds the commit before (`HEAD^1`) on every event, pushes
to `main` and the weekly run included, and times the two in turn on the same runner, as it
did for pull requests; a change fails when its own p95 is over 1.25 times the base's and
5 ms over it, or above 150 ms whatever the base measured. The fixed 45 ms limit stays only
for a run with one binary (by hand, or when the base does not build, which warns). A slow
regression spread over many commits, each under 25 %, is not caught by the comparison; the
150 ms ceiling and the long-session bench (decision 3) are what remain for it.

### The budget

The p95 budget of the guard's own decision is **20 ms on `ubuntu-latest`**. A row above it
warns. CI measured 14 to 22 ms there, so 20 ms holds on most runs and warns on slow ones;
it is a target the code meets today, not a margin. **On `macos-15` 20 ms is wrong**: the
same binary's median there is 17 to 37 ms, so its p95 cannot be held to 20 ms by this code
on that runner. The proposal is 45 ms on macOS runners (`MACOS_BUDGET_MS`), which the p95
met on two of the five commits and missed by up to 17 ms on the others, the size of the
runner's own spread. The budget warns; the comparison fails. Both scripts report the
median, p95 and p99.

Parsing and compiling the policy on every call is likely the larger part of the guard's own
time (34 ms at best on the development Mac, an older and loaded machine; the split was not
measured on a runner, where a whole call takes 15 to 20 ms on Linux). Keeping a
compiled policy between calls would need its own integrity binding to the lock and is not
part of this decision.
