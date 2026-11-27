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

## Decision 3: a long-session bench in the weekly job

`scripts/ci/guard-long-session.py` runs 3,000 hook decisions in one Claude Code session,
each recorded in the audit log: reads and writes of distinct files, `git status` and a
denied exfiltration in turn (a wrong decision stops the bench, since its timings would
mean nothing). It reports per window of 500 calls:

1. **Hook processes**, one `openmoat guard` per call as a host runs it: end to end and the
   guard's own time (median / p95), each process's peak resident memory from the kernel
   (`wait4`), and the audit log's size.
2. **A directory change.** The same session then goes on for one window from the project's
   `src/`, as an agent's `cd` does. Its first call and the window are reported on their
   own and not judged: the session's taint is folded per working directory, so the first
   call from a new one may fold the whole session once. What it measures is how much that
   costs late in a long session.
3. **A long-lived `openmoat run`.** A driver started as the run's program sends the same
   calls through `openmoat guard` inside the sandbox, which relays each to the run
   (ADR-028); the run process lives for the whole session and its resident memory is
   sampled from outside (`ps`). It runs `--no-isolate`, so the process measured is the
   run itself. Where `openmoat run` cannot start it says so; the weekly Linux job passes
   `--require-run`, which makes that an error.

It fails only on a clear trend: the last window's own p95 above 1.5 times the first's and
5 ms over it, a hook process's median peak memory grown by more than 8 MiB, or the run
process grown by more than 32 MiB after its first window. It runs weekly on
`ubuntu-latest` and `macos-15` (not a required check). Only that job can show the numbers;
nothing of it ran on the development machine, whose `openmoat init` refuses to run under an
agent.

## Amendment 2026-11-26: fewer globs built per guard process

`openmoat bench` on 0.28's `main` (f2c45a0c) put the guard's own time in loading the policy
(`context`, p50 13.7 ms), compiling and deciding (`compile`, 49.3 ms) and the session checks
(`taint`, 23.2 ms). A sampling profile of one process's work on the default policy (105 KB)
showed most of it in globset, building globs nobody needed:

- **Loading.** Three quarters of `Policy::parse` was the lint building every pattern's glob
  (globset's parse and its regex text) to learn that it parses; the engine then builds them
  again for its context. Deserializing was the other quarter.
- **The first decision.** Nine tenths of a first `decide` was building regexes. A glob's
  literal start already refused most paths, but over 150 default patterns begin with `**/` and
  most shell programs are written `{gh,*/gh}`, whose start is empty: a write in the project
  built a regex for every one of them, a `git status` one for every program glob.

Two changes, neither changing a decision, an error, or what the guard trusts:

1. The lint builds a glob only when it may fail to parse. globset's parser fails only on a
   class, an alternation or an escape (`[`, `{`, `}`, `\`); a test parses every string up to
   five characters long over the other glob characters, and a text the policy repeats is
   built once per lint. The error for the first pattern that does not compile is the one
   compiling gives.
2. Before building a glob's regex, a candidate is checked against the glob's literal end
   (`**/.env` needs `.env` at the end, `{gh,*/gh}` needs `gh`, `dir/**` needs `dir`'s end
   inside), as the literal start already was. A candidate with a non-ASCII character or a
   backslash goes to the regex; a test checks every default-policy glob, spelled for a
   context in both case modes, and every shell word, against its regex on its own matches,
   near misses and their case-flipped forms.

In-process, per fresh round on the default policy (40 rounds of 7 actions, this development
Mac, under load; p50 / p95 in ms):

| Step | Before | Lint (1) | Lint and tail (1, 2) |
|---|---|---|---|
| `Policy::parse` | 13.2 / 23.3 | 6.2 / 10.9 | 6.5 / 10.4 |
| `CompiledPolicy::compile` | 13.2 / 24.5 | 12.6 / 20.9 | 12.9 / 20.0 |
| first `decide`, write in the project | 19.6 / 39.8 | 17.7 / 30.9 | 0.27 / 0.43 |
| first `decide`, `git status` | 6.0 / 9.9 | 5.4 / 8.1 | 0.58 / 0.96 |
| first `decide`, read in the project | 2.2 / 5.8 | 1.6 / 3.3 | 0.42 / 0.71 |
| fold of one earlier call and the session checks | 0.85 / 1.78 | 0.84 / 1.54 | 0.25 / 0.43 |
| parse, compile and first decide | 36.6 / 66.3 | 26.8 / 47.1 | 20.2 / 29.3 |

What was measured and left alone:

- **Compiling** is now the larger part (globset building each spelled glob's regex text,
  most of it). Deferring that build to first use would need an infallible constructor,
  which globset does not have, so a deferred build would add an error branch inside the
  matcher with no safe answer for an allow list. Sharing each repeated shell word's glob
  across a compile (559 globbed words, 309 texts) measured within the run-to-run spread
  and was not kept.
- **Deserializing** the YAML is about a quarter of loading. The parser stays (ADR-024).
- **The audit log** (measured on a fresh log in a temporary directory): `open_read_only`
  1.3 ms p50 (one `user_version` read), the first session lookup 0.47 ms (SQLite reading the
  schema), the next 0.04 ms; the session fold's digest of the effective policy (JSON and
  SHA-256) 0.35 ms. Each is done once per process and none repeats work.
- **Classifying a call again** in each session check (`with_injected`, `with_taint`,
  `with_staging`, `with_trifecta`, the provenance step) costs tens of microseconds each once
  the globs are built.

## Amendment 2026-11-26 (second): the session checks' redaction and globs built once

`openmoat bench` on `main` (650860fa) put the guard's own time, by the phases of ADR-130,
in `compile` (p50 42.8 ms), `taint` (22.7 ms) and `lock` (13.5 ms) of a 94 ms call. These
two changes are to the first two; neither changes a decision, an error or what is recorded.

### `taint`: the first lookup built every redaction pattern

The suspicion was the audit log: lookups that scan or decode more rows as the log grows.
A scratch harness filled a real audit store (through `openmoat guard` in a throwaway home,
then copies of its rows) to 1,000, 10,000 and 50,000 rows in other sessions, and 5,000 in
the call's own, and timed each step of the phase. `EXPLAIN QUERY PLAN` of every query on
the guard's path is an index search: the session page (`events_session`), the fold cache
and its other digests (the `session_folds` key, ≤ 16 rows sorted), the fingerprints,
provenance, the files a session wrote and the MCP pieces (each table's own index), the
newest id (the row id). The log's size was not the cause:

| Rows in the log (in the call's session) | `taint` before | `taint` after |
|---|---|---|
| 88 (8) | 21.6 / 28.9 | 7.9 / 14.7 |
| 1,088 (8) | 22.7 / 34.7 | 8.0 / 13.9 |
| 10,088 (8) | 25.8 / 32.2 | 7.6 / 13.1 |
| 50,088 (8) | 22.0 / 28.7 | 8.8 / 18.9 |
| 55,088 (5,008) | 26.0 / 36.6 | 7.9 / 14.8 |

(p50 / p95 in ms of the guard's own `taint` phase over 40 calls, builds of both commits
with the same optimisation and no link-time optimisation, this development Mac under
load. The session's fold reads on from its cached row, so its own size does not show.)

Timing inside the phase put 14.9 ms of its 23.6 ms p50 in the first step,
`taint::injected::checked`, whose only work for a session without fingerprints is one
index probe. Its cost was the probe's arguments: every lookup by session passes the id
through `KnownSecrets::redact`, as `Store::record` stored it, and the first redaction of a
process compiled all 38 of the redaction's regexes (12.4 ms in a fresh process; the
`(?i)`, Unicode `\b` and `\s` patterns 0.3 to 1.5 ms each). Every later step and the
`record` phase then found them built.

**Change.** Each pattern names texts one of which every match holds (`Rule::needs`: the
credential words, the program names, `bearer`, `://`, the token prefixes), and is built the
first time a text holds one of them in some letter case (`redact/gate.rs`). A text that
holds none could not match and keeps what it is. A text with a non-ASCII character goes to
every pattern, since case folding equates `ſ` with `s` and the Kelvin sign with `k`. A
session id, a path or `git status` now builds none; a text that names a credential word
builds the patterns that need it, once per process. The needles are proved, not trusted:
a test reads each pattern as `regex` parses it (`regex-syntax`, a test-only dependency
already in the build) and derives texts every match must hold (a literal or a one-letter
class, runs of them in a concatenation, every branch of an alternation, a repetition of at
least one); each must hold one of the rule's needles. A second test runs every pattern
ungated over a corpus of the texts each pattern masks, near misses and ordinary calls, each
also upper-cased, lower-cased and with `s` and `k` replaced by their non-ASCII foldings,
and gets what the gated redaction gives. One difference remains where the patterns do not
compile, which a test rules out: before, every text was then replaced whole; now a text
that needs a broken pattern is.

### `compile`: the same globs built again

A single parse, compile and decide of the default policy in a fresh process, spawned 40
times, costs what the same round costs warm (p50 compile 15 and 14 ms), and a second
compile inside one `openmoat guard` process costs what its first does (31 and 32 ms). So
the first compile pays no one-time cost of a cold process: no table built once, no first
use. What it pays is length: with a 9-character home the compile took 14 to 18 ms, with
the 120-character home of a throwaway directory (as `openmoat bench`'s) 27 to 47 ms. A
sampling profile put 69 % of `CompiledPolicy::compile` in globset's `GlobBuilder::build`,
45 % in its regex text (an allocation per character of the glob, most of the profile's top
frames being the allocator), and showed the same texts built again: the default policy's
1,211 glob patterns spell 1,000 distinct texts, 415 of them `dir/**` with their `dir` built
beside them, and the shell patterns build 559 word globs from 309 texts.

**Change.** One compile keeps each glob it built by its text and options
(`pattern/built.rs`): path globs per case mode, shell words apart. A pattern that names a
text already built shares it, and its regex once a candidate needs it; a text that does not
build is not kept, so each pattern that names it reports its own error where it always did.
Each pattern's globs and errors are those of compiling it alone (`pattern/built.rs`'s test);
the conformance, never-widen and obfuscation tests decide with the shared ones.

Fresh process, 40 runs each in turn, default policy (p50 / p95 in ms):

| Home directory | `compile` before | `compile` after | `openmoat guard`'s `compile` phase before | after |
|---|---|---|---|---|
| `/Users/me` | 22.7 / 28.6 | 17.2 / 21.3 | | |
| 120 characters, a throwaway home | 38.4 / 48.2 | 30.8 / 39.1 | 31.5 / 36.0, 36.7 / 47.8 | 25.9 / 32.5, 27.8 / 35.6 |

(The guard's columns are two rounds of 40 calls each, its own phase times.) Over the same
rounds the guard's phases together went from 79 to 59 ms at the median.

### Measured and left alone

- **The rest of `compile`** is globset's work per character of each distinct glob. Matching
  the literal home prefix outside globset would change the regex text the never-widen proof
  reads (`widen/nfa.rs`); deferring the build stays out for the reason the first amendment
  gives.
- **The rest of `taint`**, about 8 ms: the fold of the calls since the cached row and its
  digest of the effective policy (about 2 ms), the provenance lookup (0.2 ms) and, after the
  session checks, the push check, the hook ledger's review and the decoy checks (about 5 ms
  together, not split further).
- **Dropping the compiled policy** took about a tenth of a warm round in the profile; it
  happens after the decision.
