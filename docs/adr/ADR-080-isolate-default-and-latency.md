# ADR-080: The Isolated tier by default on Linux, and the guard's latency budget

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
