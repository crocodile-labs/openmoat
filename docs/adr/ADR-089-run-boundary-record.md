# ADR-089: Every `openmoat run` records its boundary and checks it after the start

Status: accepted · Date: 2026-11-13 · Builds on ADR-018 (OS sandbox tiers), ADR-077
(`require.run: full-boundary`), ADR-080 (the Isolated tier by default on Linux),
ADR-082 (the Landlock ABI ladder) · Supersedes ADR-082's `run-landlock-abi` row

## Context

What `openmoat run` actually started with depended on the machine and was spread over
several places. A Linux run without a usable bubblewrap falls back to the Lightweight
tier and restricts the network by port only; each fallback printed a notice, and only
the tier fallback wrote an audit row (`run-isolation-unavailable`, `run-no-isolate`).
A run at full strength wrote no row at all, so the absence of a row was the only sign
of a full boundary. The kernel's Landlock ABI went to the audit log from a probe taken
before the agent started (`run-landlock-abi`), not from the call that applied the
agent's rules. Nothing confirmed after the start that the agent really ran with
`no_new_privs` and the seccomp filter: the code applied them and assumed it worked.

A script, a team's audit export or a person comparing two machines could not tell a
verified boundary from a partial one without reading the source.

## Decision

1. **One record, one shape.** `openmoat_core::boundary::EffectiveBoundary` is pure data
   (serde, no I/O): the OS, the tier asked for (`default`, `isolated`, `lightweight`)
   and the one that started (`standard`, `lightweight`, `isolated`), every downgrade
   (the tier, the network, and the project's top opened by the person's own
   `sandbox.project_top: writable` of ADR-090, which applies only to the Lightweight
   tier without a namespace) with why and whether the person chose it, the network mode
   (`namespace`, `port_only`, Seatbelt's `profile`) and the proxy's port, the Landlock
   ABI and what `restrict_self` reported, whether tool commands receive the relay token
   (ADR-075), and for each restriction four facts: `available` (the system has it),
   `configured` (the run asks for it), `applied` (the kernel or tool reported it in
   force) and `tested` (a check after the start confirmed it). `null` means unknown,
   never yes. The JSON form has a `version` (1); fields are only added.
2. **One row on every run.** Once the agent started, `openmoat run` writes one row in
   its audit session: tool `boundary`, rule `run-boundary`, the record as JSON in its
   reason, redacted like every row. A run with a gap is a `deny` row. The tier rows of
   ADR-080 stay, written before the start; the `run-landlock-abi` row is gone, its ABI
   now in this row and taken from `restrict_self`.
3. **`openmoat run --print-boundary [--format json] -- <agent>`** makes the run's own
   choices (flags, the policy's `require.run`, bubblewrap, the kernel) and prints the
   planned record, starting nothing and writing nothing. The refusals a run makes
   before it builds its sandbox are made here too, with the same words and exit 64: no
   sandbox on this system (macOS before 13), a kernel below Landlock ABI 4, the tier or
   a port-only network under `require.run: full-boundary`, a port-only network under
   `--netns=require`. Refusals that depend on the generated grants (a grant that holds
   the state directory, a `--write` path holding what `kernel-self` protects without a
   namespace) are found only by a start. `--verbose` prints the same record before the
   agent starts.
4. **The check after the start (Linux).** The thread that starts the agent reads its
   own `Seccomp_filters` count, applies the Landlock rules and the seccomp filters,
   keeps `restrict_self`'s `RestrictionStatus`, starts the agent and reads
   `/proc/<pid>/status`. `NoNewPrivs: 1` must be there (whoever set it, it is in
   force); `Seccomp: 2` must be there with `Seccomp_filters` equal to the thread's own
   count plus the filters this run applied, so a filter a container runtime or service
   manager set does not pass for the run's; and the ruleset must be `FullyEnforced` or
   `PartiallyEnforced` (the ABI 6 and 9 steps are best effort; ABI 4's file and TCP
   rights are hard requirements). A best-effort step past the kernel's ABI is
   recorded as not applied; under a partly enforced ruleset whether a step the kernel
   has applied is unknown and recorded so. A child that already exited is
   still a zombie, so its status is readable until it is waited for. Anything missing
   or unknown **fails closed**: the agent and every process it started are stopped
   first, then the row records the gap, and the run says what was missing and exits
   64. An error writing the row stops them too. The agent stays in the terminal's
   process group (a group of its own would take it out of the foreground), so the
   processes it started are found in `/proc` by parent, each stopped with `SIGSTOP`
   as found so none forks past the walk, and then all are killed. Once an agent has
   started, a restriction the tier promises counts as missing unless the check
   confirmed it: `tested` for the seccomp filters and `no_new_privs`, `applied` for
   Landlock's required rights and bubblewrap's namespace and view.
5. **Under bubblewrap** (the Isolated tier and the Lightweight tier's network
   namespace) the agent's parent is `openmoat isolated` inside, so the check runs
   there and is reported out. The run binds a Unix socket in its private (0700)
   session directory before bubblewrap starts and gives `openmoat isolated` a random
   nonce in its environment. `openmoat isolated` connects before it starts the agent
   (so its connection is first) and removes the nonce from the agent's environment;
   the run accepts only a report that carries the nonce. The agent cannot read the
   nonce from `openmoat isolated`'s `/proc` entries or take its socket: Landlock keeps
   a sandboxed process from inspecting a process outside its domain. The run checks the
   report's fields itself rather than trusting the gaps it names. The connection stays
   open for a one-byte reply: go once the row is written and nothing is missing;
   anything else, a closed connection or no reply within 60 seconds makes
   `openmoat isolated` stop the agent and its processes. That matters in the
   Lightweight tier's namespace, which has no PID namespace: stopping bubblewrap
   alone would leave the agent running, reparented. On any failure the run also stops
   bubblewrap's whole process tree itself. Inside, a gap stops the agent as in 4;
   outside, a report that never comes while bubblewrap runs (60 seconds) or that cannot
   be read is recorded as the failure and stops the tree. When bubblewrap ends before
   `openmoat isolated` connected, no agent started; the row has no `launch` part.
6. **macOS** records the Seatbelt profile as available and configured. `sandbox-exec`
   reports nothing back and there is no `/proc`, so it is neither applied nor tested
   and the row has no `launch` part.
7. **No ambiguous downgrade.** A downgrade is in the record (`downgrades`), in the
   row, and in the notice the run prints before the agent starts, as before.

## Consequences

- Every run that starts an agent leaves a machine-readable statement of its boundary
  in the audit log, so `openmoat show`, exports and live delivery carry it; a script
  checks `tier`, `downgrades` and each restriction's `tested` instead of the absence
  of a row.
- The check is a check of the kernel's own report, not of what the policy means:
  Landlock's rules cannot be read back, so its restrictions are `applied` (from
  `restrict_self`) and never `tested`; which paths they hold is shown by the
  end-to-end suite's access tests. The check runs right after the agent's `exec`, so
  a gap stops an agent that has started, not one that has not.
- Starting the agent is now spawn, check, wait instead of one `status()` call; the
  exit status and the terminal are unchanged. The bubblewrap path adds one socket
  and one short line per run.
- `openmoat isolated` takes `--report <socket>`; it is an internal command, started
  only by `openmoat run`.
- Only CI's Linux jobs run the Linux check and its report from inside bubblewrap; the
  stock-Linux job runs the downgrade path (no bubblewrap) and asserts both downgrades
  in the row and in `--print-boundary`.
