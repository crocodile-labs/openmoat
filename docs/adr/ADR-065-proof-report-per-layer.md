# ADR-065: MoatBench proof report, one row per promise and layer

Status: accepted · Date: 2026-11-07 · Builds on ADR-004, ADR-018, ADR-019 and ADR-025; amends ADR-004's exit code 1

## Context

`openmoat bench` scores the policy's decisions: each scenario's steps go to `openmoat
guard` as a host's hook payload, and the bench checks the kernel's verdict and that the
host reads the reply as that verdict. It runs no command. So it cannot say what holds a
promise such as "an agent cannot read `~/.ssh/id_rsa`": the hook (which a project script
hides from), the OS sandbox (which only runs where `openmoat run` or a host sandbox
applies), or the proxy. A scorecard of verdicts reads as if all three were tested.

The OS layer is tested elsewhere: the differential suite runs hostile scripts under
`openmoat run` and each host's sandbox in CI (`docs/EVIDENCE.md`), and
`sandbox/differential.rs` holds every generated profile to the IR's reference semantics.
Neither is something a person runs on their own machine to see what holds there.

## Decision

1. `openmoat bench --report` prints a proof report: a fixed list of promises, each a
   plain question ("can an agent read ~/.ssh/id_rsa?"), mapped to existing scenarios and
   to probes, one row per layer that holds it:
   - **policy decision**: the kernel's verdict on the promise's scenarios, from the
     throwaway audit log, against each scenario's expectation;
   - **host hook**: each host's payload shape and its reading of the reply, against the
     kernel's verdict. The bench already computed both; they are now kept apart, so a
     right verdict the host misreads and a wrong verdict the host carries faithfully are
     different rows;
   - **OS sandbox**: the attack runs for real under `openmoat run -- /bin/sh -c …` in the
     throwaway home (Seatbelt on macOS, Landlock and seccomp on Linux), against fake
     secrets planted there. `openmoat run` is the runner, the same the differential
     suite's hostile scripts use: no second way of applying the sandbox;
   - **network boundary**: the proxy's own decision functions (`decide_host`,
     `decide_tainted`) on a host the policy allows, before and after a secret read. No
     connection is made.
2. A row is **PASS** only when every piece of evidence for it ran here and held, **FAIL**
   when any ran and did not hold, and **NOT TESTED HERE**, with the reason, otherwise.
   One fold (`proof/status.rs`) decides it; no code path turns a run that did not happen
   into a pass.
3. An OS row passes only when a control command (reading a file in the project) ran in
   the same sandbox, `openmoat run` reported the command sandboxed, the attack's own
   error names the file it went for with an OS refusal, and nothing of the secret or the
   write got through (a write is undone after the check). A sandbox that could not start
   (macOS before 13, Windows, a kernel without Landlock ABI 4, a nested sandbox, a home
   under `/tmp` on Linux) makes the row NOT TESTED HERE. The IR checker's reading of the
   attack is added to that reason as a detail; it never decides the status.
4. The hosts' own behaviour when the hook crashes or times out needs the real host: its
   row is always NOT TESTED HERE and quotes `HostSpec::on_hook_failure`. OpenMoat's side
   is exercised: a payload `openmoat guard` cannot read must reach each host as a deny.
5. The report names the OpenMoat version, the system and its version, the OS sandbox
   backend, each host and the version its program on the search path reports (when
   found), and for every row the scenario or probe ids that reproduce it. Text, `--format
   json` (`openmoat-bench-report-v1`) and `--format markdown`.
6. **Exit code 1 when any row is FAIL** (amending ADR-004, where 1 meant only that the
   program `openmoat run` or `openmoat mcp proxy` started failed). A NOT TESTED HERE row
   does not fail the command: CI asserts the rows it must exercise on each platform.
7. `--scratch-dir DIR` puts the throwaway home elsewhere than the system temp directory;
   a directory that is the person's home or one of its ancestors is refused. The
   commands under `openmoat run` get a temp directory beside the home, never above it.

## Consequences

- A person can see on their own machine which promises the OS holds there and which
  only the hook holds, and a reviewer gets a Markdown table to paste.
- The bench runs commands for the first time: the probes, under `openmoat run`, in the
  throwaway home, with the bench's cleared environment. Nothing else runs.
- On Linux the OS rows are NOT TESTED HERE unless `--scratch-dir` names a directory
  outside `/tmp`: Landlock cannot deny inside a tree it grants, and `/tmp` is a read root.
- The Standard tier (each host's own sandbox) is not in the report; the differential
  suite covers it in CI and `docs/EVIDENCE.md` records it.
- Promises and their scenarios are one table in `commands/bench/proof/promises.rs`; a
  unit test checks every id names a bundled scenario.

## Amendment 2026-11-08: the hook layer is OpenMoat's model of the host

The "host hook" rows come from OpenMoat's own golden payloads and its own reading of
each host's reply (`openmoat_hosts::bench`); no host program runs. Printed beside the
version of a program named like the host on the search path, a PASS there read as
"this host, at this version, was tested", which it was not: a mistake the model shares
with OpenMoat's parser passes on every machine.

- The layer is now **host model (golden payloads)** (`host-model` in JSON). The
  host's own handling of a failed hook, which the report never runs, is its own layer,
  **real host** (`real-host`), always NOT TESTED HERE.
- The report names no host version (point 5): each host is listed as
  `{"id": …, "evidence": "model"}`, "claude-code (model, not run)" in text. A version
  appears only with evidence from a run of the real agent, which the report does not
  gather; the weekly `latest agents` workflow is where real agents run.

## Amendment 2026-11-09: the OS rows run on Linux CI

On Ubuntu CI the OS rows were NOT TESTED HERE although the sandbox works. The bench's
temp directory lies under `--scratch-dir`, deep in the build tree, and the network
namespace's Unix socket was made there: a path longer than a socket address holds, so
`openmoat run` could not start and no attack was tried. The session's directory now
goes to `/tmp` when the temp directory would make the socket too long
(`commands/run/temp.rs`), which fixes `openmoat run` for anyone with a long `TMPDIR`.

- The end-to-end test requires PASS on CI's macOS and Linux jobs again; only the
  `stock linux` job may report NOT TESTED HERE, with its reason.
- Where the test accepts NOT TESTED HERE on Linux it prints a GitHub annotation with the
  promise and the reason, so the Checks API shows it without the job's log.
- `openmoat run` no longer grants `/tmp` (ADR-018, amendment of 2026-11-09), so a
  throwaway home there is no longer refused and `--scratch-dir` is not needed on Linux.
