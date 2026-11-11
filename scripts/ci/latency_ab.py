"""What guard-latency.py and guard-session-latency.py share: the throwaway
install each binary is timed in, and the rule that passes or fails a run.

The budget (ADR-080): the guard's own decision (`latency_us`, from its start
to before the audit write) has a p95 of at most BUDGET_MS, 20 ms on Linux.
On macOS CI runners the same binary measures 17 to 37 ms median, so there
the budget is 45 ms (MACOS_BUDGET_MS); above the budget a row warns.

Two modes, chosen by `--base`:

- Against a base binary (`--base <binary>`; CI passes it on every event,
  pull requests, pushes to `main` and the weekly run): the change's binary
  ("head") and the binary of the commit before it ("base") are timed on the
  same runner, one call each in turn, the first of the pair alternating
  (A B, B A, A B, ...), so a busy or slow runner, or one that slows down
  during the run, slows both alike. Head fails when its own p95 is clearly
  worse than base's: above base x RATIO and above base + MARGIN_MS. Above
  CEILING_MS it fails whatever base measured, the backstop for a guard so
  slow that nothing about the runner explains it.

- One binary (a person timing a build by hand, or CI when the base did not
  build): the guard's own p95 fails above FAIL_MS. This is the mode pushes to
  `main` used until ADR-080, and the cause of its intermittent macOS
  failures: the same guard code (8fc05242, 483d740e and f7d9ce06 change
  nothing on its path) measured an own p95 of about 27 ms on one macos-15
  runner and 53 to 62 ms on others, while ubuntu-latest stayed at 17 to
  22 ms. A fixed limit on one shared runner measures the runner; timing the
  commit before on the same runner, in turn, cancels it.

The end to end p95 only warns in either mode: on a shared runner it is
mostly process start.

A call that writes no audit row (`PostToolUse`) has no own time: it fails
above CEILING_MS end to end in either mode and otherwise only warns
(judge_end_to_end).
"""

import os
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

LINUX_BUDGET_MS = 20.0
MACOS_BUDGET_MS = 45.0
BUDGET_MS = MACOS_BUDGET_MS if sys.platform == "darwin" else LINUX_BUDGET_MS
# Fixed numbers, not multiples of the budget: they did not move when it did.
FAIL_MS = 45.0
RATIO = 1.25
MARGIN_MS = 5.0
CEILING_MS = 150.0


def percentile(samples, p):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]


def batched_p95(batches):
    """The median of each batch's p95: a few slow process starts push up one
    batch, rarely two of three, while a real regression slows every batch."""
    return statistics.median(percentile(batch, 95) for batch in batches)


def arguments(usage, default_runs):
    """`[--base <binary>] <binary> [runs]` -> (binary, runs, base or None)."""
    args, base = sys.argv[1:], None
    if args[:1] == ["--base"]:
        if len(args) < 2:
            sys.exit(usage)
        base, args = args[1], args[2:]
    if len(args) not in (1, 2):
        sys.exit(usage)
    return args[0], int(args[1]) if len(args) == 2 else default_runs, base


class Guard:
    """One `openmoat` binary installed in its own throwaway HOME."""

    def __init__(self, name, binary, prefix, project_dirs=(), parent=None):
        self.name = name
        self.binary = os.path.abspath(binary)
        # Set when the base binary answers a call differently from head (a
        # case added with the feature it times): its numbers are not comparable.
        self.mismatch = None
        # In the system's temp directory unless `parent` says where.
        self.home = tempfile.mkdtemp(prefix=prefix, dir=parent)
        self.project = os.path.join(self.home, "project")
        os.makedirs(os.path.join(self.project, ".git"))
        for folder in project_dirs:
            os.makedirs(os.path.join(self.project, folder))
        os.makedirs(os.path.join(self.home, ".claude"))
        # Only what the e2e tests pass (crates/openmoat-cli/tests/e2e/common.rs),
        # so a developer's MOAT_HOME or CLAUDE_CONFIG_DIR can never be touched.
        self.env = {"PATH": os.environ.get("PATH", ""), "HOME": self.home,
                    "USERPROFILE": self.home}
        if "SYSTEMROOT" in os.environ:
            self.env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        # Started in the throwaway HOME, not this checkout: `openmoat init`
        # refuses a binary inside the project of the current directory.
        subprocess.run([self.binary, "init"], env=self.env, cwd=self.home, check=True,
                       capture_output=True)

    def guard(self, payload, expected, what):
        """One `openmoat guard` call, end to end in ms. Head must answer with
        `expected`; base answering otherwise is noted, not fatal."""
        started = time.perf_counter()
        out = subprocess.run([self.binary, "guard", "--host", "claude-code"], input=payload,
                             env=self.env, cwd=self.home, capture_output=True)
        elapsed = (time.perf_counter() - started) * 1000
        if out.returncode != expected:
            problem = f"{what}: exit {out.returncode}, expected {expected}\n{out.stderr.decode()}"
            if self.name != "base":
                sys.exit(f"{self.name}: {problem}")
            self.mismatch = self.mismatch or problem
        return elapsed

    def recorded(self, runs):
        """The guard's own time of the last `runs` calls, in ms."""
        with sqlite3.connect(os.path.join(self.home, ".moat", "audit.db")) as db:
            return [r[0] / 1000 for r in db.execute(
                "SELECT latency_us FROM events ORDER BY id DESC LIMIT ?", (runs,))]


def install(binary, base, prefix, project_dirs=()):
    """Head, and base when there is one, each in its own HOME."""
    guards = [Guard("head", binary, prefix, project_dirs)]
    if base:
        guards.append(Guard("base", base, prefix, project_dirs))
    return guards


def in_turn(guards, i):
    """The order of the i-th call's pair: A B, then B A, so neither binary is
    always the one that runs right after the other."""
    return guards if i % 2 == 0 else guards[::-1]


def judge(what, head, base=None):
    """(errors, warnings) for one measured row. `head` and `base` are
    (end to end p95, own p95) in ms; `base` is None in the one-binary mode."""
    wall, own = head
    over_budget = over(what, own)
    if base is None:
        if own > FAIL_MS:
            return [f"guard's own p95 {what} is {own:.1f} ms, over {FAIL_MS:.0f} ms "
                     f"(one binary, no base to compare with; end to end {wall:.1f} ms)"], []
        if wall > FAIL_MS:
            return [], [f"guard end to end p95 {what} is {wall:.1f} ms, over {FAIL_MS:.0f} ms, "
                        f"but its own p95 is {own:.1f} ms: a slow runner, not a slower guard",
                        *over_budget]
        return [], over_budget
    base_wall, base_own = base
    errors, warnings = [], list(over_budget)
    if own > CEILING_MS:
        errors.append(f"guard's own p95 {what} is {own:.1f} ms, over the {CEILING_MS:.0f} ms "
                      f"ceiling (base {base_own:.1f} ms)")
    elif regressed(own, base_own):
        errors.append(f"guard's own p95 {what} is {own:.1f} ms against {base_own:.1f} ms for "
                      f"the commit before, measured in turn on this runner: over "
                      f"{RATIO}x and {MARGIN_MS:.0f} ms slower")
    if regressed(wall, base_wall):
        warnings.append(f"guard end to end p95 {what} is {wall:.1f} ms against {base_wall:.1f} "
                        f"ms for the commit before (process start or binary size?)")
    return errors, warnings


def over(what, own):
    """The warning for an own p95 over this runner's budget, if it is."""
    if own > BUDGET_MS:
        return [f"guard's own p95 {what} is {own:.1f} ms, over the {BUDGET_MS:.0f} ms budget "
                f"(ADR-080)"]
    return []


def judge_end_to_end(what, wall, base_wall=None):
    """(errors, warnings) for a call that writes no audit row (`PostToolUse`,
    ADR-057), whose only time is end to end. It fails above CEILING_MS, the
    guard's p95 budget an after-call hook is held to (ADR-063 §2), in either
    mode; above FAIL_MS, or clearly slower than base, it only warns, since on
    a shared runner end to end is mostly process start."""
    if wall > CEILING_MS:
        return [f"guard end to end p95 {what} is {wall:.1f} ms, over the {CEILING_MS:.0f} ms "
                f"budget of an after-call hook"], []
    if base_wall is not None and regressed(wall, base_wall):
        return [], [f"guard end to end p95 {what} is {wall:.1f} ms against {base_wall:.1f} ms "
                    f"for the commit before (no audit row, so no own time to compare)"]
    if base_wall is None and wall > FAIL_MS:
        return [], [f"guard end to end p95 {what} is {wall:.1f} ms, over {FAIL_MS:.0f} ms "
                    f"(no audit row, so no own time to tell a slow runner apart)"]
    return [], []


def regressed(head_ms, base_ms):
    """Clearly worse: by a quarter and by 5 ms, so neither a fast runner's
    1 ms jitter nor a slow runner's proportional noise counts."""
    return head_ms > base_ms * RATIO and head_ms > base_ms + MARGIN_MS


def finish(table, verdicts, guards):
    """Print and publish the table, then the verdicts; exit 1 on an error."""
    print(table)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write(table + "\n")
    base = next((g for g in guards if g.name == "base"), None)
    errors = [e for errs, _ in verdicts for e in errs]
    warnings = [w for _, warns in verdicts for w in warns]
    if base is not None and base.mismatch:
        print(f"::warning::the base binary answered differently, so it cannot be compared: "
              f"{base.mismatch.splitlines()[0]}")
    for warning in warnings:
        print(f"::warning::{warning}")
    for error in errors:
        print(f"::error::{error}")
    if errors:
        sys.exit(1)
