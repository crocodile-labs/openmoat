#!/usr/bin/env python3
"""Time `moat guard` late in a long agent session (#559).

Usage: guard-session-latency.py <path to a release moat binary> [runs]

Every guard call reads its session from the audit log to work out the
session's taint (POLICY.md §4.1), so the work grows with the session. This
script grows one session to 100, 1,000 and 5,000 earlier calls, each a
distinct file read (the case the per-call cache in #542 cannot shorten), and
at each size times `runs` further calls end to end and as recorded in the
audit log's `latency_us`. The earlier calls go through `moat guard` like any
other, so the log is the real, hash-chained one.

The session cache (#570) folds only the calls since the last one, so a long
session should cost what a short one does. Like guard-latency.py, it warns
when p95 at 5,000 earlier calls is over the 15 ms budget and fails above
three times it: a regression back to folding the whole session fails here.

Each size times BATCHES batches of `runs` calls and reports the median of the
batches' p95. With 50 runs a batch's p95 is its third-slowest call, so three
slow process starts on a busy runner would fail one batch; they rarely land
in two of three, while a real regression slows every batch.

A last row times reads after another session that read untrusted content
wrote 500 files (file provenance, ADR-029): each read is one indexed lookup
per path, so it is held to the same budget.
"""

import json
import os
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

SIZES = (100, 1_000, 5_000)
BUDGET_MS = 15.0
FAIL_MS = 3 * BUDGET_MS
SESSION = "long-session"
PROVENANCE_FILES = 500
BATCHES = 3


def percentile(samples, p):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]


def batched_p95(batches):
    """The median of each batch's p95."""
    return statistics.median(percentile(batch, 95) for batch in batches)


def payload(project, command, session=SESSION, tool="Bash", tool_input=None):
    return json.dumps({
        "session_id": session,
        "cwd": project,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input if tool_input is not None else {"command": command},
        "tool_use_id": "t",
    }).encode()


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    moat = os.path.abspath(sys.argv[1])
    runs = int(sys.argv[2]) if len(sys.argv) == 3 else 50
    home = tempfile.mkdtemp(prefix="moat-session-latency-")
    project = os.path.join(home, "project")
    os.makedirs(os.path.join(project, ".git"))
    os.makedirs(os.path.join(home, ".claude"))
    # Only what the e2e tests pass (crates/openmoat-cli/tests/e2e/common.rs), so a
    # developer's MOAT_HOME or CLAUDE_CONFIG_DIR can never be touched.
    env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "USERPROFILE": home}
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    # Started in the throwaway HOME, not this checkout: `moat init` refuses a
    # binary inside the project of the current directory.
    subprocess.run([moat, "init"], env=env, cwd=home, check=True, capture_output=True)
    guard = [moat, "guard", "--host", "claude-code"]

    def call(command, **kw):
        started = time.perf_counter()
        out = subprocess.run(guard, input=payload(project, command, **kw), env=env, cwd=home,
                             capture_output=True)
        if out.returncode != 0:
            sys.exit(f"`{command}`: exit {out.returncode}\n{out.stderr.decode()}")
        return (time.perf_counter() - started) * 1000

    def timed(command_of):
        """BATCHES batches of `runs` calls: end to end and `latency_us`, in ms."""
        wall, own = [], []
        for batch in range(BATCHES):
            wall.append([call(command_of(batch * runs + i)) for i in range(runs)])
            with sqlite3.connect(os.path.join(home, ".moat", "audit.db")) as db:
                own.append([r[0] / 1000 for r in db.execute(
                    "SELECT latency_us FROM events ORDER BY id DESC LIMIT ?", (runs,))])
        return wall, own

    def report(label, title, wall, own):
        flat_wall = [ms for batch in wall for ms in batch]
        flat_own = [ms for batch in own for ms in batch]
        p95, own_p95 = batched_p95(wall), batched_p95(own)
        rows.append(f"| {label} | {statistics.median(flat_wall):.1f} / {p95:.1f} | "
                    f"{statistics.median(flat_own):.1f} / {own_p95:.1f} |")
        # a comma ends a workflow command property, so the title has none
        print(f"::notice title=guard latency {title}::"
              f"end to end median {statistics.median(flat_wall):.1f} ms, p95 {p95:.1f} ms; "
              f"latency_us median {statistics.median(flat_own):.1f} ms, p95 {own_p95:.1f} ms")
        return p95

    rows, earlier, worst = [], 0, 0.0
    for size in SIZES:
        while earlier < size:
            call(f"cat src/file{earlier}.rs")
            earlier += 1
        wall, own = timed(lambda _: "git status")
        p95 = report(f"{size:,}", f"after {size} earlier calls", wall, own)
        if size == SIZES[-1]:
            worst = p95

    # File provenance (ADR-029): another session reads untrusted content and
    # writes PROVENANCE_FILES files; every later read is looked up by path.
    fetch = {"url": "https://crates.io/crates/serde", "prompt": "summarise"}
    call("fetch", session="tainted-writer", tool="WebFetch", tool_input=fetch)
    for i in range(PROVENANCE_FILES):
        call(f"echo x > src/gen{i}.rs", session="tainted-writer")
    wall, own = timed(lambda i: f"cat src/gen{i % PROVENANCE_FILES}.rs")
    worst = max(worst, report(f"{SIZES[-1]:,} and {PROVENANCE_FILES} tainted files",
                              f"with {PROVENANCE_FILES} tainted files", wall, own))

    table = "\n".join([
        f"`moat guard` late in one session, {BATCHES} batches of {runs} runs per size, "
        "ms (median of all runs / median of the batches' p95)",
        "",
        "| earlier calls | end to end | latency_us |",
        "|---|---|---|",
        *rows,
    ])
    print(table)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write(table + "\n")
    if worst > FAIL_MS:
        print(f"::error::guard p95 at {SIZES[-1]} earlier calls is {worst:.1f} ms, "
              f"over {FAIL_MS:.0f} ms (3x the budget)")
        sys.exit(1)
    if worst > BUDGET_MS:
        print(f"::warning::guard p95 at {SIZES[-1]} earlier calls is {worst:.1f} ms, "
              f"over the {BUDGET_MS:.0f} ms budget")


if __name__ == "__main__":
    main()
