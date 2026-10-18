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

It reports and warns; it never fails. Above 50 ms at 5,000 calls, keeping
each call's exposure in its audit row, so the fold reads it instead of
classifying the call again, is worth doing (#559).
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
WARN_MS = 50.0
SESSION = "long-session"


def percentile(samples, p):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]


def payload(project, command):
    return json.dumps({
        "session_id": SESSION,
        "cwd": project,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
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

    def call(command):
        started = time.perf_counter()
        out = subprocess.run(guard, input=payload(project, command), env=env, cwd=home,
                             capture_output=True)
        if out.returncode != 0:
            sys.exit(f"`{command}`: exit {out.returncode}\n{out.stderr.decode()}")
        return (time.perf_counter() - started) * 1000

    rows, earlier, worst = [], 0, 0.0
    for size in SIZES:
        while earlier < size:
            call(f"cat src/file{earlier}.rs")
            earlier += 1
        wall = [call("git status") for _ in range(runs)]
        with sqlite3.connect(os.path.join(home, ".moat", "audit.db")) as db:
            own = [r[0] / 1000 for r in db.execute(
                "SELECT latency_us FROM events ORDER BY id DESC LIMIT ?", (runs,))]
        p95 = percentile(wall, 95)
        if size == SIZES[-1]:
            worst = p95
        rows.append(f"| {size:,} | {statistics.median(wall):.1f} / {p95:.1f} | "
                    f"{statistics.median(own):.1f} / {percentile(own, 95):.1f} |")
        # a comma ends a workflow command property, so the title has none
        print(f"::notice title=guard latency after {size} earlier calls::"
              f"end to end median {statistics.median(wall):.1f} ms, p95 {p95:.1f} ms; "
              f"latency_us median {statistics.median(own):.1f} ms")

    table = "\n".join([
        f"`moat guard` late in one session, {runs} runs per size, ms (median / p95)",
        "",
        "| earlier calls | end to end | latency_us |",
        "|---|---|---|",
        *rows,
    ])
    print(table)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write(table + "\n")
    if worst > WARN_MS:
        print(f"::warning::guard p95 at {SIZES[-1]:,} earlier calls is {worst:.1f} ms, "
              f"over {WARN_MS:.0f} ms")


if __name__ == "__main__":
    main()
