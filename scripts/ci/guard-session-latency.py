#!/usr/bin/env python3
"""Time `openmoat guard` late in a long agent session (#559).

Usage: guard-session-latency.py [--base <base moat binary>] <release moat binary> [runs]

Every guard call reads its session from the audit log to work out the
session's taint (POLICY.md §4.1), so the work grows with the session. This
script grows one session to 100, 1,000 and 5,000 earlier calls, each a
distinct file read (the case the per-call cache in #542 cannot shorten), and
at each size times `runs` further calls end to end and as recorded in the
audit log's `latency_us`. The earlier calls go through `openmoat guard` like any
other, so the log is the real, hash-chained one.

The session cache (#570) folds only the calls since the last one, so a long
session should cost what a short one does. The rows held to the rule in
latency_ab.py are the last size and the two rows after it: with `--base`,
which CI always passes, the binary of the commit before grows its own session
call for call beside this one, and the change fails only when its own p95 is
clearly worse; with one binary, the guard's own p95 fails above 45 ms. Every
row reports the median, p95 and p99 against the budget of ADR-080. A regression back to folding the whole session fails either way, while
a loaded runner's slow process starts do not.

Each size times BATCHES batches of `runs` calls and reports the median of the
batches' p95. With 50 runs a batch's p95 is its third-slowest call, so three
slow process starts on a busy runner would fail one batch; they rarely land
in two of three, while a real regression slows every batch.

A last row times reads after another session that read untrusted content
wrote 500 files (file provenance, ADR-029): each read is one indexed lookup
per path, so it is held to the same budget. Another times running scripts the
session wrote itself (ADR-039), the one case that reads the agent's sandbox
state.
"""

import json
import statistics

import latency_ab

SIZES = (100, 1_000, 5_000)
SESSION = "long-session"
PROVENANCE_FILES = 500
SCRIPTS = 100
BATCHES = 3


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
    binary, runs, base = latency_ab.arguments(__doc__, default_runs=50)
    guards = latency_ab.install(binary, base, "moat-session-latency-", project_dirs=["tools"])

    def call(g, command, **kw):
        return g.guard(payload(g.project, command, **kw), 0, f"`{command}`")

    def each(command, **kw):
        """The same call on every binary, so their sessions grow alike."""
        for g in guards:
            call(g, command, **kw)

    def timed(command_of):
        """BATCHES batches of `runs` calls per binary, taken in turn: end to
        end and `latency_us`, in ms."""
        wall = {g.name: [] for g in guards}
        own = {g.name: [] for g in guards}
        for batch in range(BATCHES):
            times = {g.name: [] for g in guards}
            for i in range(runs):
                for g in latency_ab.in_turn(guards, i):
                    times[g.name].append(call(g, command_of(batch * runs + i)))
            for g in guards:
                wall[g.name].append(times[g.name])
                own[g.name].append(g.recorded(runs))
        return wall, own

    def report(label, title, wall, own):
        """One table row per binary; (end to end p95, own p95) per binary."""
        stats = {}
        for g in guards:
            flat_wall = [ms for batch in wall[g.name] for ms in batch]
            flat_own = [ms for batch in own[g.name] for ms in batch]
            p95, own_p95 = latency_ab.batched_p95(wall[g.name]), latency_ab.batched_p95(own[g.name])
            p99 = latency_ab.percentile(flat_wall, 99)
            own_p99 = latency_ab.percentile(flat_own, 99)
            stats[g.name] = (p95, own_p95)
            rows.append(f"| {label} | {g.name} | {statistics.median(flat_wall):.1f} / {p95:.1f} / "
                        f"{p99:.1f} | {statistics.median(flat_own):.1f} / {own_p95:.1f} / "
                        f"{own_p99:.1f} |")
            # a comma ends a workflow command property, so the title has none
            print(f"::notice title=guard latency {title} ({g.name})::"
                  f"end to end median {statistics.median(flat_wall):.1f} ms, p95 {p95:.1f} ms, "
                  f"p99 {p99:.1f} ms; latency_us median {statistics.median(flat_own):.1f} ms, "
                  f"p95 {own_p95:.1f} ms, p99 {own_p99:.1f} ms")
        return stats

    rows, measured, earlier = [], [], 0
    for size in SIZES:
        while earlier < size:
            each(f"cat src/file{earlier}.rs")
            earlier += 1
        wall, own = timed(lambda _: "git status")
        stats = report(f"{size:,}", f"after {size} earlier calls", wall, own)
        if size == SIZES[-1]:
            measured.append((f"at {size} earlier calls", stats))

    # File provenance (ADR-029): another session reads untrusted content and
    # writes PROVENANCE_FILES files; every later read is looked up by path.
    fetch = {"url": "https://crates.io/crates/serde", "prompt": "summarise"}
    each("fetch", session="tainted-writer", tool="WebFetch", tool_input=fetch)
    for i in range(PROVENANCE_FILES):
        each(f"echo x > src/gen{i}.rs", session="tainted-writer")
    wall, own = timed(lambda i: f"cat src/gen{i % PROVENANCE_FILES}.rs")
    measured.append((f"with {PROVENANCE_FILES} tainted files",
                     report(f"{SIZES[-1]:,} and {PROVENANCE_FILES} tainted files",
                            f"with {PROVENANCE_FILES} tainted files", wall, own)))

    # Code the session wrote (ADR-039): the long session writes SCRIPTS files and
    # runs them, so each call looks the files up and, where Claude Code's sandbox
    # applies, reads whether it is in place: the slowest path of that check.
    for i in range(SCRIPTS):
        each(f"echo 'print(1)' > tools/s{i}.py")
    wall, own = timed(lambda i: f"python3 tools/s{i % SCRIPTS}.py")
    measured.append((f"running {SCRIPTS} scripts the session wrote",
                     report(f"{SIZES[-1]:,} and {SCRIPTS} scripts it wrote, run",
                            f"running {SCRIPTS} scripts the session wrote", wall, own)))

    table = "\n".join([
        f"`openmoat guard` late in one session, {BATCHES} batches of {runs} runs per size, "
        "ms (median of all runs / median of the batches' p95 / p99 of all runs)",
        "",
        "| earlier calls | binary | end to end | latency_us |",
        "|---|---|---|---|",
        *rows,
    ])
    compare = base is not None and not guards[-1].mismatch
    verdicts = [latency_ab.judge(what, stats["head"], stats["base"] if compare else None)
                for what, stats in measured]
    latency_ab.finish(table, verdicts, guards)


if __name__ == "__main__":
    main()
