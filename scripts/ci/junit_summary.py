#!/usr/bin/env python3
"""Why a test job failed, without reading its log: nextest's JUnit report as
the job summary and as annotations.

Usage:
  junit_summary.py <junit.xml>            the report of one job
  junit_summary.py balance <junit.xml>... the time each part took, warning
                                          when they differ by more than 25%

For one report it writes to `$GITHUB_STEP_SUMMARY` (or standard output): the
failed tests, each with its first panic line (or the reason nextest gave,
such as a timeout); the flaky ones, which failed and then passed on their
retry; and the ten slowest. Each failed test is also an `error` annotation
titled `test failed`, each flaky one a `warning` titled `flaky test`, both
`<binary id> <test name>` first: what ci-retry.yml's main watch reads to open
an issue for a test that keeps failing on `main` (scripts/ci/main_watch.py).
It always exits 0: the test run's own exit status decides the job.

Reads a file nextest wrote in this job (`target/nextest/<profile>/`), not
input from elsewhere.
"""

import os
import sys
import xml.etree.ElementTree as ET

FAILED_TITLE = "test failed"
FLAKY_TITLE = "flaky test"
SLOWEST = 10
BALANCE_LIMIT = 0.25


def text_of(element, tag):
    found = element.find(tag)
    return (found.text or "") if found is not None else ""


def first_panic(*texts):
    """`file:line:col: message` of the first panic in `texts`, or None."""
    for text in texts:
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "panicked at " not in line:
                continue
            where = line.split("panicked at ", 1)[1].strip().rstrip(":")
            message = next((l.strip() for l in lines[i + 1:] if l.strip()), "")
            return f"{where}: {message}" if message else where
    return None


def cases(root):
    """[(binary id, test, seconds, outcome, reason)] with outcome one of
    passed, failed, flaky."""
    out = []
    for case in root.iter("testcase"):
        binary = case.get("classname", "")
        name = case.get("name", "")
        seconds = float(case.get("time") or 0)
        failure = case.find("failure")
        if failure is None:
            failure = case.find("error")
        flaky = case.findall("flakyFailure") + case.findall("flakyError")
        if failure is not None:
            reruns = case.findall("rerunFailure") + case.findall("rerunError")
            texts = [text_of(case, "system-err"), text_of(case, "system-out"), failure.text or ""]
            for rerun in reruns + flaky:
                texts += [text_of(rerun, "system-err"), text_of(rerun, "system-out")]
            reason = (first_panic(*texts) or failure.get("message")
                      or failure.get("type") or "no panic message; see the log")
            out.append((binary, name, seconds, "failed", reason))
        elif flaky:
            first = flaky[0]
            reason = (first_panic(text_of(first, "system-err"), text_of(first, "system-out"),
                                  first.text or "")
                      or first.get("message") or first.get("type") or "")
            out.append((binary, name, seconds, "flaky", reason))
        else:
            out.append((binary, name, seconds, "passed", ""))
    return out


def escape(text):
    """A value for a workflow command (`::error ...::<value>`)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def cell(text):
    return text.replace("|", "\\|").replace("\n", " ")


def report(all_cases):
    """(markdown summary, annotation lines)."""
    failed = [c for c in all_cases if c[3] == "failed"]
    flaky = [c for c in all_cases if c[3] == "flaky"]
    slowest = sorted(all_cases, key=lambda c: c[2], reverse=True)[:SLOWEST]
    total = sum(c[2] for c in all_cases)
    lines = [f"### Tests: {len(all_cases)} run, {len(failed)} failed, {len(flaky)} flaky "
             f"({total / 60:.1f} test-minutes)", ""]
    notes = []
    if failed:
        lines += ["**Failed**", "", "| test | why |", "|---|---|"]
        for binary, name, _s, _o, reason in failed:
            lines.append(f"| `{binary}` `{cell(name)}` | {cell(reason)} |")
            notes.append(f"::error title={FAILED_TITLE}::{escape(f'{binary} {name}: {reason}')}")
        lines.append("")
    if flaky:
        lines += ["**Flaky** (failed, then passed on the retry; not hidden)", "",
                  "| test | first failure |", "|---|---|"]
        for binary, name, _s, _o, reason in flaky:
            lines.append(f"| `{binary}` `{cell(name)}` | {cell(reason)} |")
            notes.append(f"::warning title={FLAKY_TITLE}::"
                         f"{escape(f'{binary} {name}: passed only on retry; {reason}')}")
        lines.append("")
    if slowest:
        lines += [f"**Slowest {len(slowest)}**", "", "| test | seconds |", "|---|---|"]
        lines += [f"| `{b}` `{cell(n)}` | {s:.1f} |" for b, n, s, _o, _r in slowest]
        lines.append("")
    return "\n".join(lines) + "\n", notes


def balance(totals):
    """A warning when the slowest part took over 25% longer than the
    quickest; None otherwise. `totals`: {part: test-seconds}."""
    if len(totals) < 2:
        return None
    quick = min(totals.values())
    slow = max(totals.values())
    if quick <= 0 or (slow - quick) / quick <= BALANCE_LIMIT:
        return None
    shown = ", ".join(f"{part} {seconds / 60:.1f} min" for part, seconds in sorted(totals.items()))
    return (f"::warning title=partition balance::the test parts differ by "
            f"{(slow - quick) / quick:.0%} (over {BALANCE_LIMIT:.0%}): {shown}")


def write_summary(markdown):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(markdown)
    else:
        sys.stdout.write(markdown)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        sys.exit(__doc__)
    try:
        if argv[0] == "balance":
            totals = {p: sum(c[2] for c in cases(ET.parse(p).getroot())) for p in argv[1:]}
            warning = balance(totals)
            if warning:
                print(warning)
            return 0
        markdown, notes = report(cases(ET.parse(argv[0]).getroot()))
    except (OSError, ET.ParseError) as e:
        print(f"::warning title=junit summary::cannot read the test report ({e})")
        return 0
    write_summary(markdown)
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
