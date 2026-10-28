#!/usr/bin/env python3
"""The README quick start as the clean-install workflow runs it.

The README marks each code block of its quick start with an HTML comment on the
line before it:

    <!-- ci:quickstart run ... -->     a bash block whose lines are commands
    <!-- ci:quickstart output ... -->  the output the README shows for the
                                       command before it

    readme-quickstart.py commands <README.md>   each command, one per line
    readme-quickstart.py output <README.md>     the output block, as written
    readme-quickstart.py compare <expected> <actual> <home>
                                                the actual output is the README's, once
                                                the home directory reads /Users/you

A command is a line of a `run` block as written (a trailing `# comment` is
left in: the shell ignores it). Blank lines are skipped. It fails when the
README has no `run` block or not exactly one `output` block, so removing a
marker cannot quietly turn the check into one that runs nothing.
"""

import os
import re
import sys
from pathlib import Path

MARKER = re.compile(r"^\s*<!--\s*ci:quickstart\s+(run|output)\b.*-->\s*$")
FENCE = re.compile(r"^\s{0,3}(```|~~~)")


def blocks(text):
    """(kind, lines) for each marked fenced block, in order."""
    lines = text.splitlines()
    found = []
    i = 0
    while i < len(lines):
        marker = MARKER.match(lines[i])
        i += 1
        if not marker:
            continue
        if i >= len(lines) or not FENCE.match(lines[i]):
            sys.exit(f"readme-quickstart: line {i}: a ci:quickstart marker must be followed by a fenced block")
        fence = FENCE.match(lines[i]).group(1)
        i += 1
        body = []
        while i < len(lines) and not lines[i].lstrip().startswith(fence):
            body.append(lines[i])
            i += 1
        if i >= len(lines):
            sys.exit("readme-quickstart: an unclosed fenced block after a ci:quickstart marker")
        i += 1
        found.append((marker.group(1), body))
    return found


def compare(expected_path, actual_path, home):
    """The README shows the home as /Users/you; the run's own home (as given
    and resolved) reads that way before the comparison, line endings aside."""
    expected = Path(expected_path).read_text(encoding="utf-8").splitlines()
    actual = Path(actual_path).read_text(encoding="utf-8")
    for spelling in sorted({home, os.path.realpath(home)}, key=len, reverse=True):
        actual = actual.replace(spelling, "/Users/you")
    actual_lines = [line.rstrip() for line in actual.splitlines()]
    if [line.rstrip() for line in expected] != actual_lines:
        print("FAIL  the output is not the one the README shows")
        print("README:")
        print("\n".join(expected))
        print("actual (home as /Users/you):")
        print("\n".join(actual_lines))
        return 1
    print("ok    the output is the one the README shows")
    return 0


def main(argv):
    if len(argv) == 4 and argv[0] == "compare":
        return compare(*argv[1:])
    if len(argv) != 2 or argv[0] not in ("commands", "output"):
        print(__doc__, file=sys.stderr)
        return 64
    marked = blocks(Path(argv[1]).read_text(encoding="utf-8"))
    runs = [line for kind, body in marked if kind == "run" for line in body if line.strip()]
    outputs = [body for kind, body in marked if kind == "output"]
    if not runs:
        sys.exit("readme-quickstart: no ci:quickstart run block in the README")
    if len(outputs) != 1:
        sys.exit(f"readme-quickstart: {len(outputs)} ci:quickstart output blocks; there must be one")
    for line in runs if argv[0] == "commands" else outputs[0]:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
