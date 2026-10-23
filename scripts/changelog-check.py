#!/usr/bin/env python3
"""Fail when a changelog fragment in `changelog.d/` is not well formed.

A fragment is one user-visible change (CONTRIBUTING.md "Changelog"):

- its name is `<pr>-<slug>.md`: the pull request number, then lowercase words
  joined by `-` (`712-pi-dialog-timeout.md`);
- its first line is the heading it goes under, one of `### Security`,
  `### Added`, `### Changed`, `### Removed`, `### Fixed`;
- every other non-blank line is one entry, `- …`, that links its pull request:
  `([#712](https://github.com/crocodile-labs/openmoat/pull/712))`.

`changelog.d/README.md` is the directory's own page and is not a fragment.
`scripts/changelog-assemble.py` folds the fragments into `CHANGELOG.md`.

    python3 scripts/changelog-check.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAGMENTS = ROOT / "changelog.d"
# The order the headings take in a release section of CHANGELOG.md.
SECTIONS = ("Security", "Added", "Changed", "Removed", "Fixed")
NAME = re.compile(r"^([1-9][0-9]*)-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
HEADING = re.compile(r"^### (\w+)\s*$")
PR_URL = "https://github.com/crocodile-labs/openmoat/pull/"


def fragment_paths():
    """Every fragment, in pull request order."""
    if not FRAGMENTS.is_dir():
        return []
    paths = [p for p in FRAGMENTS.iterdir() if p.is_file() and p.name != "README.md"]
    return sorted(paths, key=lambda p: (pr_of(p.name) or 0, p.name))


def pr_of(name):
    match = NAME.match(name)
    return int(match.group(1)) if match else None


def parse(path):
    """Return (section, entries, problems) for one fragment."""
    problems = []
    pr = pr_of(path.name)
    if pr is None:
        problems.append("name is not `<pr>-<slug>.md` (lowercase slug, words joined by `-`)")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return None, [], [f"cannot be read as UTF-8: {error}"]
    lines = text.splitlines()
    heading = HEADING.match(lines[0]) if lines else None
    section = heading.group(1) if heading else None
    if section not in SECTIONS:
        problems.append(
            "first line is not one of " + ", ".join(f"`### {s}`" for s in SECTIONS)
        )
    entries = []
    for number, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        if not line.startswith("- "):
            problems.append(f"line {number} is not an entry starting with `- `")
            continue
        if line.rstrip() != line:
            problems.append(f"line {number} ends with spaces")
        if pr is not None and f"[#{pr}]({PR_URL}{pr})" not in line:
            problems.append(f"line {number} does not link [#{pr}]({PR_URL}{pr})")
        if not line.rstrip().endswith((")", ").")):
            problems.append(f"line {number} does not end with its pull request link")
        entries.append(line.rstrip())
    if not entries:
        problems.append("has no entry")
    return section, entries, problems


def main():
    failed = False
    paths = fragment_paths()
    for path in paths:
        _, _, problems = parse(path)
        for problem in problems:
            failed = True
            print(f"changelog.d/{path.name}: {problem}", file=sys.stderr)
    if failed:
        return 1
    print(f"changelog fragments ok ({len(paths)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
