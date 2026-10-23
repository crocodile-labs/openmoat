#!/usr/bin/env python3
"""Fold the fragments in `changelog.d/` into `## [Unreleased]` of CHANGELOG.md.

Run at release time (CONTRIBUTING.md "Releasing"), before the Unreleased entries
move under the new version heading. Each fragment's entries go at the end of its
heading in `## [Unreleased]`, in pull request order; a heading the section does
not have yet is added in the order releases use (Security, Added, Changed,
Removed, Fixed). Entries already in CHANGELOG.md stay where they are. The
fragments are then deleted, so commit CHANGELOG.md and the deletions together.

It checks every fragment first (`scripts/changelog-check.py`) and changes
nothing when one is malformed.

    python3 scripts/changelog-assemble.py            # write CHANGELOG.md, delete fragments
    python3 scripts/changelog-assemble.py --dry-run  # print the new CHANGELOG.md only
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
UNRELEASED = "## [Unreleased]"


def load_check():
    """The checker, loaded by path: the scripts directory is not a package."""
    path = Path(__file__).resolve().with_name("changelog-check.py")
    spec = importlib.util.spec_from_file_location("changelog_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def split_unreleased(lines):
    """Return (start, end) of the Unreleased section: its heading line and the
    line of the next `## [` heading (or the end of the file)."""
    try:
        start = lines.index(UNRELEASED)
    except ValueError:
        sys.exit(f"CHANGELOG.md has no `{UNRELEASED}` line")
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")),
        len(lines),
    )
    return start, end


def parse_block(block):
    """Split the lines under `## [Unreleased]` into the text before the first
    `###` heading and an ordered list of (heading, lines)."""
    preamble, groups = [], []
    for line in block:
        if line.startswith("### "):
            groups.append((line[4:].strip(), []))
        elif groups:
            groups[-1][1].append(line)
        else:
            preamble.append(line)
    return preamble, groups


def trim(lines):
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)
    return lines


def merge(groups, additions, order):
    """Append each section's new entries to its group, adding missing groups
    at their place in `order`."""
    for section in order:
        entries = additions.get(section)
        if not entries:
            continue
        existing = next((g for g in groups if g[0] == section), None)
        if existing:
            trim(existing[1]).extend(entries)
            continue
        rank = order.index(section)
        at = next(
            (i for i, (name, _) in enumerate(groups)
             if name in order and order.index(name) > rank),
            len(groups),
        )
        groups.insert(at, (section, list(entries)))
    return groups


def render(preamble, groups):
    out = [UNRELEASED, ""]
    preamble = trim(list(preamble))
    if preamble:
        out += preamble + [""]
    for name, body in groups:
        out += [f"### {name}"] + trim(list(body)) + [""]
    return out


def main(argv):
    dry_run = "--dry-run" in argv
    check = load_check()
    paths = check.fragment_paths()
    additions, failed = {}, False
    for path in paths:
        section, entries, problems = check.parse(path)
        for problem in problems:
            failed = True
            print(f"changelog.d/{path.name}: {problem}", file=sys.stderr)
        if not problems:
            additions.setdefault(section, []).extend(entries)
    if failed:
        print("nothing changed: fix the fragments above first", file=sys.stderr)
        return 1
    if not paths:
        print("no changelog fragments to fold")
        return 0

    text = CHANGELOG.read_text(encoding="utf-8")
    lines = text.splitlines()
    start, end = split_unreleased(lines)
    preamble, groups = parse_block(lines[start + 1:end])
    groups = merge(groups, additions, list(check.SECTIONS))
    new = lines[:start] + render(preamble, groups) + lines[end:]
    output = "\n".join(new) + ("\n" if text.endswith("\n") else "")

    if dry_run:
        sys.stdout.write(output)
        return 0
    CHANGELOG.write_text(output, encoding="utf-8")
    for path in paths:
        path.unlink()
    print(f"folded {len(paths)} fragments into {UNRELEASED}; commit CHANGELOG.md and changelog.d/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
