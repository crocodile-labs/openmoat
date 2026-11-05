#!/usr/bin/env python3
"""Print `code=false` when a pull request changes documentation only, else `code=true`.

Usage: changes.py <base commit> <head commit>

CI's first job (`changes` in .github/workflows/ci.yml) runs this on pull
requests; on every other event CI runs everything without asking. With
`code=false` the Rust, JavaScript, fuzz and latency jobs skip, and the checks
that read documentation (links, spelling, the changelog fragments, the release
version strings) still run.

A changed file is documentation when both hold:

- it is Markdown at the top level, under `docs/` or under `changelog.d/`, or
  an image under `docs/assets/`; anything under `crates/`, `tests/`, `sdk/`,
  `scripts/` or `.github/` is code, Markdown or not (a crate README is part of
  its package and its doc tests);
- nothing that a skipped job builds or runs names it: its path and its file
  name are searched for in every tracked file that is not itself
  documentation. Tests that read a document (the generated blocks of
  `docs/COVERAGE.md`, `docs/EVIDENCE.md`, the tables `doc_tables.rs` and the
  hosts' `docs.rs` compare, `POLICY.md` §5.1, the package's `README.md` and
  `CHANGELOG.md`) name it, so a change to one of those runs everything. A
  mention in a comment or a message counts too: a needless full run costs
  minutes, a skipped test costs a bug on `main`.

Renames are read as a delete and an add, so moving code into `docs/` is a code
change. Any error answers `code=true`.
"""

import fnmatch
import subprocess
import sys

DOC_PATTERNS = ("*.md", "docs/*.md", "docs/**/*.md", "changelog.d/*",
                "docs/assets/*.svg", "docs/assets/*.png", "docs/assets/*.gif")

# Files that name documents without a skipped job reading them: the issue
# forms and CODEOWNERS are not code, `_typos.toml` configures the spelling
# job, this file only lists examples, and the scripts below run in the
# `scripts` job on every pull request, documentation only or not.
NOT_READERS = (
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/",
    "_typos.toml",
    "scripts/ci/changes.py",
    "scripts/changelog-check.py",
    "scripts/ci/check-links.py",
    "scripts/ci/check-versions.py",
    "scripts/ci/latest-agents/check.py",
)


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def is_doc_path(path):
    if path.count("/") == 0:
        return fnmatch.fnmatchcase(path, "*.md")
    return any(fnmatch.fnmatchcase(path, p) for p in DOC_PATTERNS if "/" in p)


def readers(path):
    """Tracked files, other than documentation, that name `path` or its file name."""
    name = path.rsplit("/", 1)[-1]
    excludes = [":(exclude)*.md", ":(exclude)docs/", ":(exclude)changelog.d/",
                *(f":(exclude){p}" for p in NOT_READERS)]
    out = subprocess.run(["git", "grep", "-I", "-l", "-F", "-e", path, "-e", name, "--", ".",
                          *excludes], capture_output=True, text=True)
    if out.returncode not in (0, 1):  # 1: no match
        raise RuntimeError(out.stderr)
    return out.stdout.split()


def classify(base, head):
    """(code, reasons): whether anything but documentation changed, and why."""
    changed = git("diff", "--name-only", "--no-renames", "-z", base, head).split("\0")
    reasons = []
    for path in filter(None, changed):
        if not is_doc_path(path):
            reasons.append(f"{path}: not documentation")
            continue
        named_by = readers(path)
        if named_by:
            reasons.append(f"{path}: named by {', '.join(named_by[:3])}")
    return bool(reasons) or not any(changed), reasons


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    try:
        code, reasons = classify(sys.argv[1], sys.argv[2])
    except (OSError, subprocess.CalledProcessError, RuntimeError) as e:
        print(f"::warning::could not tell what changed ({e}); running every job", file=sys.stderr)
        code, reasons = True, []
    for reason in reasons[:20]:
        print(f"runs everything: {reason}", file=sys.stderr)
    if not code:
        print("documentation only: the Rust, JavaScript, fuzz and latency jobs skip",
              file=sys.stderr)
    print(f"code={'true' if code else 'false'}")


if __name__ == "__main__":
    main()
