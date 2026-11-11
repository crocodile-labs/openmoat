#!/usr/bin/env python3
"""Decide which CI jobs a run needs, and print the answer as `key=value` lines.

Usage: changes.py --event <event> [--pr <number>] <base commit> <head commit>

CI's first job (`changes` in .github/workflows/ci.yml, and the one in
adr062-poc.yml) runs this and passes its output on. It prints three lines:

- `code`: `false` when a pull request changes documentation only. The Rust,
  JavaScript, fuzz and latency jobs then skip; the checks that read
  documentation (links, spelling, the changelog fragments, the release version
  strings) still run.
- `full`: whether the slow legs run: the `macos-15-intel` quality gate and
  ADR-062 step 0. A push to `main`, the weekly schedule and a run by hand
  always run them. A pull request runs them when it is labelled `ci:full` or
  changes platform sandbox code (`SANDBOX`): the Seatbelt, bubblewrap,
  Landlock and seccomp backends, `openmoat run` on macOS and Linux, the
  default policy, the toolchain, `.github/`, or these CI scripts themselves.
- `long_fuzz`: whether each fuzz target runs ten minutes instead of one. A
  push to `main`, the schedule and a run by hand do; a pull request only when
  labelled `ci:full`. Sandbox paths do not order it: the fuzz targets are
  parsers, not the OS sandbox, and a long run would hold the pull request for
  an hour and a half.

The label is read when the job runs, through `gh` (`GH_TOKEN`), not from the
event, so labelling a pull request `ci:full` and re-running its jobs is enough.

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
change. Every doubt runs more, never less: an error while reading the diff
answers `code=true` and `full=true`, an error while reading the labels
`full=true` and `long_fuzz=true`, and an empty diff `code=true` and `full=true`.
"""

import argparse
import fnmatch
import re
import subprocess
import sys

DOC_PATTERNS = ("*.md", "docs/*.md", "docs/**/*.md", "changelog.d/*",
                "docs/assets/*.svg", "docs/assets/*.png", "docs/assets/*.gif")

# Files that name documents without a skipped job reading them: the issue
# forms and CODEOWNERS are not code, `_typos.toml` configures the spelling
# job, this file and its tests only list examples, and the scripts below run
# in the `scripts` job on every pull request, documentation only or not.
NOT_READERS = (
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/",
    "_typos.toml",
    "scripts/ci/changes.py",
    "scripts/ci/test_ci_gates.py",
    "scripts/changelog-check.py",
    "scripts/ci/check-links.py",
    "scripts/ci/check-versions.py",
    "scripts/ci/latest-agents/check.py",
)

# Platform sandbox code: a change here runs the slow legs on the pull request.
# `fnmatch`'s `*` crosses `/`, so `run/linux*` covers `run/linux.rs` and
# everything under `run/linux/`.
SANDBOX = (
    ".github/*",
    "crates/openmoat-cli/src/commands/run/macos*",
    "crates/openmoat-cli/src/commands/run/linux*",
    "crates/openmoat-cli/tests/e2e/run/*",
    "crates/openmoat-core/policies/*",
    "tests/fixtures/sandbox/*",
    "rust-toolchain.toml",
    "scripts/ci/changes.py",
    "scripts/ci/ci_ok.py",
)
# Any path naming a sandbox backend, wherever it lives (its module, its tests).
SANDBOX_WORDS = re.compile(r"seatbelt|bwrap|bubblewrap|landlock|seccomp", re.IGNORECASE)

FULL_LABEL = "ci:full"


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def is_doc_path(path):
    if path.count("/") == 0:
        return fnmatch.fnmatchcase(path, "*.md")
    return any(fnmatch.fnmatchcase(path, p) for p in DOC_PATTERNS if "/" in p)


def is_sandbox_path(path):
    return bool(SANDBOX_WORDS.search(path)) or any(fnmatch.fnmatchcase(path, p) for p in SANDBOX)


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


def changed_paths(base, head):
    return [p for p in git("diff", "--name-only", "--no-renames", "-z", base, head).split("\0") if p]


def pr_labels(pr):
    """The pull request's labels now, through `gh`; raises on any failure."""
    out = subprocess.run(["gh", "pr", "view", str(pr), "--json", "labels",
                          "--jq", ".labels[].name"],
                         check=True, capture_output=True, text=True).stdout
    return out.split("\n")


def classify(changed, find_readers=readers):
    """(code, sandbox, reasons) for a pull request's changed paths."""
    reasons = []
    sandbox = []
    for path in changed:
        if is_sandbox_path(path):
            sandbox.append(path)
        if not is_doc_path(path):
            reasons.append(f"{path}: not documentation")
            continue
        named_by = find_readers(path)
        if named_by:
            reasons.append(f"{path}: named by {', '.join(named_by[:3])}")
    if not changed:
        return True, ["(an empty diff)"], ["an empty diff"]
    return bool(reasons), sandbox, reasons


def decide(event, pr, base, head, list_changed=changed_paths, find_readers=readers,
           labels=pr_labels):
    """{"code", "full", "long_fuzz"} and the notes that explain them."""
    if event != "pull_request":
        return {"code": True, "full": True, "long_fuzz": True}, [f"{event}: every job runs"]
    notes = []
    try:
        code, sandbox, reasons = classify(list_changed(base, head), find_readers)
    except (OSError, subprocess.CalledProcessError, RuntimeError) as e:
        notes.append(f"::warning::could not tell what changed ({e}); running every job")
        code, sandbox, reasons = True, ["(the diff could not be read)"], []
    notes += [f"runs everything: {r}" for r in reasons[:20]]
    if not code:
        notes.append("documentation only: the Rust, JavaScript, fuzz and latency jobs skip")
    try:
        if not pr:
            raise RuntimeError("no pull request number")
        labelled = FULL_LABEL in labels(pr)
    except (OSError, subprocess.CalledProcessError, RuntimeError) as e:
        notes.append(f"::warning::could not read the labels ({e}); running the slow legs")
        labelled = True
    if labelled:
        notes.append(f"`{FULL_LABEL}` (or unknown labels): the slow legs and long fuzz run")
    elif sandbox:
        notes.append(f"platform sandbox code changed ({', '.join(sandbox[:5])}): the slow legs run")
    else:
        notes.append("the slow legs (macos-15-intel, ADR-062 step 0) and long fuzz wait for main")
    return {"code": code, "full": labelled or bool(sandbox), "long_fuzz": labelled}, notes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--event", required=True)
    parser.add_argument("--pr", default="")
    parser.add_argument("base")
    parser.add_argument("head")
    args = parser.parse_args(argv)
    outputs, notes = decide(args.event, args.pr, args.base, args.head)
    for note in notes:
        print(note, file=sys.stderr)
    for key, value in outputs.items():
        print(f"{key}={'true' if value else 'false'}")


if __name__ == "__main__":
    main()
