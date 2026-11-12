#!/usr/bin/env python3
"""The verdict of CI's `ci-ok` job: pass only when every other job did.

Usage: NEEDS='<toJSON(needs)>' ci_ok.py <workflow file>

`ci-ok` in .github/workflows/ci.yml `needs` every other job and runs
`if: always()`, so it reports on every run, and it is the one check the
`main` ruleset requires. This script fails it when:

- a job of the workflow is missing from `needs` (a new job would otherwise
  merge unchecked), or `needs` names a job the workflow does not have;
- any job failed or was cancelled, the `changes` job included;
- any job was skipped that the `changes` job did not order to skip. The only
  ordered skip is a job whose own `if:` tests
  `needs.changes.outputs.code != 'false'`, on a run where `changes` succeeded
  and answered `code=false` (a documentation-only pull request).

A matrix job reports one result for all its legs: `failure` if any leg
failed. Legs with nothing to run (a documentation-only pull request, or the
slow legs `changes` held back) run their skipped steps and report `success`.

On a pull request, ci.yml runs the copy of this file on the branch the pull
request lands on (the merge commit's first parent), not the pull request's
own, so a pull request cannot change how its own run is judged; it checks
the pull request's ci.yml, the workflow that actually ran. A change to this
file sets `full` on that pull request (scripts/ci/changes.py) and judges runs
from the next pull request after it merges. Only while the base branch has no
copy of this file does the pull request's copy run, with a warning.

The workflow is read as text, not YAML (no YAML parser in the standard
library): a job is a line `  <id>:` under `jobs:`, its condition the line
`    if: …` below it. Anything the reader does not understand fails the job.
"""

import json
import os
import re
import sys

DOCS_ONLY_TEST = "needs.changes.outputs.code != 'false'"
SELF = "ci-ok"
JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")
JOB_IF = re.compile(r"^    if:\s*(.*)$")


def workflow_jobs(text):
    """{job id: its job-level `if:` text, or ""} in the order they appear."""
    jobs = {}
    current = None
    in_jobs = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_jobs = line.rstrip() == "jobs:"
            current = None
            continue
        if not in_jobs:
            continue
        m = JOB.match(line)
        if m:
            current = m.group(1)
            jobs[current] = ""
            continue
        m = JOB_IF.match(line)
        if m and current is not None:
            jobs[current] = m.group(1)
    return jobs


def verdict(needs, jobs):
    """The list of problems; empty means the run passes."""
    problems = []
    expected = set(jobs) - {SELF}
    for job in sorted(expected - set(needs)):
        problems.append(f"{job}: not in ci-ok's needs, so its result is not checked")
    for job in sorted(set(needs) - expected):
        problems.append(f"{job}: in ci-ok's needs but not a job of the workflow")

    changes = needs.get("changes", {})
    docs_only = (changes.get("result") == "success"
                 and (changes.get("outputs") or {}).get("code") == "false")
    for job in sorted(needs):
        result = needs[job].get("result")
        if result == "success":
            continue
        if result == "skipped" and docs_only and DOCS_ONLY_TEST in jobs.get(job, ""):
            continue
        if result == "skipped":
            problems.append(f"{job}: skipped, and the changes job did not order it")
        else:
            problems.append(f"{job}: {result}")
    if not needs:
        problems.append("no job results at all")
    return problems


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.exit(__doc__)
    try:
        with open(argv[0], encoding="utf-8") as f:
            jobs = workflow_jobs(f.read())
        needs = json.loads(os.environ["NEEDS"])
        if not isinstance(needs, dict) or not all(isinstance(v, dict) for v in needs.values()):
            raise ValueError("NEEDS is not an object of job results")
    except (OSError, KeyError, ValueError) as e:
        print(f"::error title=ci-ok::cannot read the job results ({e!r})")
        return 1
    if SELF not in jobs:
        print(f"::error title=ci-ok::{argv[0]} has no `{SELF}` job; is this the right workflow?")
        return 1
    problems = verdict(needs, jobs)
    for job in sorted(needs):
        print(f"{job}: {needs[job].get('result')}")
    for problem in problems:
        print(f"::error title=ci-ok::{problem}")
    if problems:
        return 1
    print("ci-ok: every job passed or was skipped by the changes job's order")
    return 0


if __name__ == "__main__":
    sys.exit(main())
