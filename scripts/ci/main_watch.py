#!/usr/bin/env python3
"""After each `ci` run of a push to `main`: open or update the issues a person
must see.

Usage: main_watch.py <run id> <run attempt> <conclusion>   (GH_TOKEN, GH_REPO)

ci-retry.yml runs this once the run is final (not when it re-runs it for an
infrastructure failure, scripts/ci/infra_retry.py). It reads the annotations
scripts/ci/junit_summary.py wrote on this run and on the push to `main` before
it, and keeps one open issue per subject, commenting on it when it already
exists:

- `ci: main is red`: the run failed;
- `flaky test: <binary id> <test>`: a test that failed and passed on its
  retry in this run (a flaky test is listed, never hidden);
- `test failing on main: <binary id> <test>`: a test that failed in this run
  and failed or needed a retry in the run before: twice in a row on `main`.

It never closes an issue; a person does, with the fix.
"""

import json
import subprocess
import sys

FAILED_TITLE = "test failed"
FLAKY_TITLE = "flaky test"
RED_TITLE = "ci: main is red"


def tests_in(annotations):
    """({failed test}, {flaky test}) named by junit_summary.py's annotations,
    each `<binary id> <test>`."""
    failed, flaky = set(), set()
    for a in annotations:
        title = (a.get("title") or "").strip()
        # `<binary id> <test>: …`: both hold `::`, neither a space, and the
        # reason follows `: `.
        head = (a.get("message") or "").split(": ", 1)[0].strip()
        if len(head.split(" ")) != 2:
            continue
        if title == FAILED_TITLE:
            failed.add(head)
        elif title == FLAKY_TITLE:
            flaky.add(head)
    return failed, flaky


def plan(conclusion, run_url, now, before):
    """[(issue title, comment)] for this run. `now` and `before`: the
    (failed, flaky) tests of this run and of the push to main before it."""
    failed, flaky = now
    before_failed, before_flaky = before
    issues = []
    if conclusion == "failure":
        issues.append((RED_TITLE, f"The `ci` run of a push to `main` failed: {run_url}"))
    for test in sorted(flaky):
        issues.append((f"{FLAKY_TITLE}: {test}",
                       f"`{test}` failed and then passed on its retry: {run_url}. Fix it, or "
                       "quarantine it in `.config/nextest-quarantine.md` under its rules."))
    for test in sorted(failed & (before_failed | before_flaky)):
        issues.append((f"test failing on main: {test}",
                       f"`{test}` failed on `main` in this run and in the one before: {run_url}"))
    return issues


def gh(*args):
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def gh_pages(path):
    out = gh("api", "--paginate", path)
    decoder = json.JSONDecoder()
    pages, i = [], 0
    while i < len(out):
        if out[i].isspace():
            i += 1
            continue
        page, i = decoder.raw_decode(out, i)
        pages.append(page)
    return pages


def annotations(run_id, attempt):
    found = []
    for page in gh_pages(f"repos/{{owner}}/{{repo}}/actions/runs/{run_id}/attempts/{attempt}"
                         "/jobs?per_page=100"):
        for job in page.get("jobs", []):
            for notes in gh_pages(f"repos/{{owner}}/{{repo}}/check-runs/{job['id']}"
                                  "/annotations?per_page=100"):
                found += notes
    return found


def previous_main_run(run_id):
    """(id, attempt) of the completed push to main before `run_id`, or None."""
    runs = json.loads(gh("api", "repos/{owner}/{repo}/actions/workflows/ci.yml/runs"
                         "?branch=main&event=push&status=completed&per_page=10"))
    for run in runs.get("workflow_runs", []):
        if run["id"] < int(run_id):
            return run["id"], run.get("run_attempt", 1)
    return None


def upsert(title, comment):
    listed = json.loads(gh("issue", "list", "--state", "open", "--search", f'in:title "{title}"',
                           "--json", "number,title"))
    same = [i for i in listed if i["title"] == title]
    if same:
        gh("issue", "comment", str(same[0]["number"]), "--body", comment)
        print(f"commented on #{same[0]['number']}: {title}")
    else:
        gh("issue", "create", "--title", title, "--body", comment)
        print(f"opened: {title}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        sys.exit(__doc__)
    run_id, attempt, conclusion = argv
    repo = subprocess.run(["gh", "repo", "view", "--json", "url", "--jq", ".url"],
                          capture_output=True, text=True).stdout.strip()
    run_url = f"{repo}/actions/runs/{run_id}" if repo else f"run {run_id}"
    now = tests_in(annotations(run_id, attempt))
    before = (set(), set())
    previous = previous_main_run(run_id)
    if previous:
        before = tests_in(annotations(*previous))
    for title, comment in plan(conclusion, run_url, now, before):
        upsert(title, comment)
    return 0


if __name__ == "__main__":
    sys.exit(main())
