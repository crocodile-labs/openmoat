#!/usr/bin/env python3
"""Refuse a release of a commit whose `ci` run on `main` is not green.

Usage: main_ci_green.py [--wait-minutes N] [--interval S] <owner/repo> <commit sha>
       (GH_TOKEN with actions: read and contents: read)

The release workflow runs this before it builds anything for a tag. Pull
requests need not be up to date with `main`, and they run a fast subset of
CI, so the full run on `main` (every leg, long fuzz) is what a release rests
on. The newest `ci` run of a push to `main` at exactly this commit must have
completed with `success`.

- A run still queued or in progress is waited for: the runs are read again
  every `--interval` seconds (60) for up to `--wait-minutes` (150, longer than
  the slowest `ci` run). A tag pushed right after its merge thus releases once
  main's run is green.
- No run at all: when the commit is on `main` (the compare API), no run has
  started for it yet, and that is waited for too; when it is not on `main`,
  the release refuses at once: release only commits that landed on main.
- A run that failed or was cancelled refuses at once. Re-running the failed
  jobs on `main` and then the release workflow is the way out.

Any error while reading the runs or the commit refuses.
"""

import argparse
import json
import subprocess
import sys
import time

WAIT, PASS, REFUSE = "wait", "pass", "refuse"


def verdict(runs, sha, on_main):
    """(WAIT | PASS | REFUSE, why). `on_main()` is asked only when there is no run."""
    runs = [r for r in runs if r.get("head_sha") == sha
            and r.get("event") == "push" and r.get("head_branch") == "main"]
    if not runs:
        if on_main():
            return WAIT, f"no ci run has started for this commit yet ({sha})"
        return REFUSE, (f"this commit is not on main ({sha}): "
                        "release only commits that landed on main")
    newest = max(runs, key=lambda r: (r.get("created_at") or "", r.get("run_attempt") or 0))
    url = newest.get("html_url", "")
    if newest.get("status") != "completed":
        return WAIT, f"main's `ci` run for {sha} is still {newest.get('status')} ({url})"
    if newest.get("conclusion") != "success":
        return REFUSE, f"main's `ci` run for {sha} ended `{newest.get('conclusion')}` ({url})"
    return PASS, f"main's ci run for {sha} is green ({url})"


def gh_json(*args):
    out = subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def fetch_runs(repo, sha):
    return gh_json("-X", "GET", f"repos/{repo}/actions/workflows/ci.yml/runs",
                   "-f", f"head_sha={sha}", "-f", "event=push", "-f", "branch=main",
                   "-f", "per_page=30").get("workflow_runs", [])


def commit_on_main(repo, sha):
    """Whether `sha` is `main` or one of its ancestors."""
    status = gh_json(f"repos/{repo}/compare/main...{sha}").get("status")
    return status in ("identical", "behind")


def gate(repo, sha, wait_minutes, interval, fetch=fetch_runs, on_main=commit_on_main,
         sleep=time.sleep, clock=time.monotonic):
    """(passed, why) after waiting for a run in progress up to `wait_minutes`."""
    deadline = clock() + wait_minutes * 60
    while True:
        state, why = verdict(fetch(repo, sha), sha, lambda: on_main(repo, sha))
        if state != WAIT:
            return state == PASS, why
        if clock() + interval > deadline:
            return False, f"{why}; gave up after {wait_minutes} minutes"
        print(f"waiting: {why}", flush=True)
        sleep(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--wait-minutes", type=float, default=150)
    parser.add_argument("--interval", type=float, default=60)
    parser.add_argument("repo")
    parser.add_argument("sha")
    args = parser.parse_args(argv)
    try:
        passed, why = gate(args.repo, args.sha, args.wait_minutes, args.interval,
                           fetch=fetch_runs, on_main=commit_on_main)
    except (OSError, subprocess.CalledProcessError, ValueError, AttributeError) as e:
        print(f"::error title=release gate::cannot read main's ci runs ({e!r}); refusing")
        return 1
    if not passed:
        print(f"::error title=release gate::{why}")
        return 1
    print(why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
