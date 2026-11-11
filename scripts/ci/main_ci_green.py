#!/usr/bin/env python3
"""Refuse a release of a commit whose `ci` run on `main` is not green.

Usage: main_ci_green.py <owner/repo> <commit sha>      (GH_TOKEN with actions: read)

The release workflow runs this before it builds anything for a tag. Pull
requests need not be up to date with `main`, and they run a fast subset of
CI, so the full run on `main` (every leg, long fuzz) is what a release rests
on. The newest `ci` run of a push to `main` at exactly this commit must have
completed with `success`; a run still going, failed, cancelled, or no such run
at all (a tag on a commit that never landed on `main`) refuses. Re-running the
failed jobs on `main` and then the release workflow is the way out.
"""

import json
import subprocess
import sys


def verdict(runs, sha):
    """None when the release may go on, else why it may not."""
    runs = [r for r in runs if r.get("head_sha") == sha
            and r.get("event") == "push" and r.get("head_branch") == "main"]
    if not runs:
        return f"no `ci` run of a push to main at {sha}: release only commits that landed on main"
    newest = max(runs, key=lambda r: (r.get("created_at") or "", r.get("run_attempt") or 0))
    url = newest.get("html_url", "")
    if newest.get("status") != "completed":
        return f"main's `ci` run for {sha} is still {newest.get('status')}: wait for it ({url})"
    if newest.get("conclusion") != "success":
        return f"main's `ci` run for {sha} ended `{newest.get('conclusion')}` ({url})"
    return None


def fetch_runs(repo, sha):
    out = subprocess.run(
        ["gh", "api", "-X", "GET", f"repos/{repo}/actions/workflows/ci.yml/runs",
         "-f", f"head_sha={sha}", "-f", "event=push", "-f", "branch=main",
         "-f", "per_page=30"],
        check=True, capture_output=True, text=True).stdout
    return json.loads(out).get("workflow_runs", [])


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        sys.exit(__doc__)
    repo, sha = argv
    try:
        runs = fetch_runs(repo, sha)
    except (OSError, subprocess.CalledProcessError, ValueError) as e:
        print(f"::error title=release gate::cannot read main's ci runs ({e!r}); refusing")
        return 1
    problem = verdict(runs, sha)
    if problem:
        print(f"::error title=release gate::{problem}")
        return 1
    print(f"main's ci run for {sha} is green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
