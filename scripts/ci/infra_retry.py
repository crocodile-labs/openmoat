#!/usr/bin/env python3
"""Whether a failed `ci` run failed only on infrastructure, so ci-retry.yml
re-runs its failed jobs once.

Usage: infra_retry.py <run id> <run attempt>     (GH_TOKEN, GH_REPO set)

Prints `retry=true` or `retry=false` for `$GITHUB_OUTPUT`, and why on stderr.

It answers true only when all of these hold:
- this is the run's first attempt: a re-run is never re-run;
- at least one job failed, `ci-ok` aside (it fails because another did);
- every failed job carries an infrastructure signature among its failure
  annotations (`INFRA`): a runner that was not acquired or lost
  communication, a name that did not resolve (`Temporary failure resolving`,
  which scripts/ci/apt-install.sh repeats in its error), an HTTP 5xx from
  GitHub;
- and no failed job carries anything else: a test failure, a panic, our own
  job timeout (`exceeded the maximum execution time`), a job that timed out
  or was cancelled without a signature, or any failure annotation that is not
  infrastructure. The generic `Process completed with exit code N` line says
  nothing either way and is left out.

Any doubt answers false: a person re-runs by hand, as before.
"""

import json
import re
import subprocess
import sys

VERDICT_JOBS = ("ci-ok",)
FAILED = ("failure", "timed_out", "cancelled", "startup_failure")

INFRA = (
    re.compile(r"not acquired by Runner", re.IGNORECASE),
    re.compile(r"lost communication with the server", re.IGNORECASE),
    re.compile(r"Temporary failure resolving", re.IGNORECASE),
    # An HTTP 5xx from GitHub: a download, a checkout, an API call.
    re.compile(r"(github\.com|githubusercontent\.com|api\.github)\S*.*\b5\d\d\b", re.IGNORECASE),
    re.compile(r"\b5\d\d\b.*(github\.com|githubusercontent\.com|api\.github)", re.IGNORECASE),
    re.compile(r"Response status code does not indicate success: 5\d\d", re.IGNORECASE),
)
NEVER = (
    re.compile(r"exceeded the maximum execution time", re.IGNORECASE),
    re.compile(r"panicked at", re.IGNORECASE),
    re.compile(r"^test .* FAILED", re.IGNORECASE),
)
NEVER_TITLES = ("test failed", "cargo test", "differential", "flaky test")
NEUTRAL = re.compile(r"^Process completed with exit code \d+\.?$")


def job_verdict(job, annotations):
    """(is infrastructure, why) for one failed job and its annotations."""
    name = job.get("name", "?")
    if job.get("conclusion") == "timed_out":
        return False, f"{name}: timed out"
    messages = []
    for a in annotations:
        if a.get("annotation_level") != "failure":
            continue
        title = (a.get("title") or "").strip()
        message = (a.get("message") or "").strip()
        if title.lower() in NEVER_TITLES:
            return False, f"{name}: {title}: {message[:120]}"
        if NEUTRAL.match(message):
            continue
        messages.append(message)
    for message in messages:
        if any(p.search(message) for p in NEVER):
            return False, f"{name}: {message[:120]}"
    infra = [m for m in messages if any(p.search(m) for p in INFRA)]
    other = [m for m in messages if m not in infra]
    if other:
        return False, f"{name}: {other[0][:120]}"
    if not infra:
        return False, f"{name}: {job.get('conclusion')} with no infrastructure signature"
    return True, f"{name}: {infra[0][:120]}"


def decide(attempt, jobs, annotations_of):
    """(retry, reasons). `jobs`: the attempt's jobs as the API lists them;
    `annotations_of(job)`: that job's check-run annotations."""
    if attempt != 1:
        return False, [f"attempt {attempt}: a re-run is never re-run"]
    failed = [j for j in jobs
              if j.get("conclusion") in FAILED and j.get("name") not in VERDICT_JOBS]
    if not failed:
        return False, ["no failed job but the verdict"]
    reasons = []
    retry = True
    for job in failed:
        infra, why = job_verdict(job, annotations_of(job))
        reasons.append(("infrastructure: " if infra else "not infrastructure: ") + why)
        retry = retry and infra
    return retry, reasons


def gh_api(path):
    out = subprocess.run(["gh", "api", "--paginate", path],
                         check=True, capture_output=True, text=True).stdout
    # --paginate concatenates pages: JSON documents back to back.
    decoder = json.JSONDecoder()
    pages, i = [], 0
    while i < len(out):
        if out[i].isspace():
            i += 1
            continue
        page, i = decoder.raw_decode(out, i)
        pages.append(page)
    return pages


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        sys.exit(__doc__)
    run_id, attempt = argv[0], int(argv[1])
    try:
        jobs = [j for page in gh_api(f"repos/{{owner}}/{{repo}}/actions/runs/{run_id}"
                                     f"/attempts/{attempt}/jobs?per_page=100")
                for j in page.get("jobs", [])]

        def annotations_of(job):
            return [a for page in gh_api(f"repos/{{owner}}/{{repo}}/check-runs/{job['id']}"
                                         "/annotations?per_page=100") for a in page]

        retry, reasons = decide(attempt, jobs, annotations_of)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as e:
        retry, reasons = False, [f"could not read the run ({e}); no re-run"]
    for reason in reasons:
        print(reason, file=sys.stderr)
    print(f"retry={'true' if retry else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
