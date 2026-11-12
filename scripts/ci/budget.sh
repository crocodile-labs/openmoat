#!/usr/bin/env bash
# How much of its time limit a CI job used, and a warning past 60%.
#
#     JOB_STARTED=<epoch seconds> scripts/ci/budget.sh <limit in minutes>
#
# Each job of ci.yml and weekly.yml writes JOB_STARTED as its first step and
# runs this as its last (`if: always()`), with the job's own `timeout-minutes`
# (scripts/ci/test_ci_gates.py checks that they agree). The rule
# (CONTRIBUTING "CI"): a job's usual time is at most half its limit; one that
# passes 60% is a job to split or speed up, before it meets its limit. Limits
# are not raised. Never fails the job.
set -uo pipefail
limit=${1:-}
case "$limit" in
    '' | *[!0-9]*) echo "usage: JOB_STARTED=<epoch seconds> $0 <limit in minutes>" >&2; exit 0 ;;
esac
started=${JOB_STARTED:-}
case "$started" in
    '' | *[!0-9]*) echo "::warning title=time budget::JOB_STARTED is not set; no budget check"; exit 0 ;;
esac
now=${BUDGET_NOW:-$(date +%s)}
used=$((now - started))
percent=$((used * 100 / (limit * 60)))
line="this job used $((used / 60)) min $((used % 60)) s, ${percent}% of its ${limit}-minute limit"
echo "$line"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "Time: $line." >> "$GITHUB_STEP_SUMMARY"
fi
if [ "$percent" -gt 60 ]; then
    echo "::warning title=time budget::${line}: over 60%; split or speed it up (CONTRIBUTING \"CI\")"
fi
exit 0
