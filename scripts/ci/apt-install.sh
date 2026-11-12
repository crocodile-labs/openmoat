#!/usr/bin/env bash
# Install Ubuntu packages on a GitHub-hosted runner, surviving a mirror outage.
#
# The runners fetch from the Azure mirror first (`mirror+file:/etc/apt/apt-mirrors.txt`).
# When names under ubuntu.com do not resolve ("Temporary failure resolving
# 'azure.archive.ubuntu.com'", 2026-11-11), apt fails every job that installs
# bubblewrap. This tries the runner's own sources once, then archive.ubuntu.com,
# then a mirror outside ubuntu.com (kernel.org), each with short timeouts so a
# dead mirror costs seconds, not the job's time limit.
#
#     scripts/ci/apt-install.sh bubblewrap socat
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: $0 package..." >&2; exit 64; }

opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)

# Every attempt's output, so the final error can name a resolution failure:
# ci-retry.yml re-runs a job whose error says "Temporary failure resolving"
# (scripts/ci/infra_retry.py).
log=$(mktemp)
trap 'rm -f "$log"' EXIT

attempt() {
    { sudo apt-get "${opts[@]}" update -q &&
        sudo apt-get "${opts[@]}" install -y -q --no-install-recommends "$@"; } 2>&1 | tee -a "$log"
}

# Point every Ubuntu source at one mirror. Ubuntu 24.04 keeps them in deb822
# form (ubuntu.sources); older images in sources.list.
use_mirror() {
    local mirror=$1 f
    for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
        [ -f "$f" ] || continue
        sudo sed -i -E \
            -e "s#mirror\+file:/etc/apt/apt-mirrors\.txt#${mirror}#g" \
            -e "s#https?://([a-z0-9.-]+\.)?(archive|security)\.ubuntu\.com/ubuntu/?#${mirror}#g" \
            -e "s#https?://mirrors\.edge\.kernel\.org/ubuntu/?#${mirror}#g" \
            "$f"
    done
}

if attempt "$@"; then
    exit 0
fi
for mirror in http://archive.ubuntu.com/ubuntu/ http://mirrors.edge.kernel.org/ubuntu/; do
    echo "::warning::apt failed through the runner's sources; trying ${mirror}"
    use_mirror "$mirror"
    if attempt "$@"; then
        exit 0
    fi
done
resolving=$(grep -m1 -o "Temporary failure resolving '[^']*'" "$log" || true)
echo "::error::apt could not install: $*${resolving:+ ($resolving)}"
exit 1
