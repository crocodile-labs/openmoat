#!/usr/bin/env bash
# Install Ubuntu packages on a GitHub-hosted runner, surviving a mirror outage.
#
# The runners fetch from the Azure mirror first (`mirror+file:/etc/apt/apt-mirrors.txt`).
# When its name does not resolve ("Temporary failure resolving
# 'azure.archive.ubuntu.com'"), apt fails every job that installs bubblewrap.
# This tries twice as configured, then points apt straight at archive.ubuntu.com
# and security.ubuntu.com and tries twice more, so one mirror down does not fail CI.
#
#     scripts/ci/apt-install.sh bubblewrap socat
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: $0 package..." >&2; exit 64; }

attempt() {
    sudo apt-get -o Acquire::Retries=3 update -q &&
        sudo apt-get -o Acquire::Retries=3 install -y -q --no-install-recommends "$@"
}

direct_mirrors() {
    # Ubuntu 24.04 keeps its sources in deb822 form; older images in sources.list.
    local f
    for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
        [ -f "$f" ] || continue
        sudo sed -i \
            -e 's#mirror+file:/etc/apt/apt-mirrors.txt#http://archive.ubuntu.com/ubuntu/#g' \
            -e 's#http://azure.archive.ubuntu.com/ubuntu#http://archive.ubuntu.com/ubuntu#g' \
            "$f"
    done
}

for n in 1 2 3 4; do
    if attempt "$@"; then
        exit 0
    fi
    if [ "$n" = 2 ]; then
        echo "::warning::apt failed twice through the runner's mirror; using archive.ubuntu.com directly"
        direct_mirrors
    fi
    sleep $((n * 10))
done
echo "::error::apt could not install: $*"
exit 1
