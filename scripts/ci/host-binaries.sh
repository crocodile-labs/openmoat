#!/usr/bin/env bash
# Fetch the pinned Claude Code and Codex binaries that the differential suite
# runs the Standard tier with (#346): each npm platform package, checked against
# the sha512 integrity the registry published for it. Neither needs an account:
# Claude Code runs against the suite's local fake API and `codex sandbox` makes
# no API call. Only this download uses the network; the tests do not.
#
#   scripts/ci/host-binaries.sh <dir> >> "$GITHUB_ENV"
#
# prints MOAT_CLAUDE_BIN=… and MOAT_CODEX_BIN=… for the differential tests
# (`cargo test -p openmoat --test e2e -- differential`).
set -euo pipefail
dir=${1:?usage: host-binaries.sh <dir>}

claude=2.1.290
codex=0.160.1
case "$(uname -s)-$(uname -m)" in
Darwin-arm64)
    claude_sha=Gwf07acohw9mGTBIXeac1PTZKRMRsGoBFtm7OA3TMoLoF/3M2kPojkqdjxEzTVw15lJjA0N1lgZEa8jLWt4odQ==
    codex_sha=6Znu97O7+Ie/cnUpsWLx6NlcPc7DNuj6sAs58xpt0/tKRgx4+xgE9zca1YrwqQUBjUQO1HexudyimmhpZjdWlA==
    platform=darwin-arm64
    ;;
Linux-x86_64)
    claude_sha=1FQDIO4tXPFyw9wR1icEedIhEmLzOiQBAGR0NgETrXK8M2YbHEDXoE5Gg/LIuIee7giUuX5F2RzLw2N2i++ofQ==
    codex_sha=sIDhqV+bsZKKVaVFVY5iB+pAzyOz2XRm3H1KXCsSJwGj5p98qnrT0Fweo1Hfe7WnyTp8mfBNdbVzUeO+mHYugA==
    platform=linux-x64
    ;;
*)
    echo "no pinned host binaries for $(uname -sm)" >&2
    exit 64
    ;;
esac

# fetch <name> <tarball url> <sha512 integrity>: verified, unpacked in <dir>/<name>.
fetch() {
    mkdir -p "$dir/$1"
    curl -fsSL --retry 3 -o "$dir/$1.tgz" "$2"
    got=$(openssl dgst -sha512 -binary "$dir/$1.tgz" | openssl base64 -A)
    if [ "$got" != "$3" ]; then
        echo "$1: sha512 $got does not match the pinned $3" >&2
        exit 1
    fi
    tar -xzf "$dir/$1.tgz" -C "$dir/$1"
}

registry=https://registry.npmjs.org
fetch claude "$registry/@anthropic-ai/claude-code-$platform/-/claude-code-$platform-$claude.tgz" "$claude_sha"
fetch codex "$registry/@openai/codex/-/codex-$codex-$platform.tgz" "$codex_sha"

echo "MOAT_CLAUDE_BIN=$dir/claude/package/claude"
echo "MOAT_CODEX_BIN=$(echo "$dir"/codex/package/vendor/*/bin/codex)"
