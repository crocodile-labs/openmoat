#!/usr/bin/env bash
# Install cargo-nextest from its pinned release, its SHA-256 checked first.
#
#     scripts/ci/install-nextest.sh <directory>     # prints the directory for $GITHUB_PATH
#
# One archive per runner OS: Linux x86_64, macOS (one universal binary, Apple
# silicon and Intel) and Windows x86_64. The digests are GitHub's own for the
# release assets (the `digest` of each asset in the releases API), recorded
# here so a replaced asset fails the install. A version change updates all
# three lines together.
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: $0 <directory>" >&2; exit 64; }
dir=$1

VERSION=0.9.150
# GNU tar on Windows reads `D:\…` as a remote host without this.
tar_opts=()
case "$(uname -sm)" in
    "Linux x86_64")
        target=x86_64-unknown-linux-gnu
        sha256=b0959bc64232974224cf9fb22c915845398c0e8668fa7831eb5b43fb1eef781f ;;
    Darwin\ *)
        target=universal-apple-darwin
        sha256=82a759b4d218d38359424196ab244c470e8f7c7d149c814fbbeef4d67c3c301a ;;
    MINGW64_NT*\ x86_64 | MSYS_NT*\ x86_64)
        target=x86_64-pc-windows-msvc
        sha256=b7a8bf567140b8b366716f2dea27b32e088dc12f53597315f976d0dbf7c6ade8
        tar_opts=(--force-local) ;;
    *)
        echo "no pinned cargo-nextest for $(uname -sm)" >&2
        exit 1 ;;
esac

archive="cargo-nextest-${VERSION}-${target}.tar.gz"
url="https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${VERSION}/${archive}"
mkdir -p "$dir"
# curl's own error (`The requested URL returned error: 503`) goes into the
# annotation with the URL: ci-retry.yml re-runs a job that failed on a GitHub
# 5xx (scripts/ci/infra_retry.py).
if ! err=$(curl -fsSL --retry 5 --retry-all-errors -o "$dir/$archive" "$url" 2>&1); then
    echo "::error::downloading $url failed: $err"
    exit 1
fi
# Hashed from standard input: given a path with a backslash (Windows), GNU
# sha256sum escapes its output line and puts a `\` before the hash.
if command -v sha256sum > /dev/null; then
    got=$(sha256sum < "$dir/$archive" | cut -d' ' -f1)
else
    got=$(shasum -a 256 < "$dir/$archive" | cut -d' ' -f1)
fi
if [ "$got" != "$sha256" ]; then
    echo "::error::$archive: sha256 $got does not match the pinned $sha256" >&2
    exit 1
fi
tar ${tar_opts[@]+"${tar_opts[@]}"} -xzf "$dir/$archive" -C "$dir"
rm "$dir/$archive"
echo "$dir"
