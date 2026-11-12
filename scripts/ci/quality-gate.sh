#!/usr/bin/env bash
# What CI's lint and test jobs run (.github/workflows/ci.yml), for before a push.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
