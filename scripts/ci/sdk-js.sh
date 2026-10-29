#!/usr/bin/env bash
# Build the JavaScript SDK's WebAssembly module and run the package's tests
# under Node, including every conformance fixture through the module, which
# must decide exactly as the engine does (ADR-046, docs/SDK.md).
#
#   scripts/ci/sdk-js.sh            # release module, as the npm package ships it
#   OPENMOAT_WASM_PROFILE=dev scripts/ci/sdk-js.sh   # faster local build
#
# Needs the pinned toolchain's wasm32-unknown-unknown target (rust-toolchain.toml)
# and Node 20 or later. The module is built from Cargo.lock with the source
# paths remapped, so the same commit gives the same bytes on any machine; its
# SHA-256 is written beside it. Nothing is downloaded beyond the locked crates,
# and the package has no npm dependencies.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
profile=${OPENMOAT_WASM_PROFILE:-release}
case "$profile" in
    release) out=release ;;
    dev) out=debug ;;
    *) echo "OPENMOAT_WASM_PROFILE must be release or dev" >&2; exit 64 ;;
esac

cargo_home=${CARGO_HOME:-$HOME/.cargo}
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--remap-path-prefix=$root=/openmoat --remap-path-prefix=$cargo_home=/cargo"

echo "▶ build the module ($profile)"
cargo build --locked -p openmoat-wasm --target wasm32-unknown-unknown --profile "$profile"
mkdir -p sdk/js/dist
cp "target/wasm32-unknown-unknown/$out/openmoat_wasm.wasm" sdk/js/dist/openmoat.wasm
if command -v sha256sum >/dev/null; then
    (cd sdk/js/dist && sha256sum openmoat.wasm > openmoat.wasm.sha256)
else
    (cd sdk/js/dist && shasum -a 256 openmoat.wasm > openmoat.wasm.sha256)
fi
cat sdk/js/dist/openmoat.wasm.sha256

vectors=$(mktemp "${TMPDIR:-/tmp}/openmoat-sdk-vectors.XXXXXX")
trap 'rm -f "$vectors"' EXIT
echo "▶ conformance vectors from the engine"
OPENMOAT_SDK_VECTORS="$vectors" cargo test --locked -p openmoat-sdk --test conformance

echo "▶ the package's tests under Node $(node --version)"
OPENMOAT_SDK_VECTORS="$vectors" node --test "sdk/js/test/*.test.js"
echo "✔ the JavaScript SDK decides as the engine does"
