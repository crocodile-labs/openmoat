#!/usr/bin/env bash
# Type-check the JavaScript OpenMoat installs into OpenClaw, pi and OpenCode
# (`crates/openmoat-hosts/src/host/*/integration/`), each file under
# `// @ts-check`, with TypeScript's checker in strict mode and nothing emitted
# (`crates/openmoat-hosts/jsconfig.json`).
#
#   scripts/ci/check-js.sh
#
# The plugins have no dependencies; the checker needs TypeScript and Node's
# type declarations (`@types/node`, for `node:child_process` and the rest),
# both pinned to exact versions and installed into a throwaway directory,
# never into the repository. `npx typescript` alone cannot do it: the checker
# finds type declarations next to the project, not next to itself. npm checks
# each package against the integrity the registry published for it. This is
# the only step that uses the network.
set -euo pipefail

typescript=6.0.3
node_types=24.19.2

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/openmoat-check-js.XXXXXX")
trap 'rm -rf "$work"' EXIT

npm install --prefix "$work" --no-save --no-package-lock --ignore-scripts \
    --no-audit --no-fund --loglevel=error \
    "typescript@$typescript" "@types/node@$node_types" >/dev/null
"$work/node_modules/.bin/tsc" --version
"$work/node_modules/.bin/tsc" -p "$root/crates/openmoat-hosts/jsconfig.json" \
    --typeRoots "$work/node_modules/@types"
echo "the plugins type-check"
