#!/usr/bin/env bash
# The full differential suite (ADR-019, issue #170): every scenario in
# tests/differential/scenarios.yaml run against every enforcement point this
# machine has. `cargo test` alone runs the fast subset (the hook decision, and
# any host sandbox whose binary is already on PATH); this script also points the
# suite at the host binaries so the executing host-sandbox layers run too, the
# hostile project scripts of docs/EVIDENCE.md among them (#346). CI's
# `standard tier` job fetches pinned binaries with scripts/ci/host-binaries.sh.
#
# A layer whose binary is missing prints a visible "skipped" line and the suite
# still passes on the layers it can run, unless MOAT_REQUIRE_HOST_BINARIES is
# set (CI's `standard tier` job): then a missing binary fails the test. No step
# touches the network.
#
#   MOAT_CODEX_BIN   codex binary for the `codex sandbox -P moat` layer
#   MOAT_CLAUDE_BIN  claude binary for the fake-API `claude -p` layer and the
#                    hook scenarios with the real agent (`differential::agents`)
#   MOAT_FAKE_API    python3 for the fake Anthropic API and MCP server they need
set -euo pipefail
cd "$(dirname "$0")/../.."

# Default to a binary on PATH; override by exporting the variable before running.
: "${MOAT_CODEX_BIN:=$(command -v codex || true)}"
: "${MOAT_CLAUDE_BIN:=$(command -v claude || true)}"
: "${MOAT_FAKE_API:=$(command -v python3 || true)}"
export MOAT_CODEX_BIN MOAT_CLAUDE_BIN MOAT_FAKE_API

echo "▶ differential suite"
echo "  codex:  ${MOAT_CODEX_BIN:-<none; codex layer skipped>}"
echo "  claude: ${MOAT_CLAUDE_BIN:-<none; claude layer skipped>}"

# Arguments (CI: `differential sandbox_exec`) choose the tests whose name
# contains any of them; the default is the differential suite.
if [ -z "${GITHUB_ACTIONS:-}" ]; then
    cargo test --locked -p openmoat --test e2e -- --nocapture "${@:-differential}"
else
    # As in quality-gate.sh: the failing tests and their panic lines become
    # annotations, shown on the run without reading its log.
    log="${RUNNER_TEMP:-/tmp}/differential.log"
    if ! cargo test --locked -p openmoat --test e2e -- --nocapture "${@:-differential}" 2>&1 | tee "$log"; then
        { grep -E "^test .* FAILED$" "$log"; grep -A1 "panicked at" "$log" | grep -v '^--$'; } |
            head -10 | sed -e 's/%/%25/g' -e 's/^/::error title=differential::/'
        exit 1
    fi
fi
echo "✔ differential suite passed"
