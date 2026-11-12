#!/usr/bin/env bash
# Source of truth for repository labels. Idempotent: run after editing.
#   scripts/ci/sync-labels.sh [owner/repo]
set -euo pipefail
repo="${1:-crocodile-labs/openmoat}"

label() { # name color description
    gh label create "$1" --repo "$repo" --color "$2" --description "$3" --force >/dev/null
    echo "✔ $1"
}

# Remove labels from the earlier slash-separated scheme.
for old in $(gh label list --repo "$repo" --limit 200 --json name --jq '.[].name' | grep -E '^(type|area|size|risk)/|^needs-|^good-first-issue$' || true); do
    gh label delete "$old" --repo "$repo" --yes >/dev/null && echo "✖ $old"
done

# type: * — derived from the Conventional Commits title by pr-standards.yml
label "type: feat"     1d76db "New capability"
label "type: fix"      d73a4a "Bug fix"
label "type: sec"      b60205 "Security fix or hardening"
label "type: policy"   e99695 "Default policy or conformance fixtures"
label "type: host"     5319e7 "Host integration (Claude Code, Codex, …)"
label "type: docs"     0075ca "Documentation only"
label "type: test"     bfd4f2 "Tests only"
label "type: refactor" c5def5 "No behaviour change"
label "type: perf"     fbca04 "Performance"
label "type: build"    0366d6 "Build system or dependencies"
label "type: ci"       000000 "CI and automation"
label "type: chore"    ededed "Housekeeping"

# area: * — derived from changed paths
label "area: core"     0e8a16 "crates/openmoat-core: lexer, classifier, engine"
label "area: hosts"    5319e7 "crates/openmoat-hosts: adapters"
label "area: audit"    006b75 "crates/openmoat-audit: audit log, redaction"
label "area: cli"      1d76db "crates/openmoat-cli: commands, install"
label "area: policy"   e99695 "default policy and tests/conformance"
label "area: ci"       000000 ".github and scripts"
label "area: docs"     0075ca "docs and markdown"
label "area: deps"     0366d6 "Cargo manifests and lockfile"

# size: * — additions + deletions
label "size: XS"       c2e0c6 "≤ 10 lines"
label "size: S"        7bcc7b "≤ 50 lines"
label "size: M"        fbca04 "≤ 200 lines"
label "size: L"        f0a04b "≤ 500 lines"
label "size: XL"       d93f0b "> 500 lines: split, or justify with size: override"
label "size: override" 5319e7 "Reviewer accepted an XL change"

# risk: * — derived from paths that change what agents may do
label "risk: low"      c2e0c6 "Docs, tests, tooling"
label "risk: medium"   fbca04 "Adapters, install, audit"
label "risk: high"     b60205 "Decision engine, policy, guard, workflows, SECURITY"

# workflow
label "needs: fixture"      e4e669 "Behaviour change without a conformance fixture"
label "needs: adr"          e4e669 "Changes an invariant; add docs/adr entry"
label security           b60205 "Security-relevant; maintainer review required"
label "good first issue"   7057ff "Adapters, docs, examples; never the trusted core"
label breaking           b60205 "Breaking change to policy schema, CLI or exit codes"
label "help wanted"        008672 "Open for contributors"
label "ci:full"            000000 "CI's slow legs on this PR (macos-15-intel, long fuzz, ADR-062 step 0); then re-run all jobs"

# roadmap: the order of work (pinned roadmap issue)
label "priority: P0"       b60205 "This week: blocks everything after it"
label "priority: P1"       d93f0b "Needed for the alpha release"
label "priority: P2"       fbca04 "Beta: enforcement and the team story"
label "priority: P3"       c5def5 "After beta (v1.0)"
label "owner task"         5319e7 "Needs the maintainer (credentials, decisions, legal)"

# issues: applied by the issue forms
label bug                d73a4a "Behaves differently from the docs or policy"
label "false positive"     fbca04 "A safe action denied or held for review by the default policy"
label enhancement        a2eeef "Feature request"
label design             c5def5 "Design proposal; may become an ADR"
