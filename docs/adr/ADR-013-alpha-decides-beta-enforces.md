# ADR-013: Alpha releases decide; enforcement gates beta; the benchmark gates 1.0

Status: accepted · Date: 2026-10-05 · Supersedes the release clause of ADR-003

## Context

ADR-003 tied the first release to OS enforcement (`moat exec`), an egress proxy and the
public benchmark, because a decision on a command string can be wrong and a decide-only
release "would not survive scrutiny".

What exists on 2026-10-05 is a decision layer with real guarantees of its own: one policy
for Claude Code, Codex and Cursor; a lock verified on every call; fail-closed behaviour on
every error path; executable pins; symlink resolution; a redacted audit log; and a
conformance suite tagged by threat, fuzzed in CI. It has no installer, so nobody can use
it without building from source, and real use is the only way to find the false positives
that decide whether people keep it on. Waiting for enforcement keeps that feedback away for
months, while the risk ADR-003 named (overclaiming) can be handled by labelling.

## Decision

- Releases are staged, each with exit criteria:
  - **Alpha** (`0.1.0-alpha.N`): decide-only. Installers for macOS (arm64, x64), Linux
    (x64, arm64, static musl) and Windows (x64); repo-level policy with `moat trust`; a
    conservative PowerShell tokenizer. Exit: installs from a tag on every target, the
    conformance suite green on all CI platforms, and a week of the maintainer's daily use with
    every false positive turned into a fixture.
  - **Beta** (`0.1.0-beta.N`): enforcement. `moat exec` (Seatbelt, Landlock + seccomp),
    the egress proxy, session taint, the MCP stdio proxy with description pinning. Exit:
    executing fixtures show obfuscated exfiltration failing at the OS level, and
    read-then-exfiltrate fixtures are blocked.
  - **1.0**: OpenClaw plugin and `moat serve`; MoatBench v0 meets the gate in
    `docs/STRENGTH.md` §3.3; the policy schema is stable.
- Every alpha says what it is: the README, SECURITY.md and each release note state that
  decisions are not yet enforced by the operating system, so a classifier mistake is a
  security bug, not a usability bug. ADR-003's statement that "a parser bug is a usability
  bug" applies from beta on.
- ADR-003's technical decisions (enforcement on macOS and Linux, the proxy, taint, Windows
  decide-only at first) stand; only their timing moves.

## Consequences

- People can install and use moat now, and the default policy is shaped by real use before
  enforcement is layered under it.
- Until beta, the classifier is the security boundary: bypass reports are in scope (see
  SECURITY.md) and the fuzz targets and conformance suite carry that weight.
- The roadmap (`docs/PROGRESS.md` §4, `03-plans`) orders release before enforcement;
  `moat-sandbox` and `moat-proxy` are beta crates.
