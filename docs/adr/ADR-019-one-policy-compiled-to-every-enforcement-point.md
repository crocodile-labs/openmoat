# ADR-019: One policy, compiled to every enforcement point, proven by differential tests

Status: accepted · Date: 2026-10-06 · Decided by the maintainer

## Context

Enforcement now spans several layers, each with its own configuration language:

- the hook decision (moat-core)
- Claude Code's `sandbox` settings
- Codex `[permissions]` profiles
- Seatbelt profiles
- Landlock and seccomp rules
- container and VM specifications
- egress proxy rules

Products that keep these by hand drift apart. ZeroClaw's own RFC records that its
application-layer and OS-layer policies had diverged. Claude Code's sandbox and its permission
rules are separate systems that users must keep consistent. A rule that one layer enforces and
another forgets is a bypass that no single test finds.

## Decision

- **`policy.yaml` (schema v1, plus additive keys) is the only source of truth.** Every
  enforcement artefact is generated from it by a policy compiler, and none is edited by hand.
- **The compiler has one intermediate representation** (paths to deny or allow for read and
  write, egress hosts and methods, secrets to broker, process limits) and one backend per
  target:
  - hook decisions (the existing engine)
  - Claude Code `sandbox` settings
  - Codex permissions
  - Seatbelt SBPL
  - Landlock, seccomp and bubblewrap arguments
  - container and VM specifications
  - proxy rules
- **Lossy translations are explicit.** When a target cannot express a rule exactly, the backend
  narrows it (denies more) and reports the loss. It never widens. `moat sandbox sync` prints
  the losses, and `moat doctor` repeats them.
- **Pure parts stay in moat-core.** Writing files and starting processes stays in moat-cli
  (crate boundaries from ADR-001 and AGENTS.md).
- **Generated artefacts are pinned** in `policy.lock` and covered by `kernel-self`.
- **Differential testing proves the layers agree.** One executing fixture suite runs every
  attack and benign scenario against every backend available on the CI runner:
  - the hook decision
  - each host's sandbox through `codex sandbox -P` and a fake-API `claude -p`
  - each moat tier

  Each must give the verdict the fixture expects, or a documented, narrower one. A
  disagreement fails CI. The suite includes replays of public sandbox-escape CVEs from
  comparable products.

## Consequences

- One edit to the policy changes every layer consistently, and a reviewer reads one file.
- Adding a host or a tier is a new backend plus its row in the differential matrix, not a new
  policy format.
- CI needs runners that can execute the hosts' sandboxes. Fixtures that need a host binary skip
  with a visible notice where it is missing, and the release workflow requires them.
- The compiler is security-critical code. It gets the same treatment as the engine: fuzzing,
  property tests ("never widens"), and the parser freeze does not apply to it.
