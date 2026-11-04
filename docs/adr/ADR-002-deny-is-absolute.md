# ADR-002: Deny is absolute; defaults are per kind

Status: accepted · Date: 2026-10-02

## Context

The first draft expressed "no outbound network except these hosts" as a deny rule
`net: ["*"]` with allow rules punching holes. That requires allow to override deny,
which makes every deny rule conditional on the absence of a broader allow rule and
turns policy review into whole-file reasoning.

## Decision

- Evaluation order is `deny → allow → review → defaults`; the first list with a match wins.
- An allow rule can never override a deny rule.
- "Deny by default for a kind" is written as `defaults: {net: deny}` plus allow
  rules. `defaults` is a single verdict or a map from action kind to verdict; the
  synthetic rule id is `default` or `default.<kind>`.
- Across the atomic actions of one tool call, the strictest verdict wins.

## Consequences

- A deny rule can be reviewed in isolation: if it matches, the action is denied.
- Policy authors must use `defaults` for kind-wide denial; `moat policy lint` can
  warn on `deny: ["*"]`-style rules in a later version.
- Fixtures assert `default.net` rather than a named rule for unlisted hosts.
