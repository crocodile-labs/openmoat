<!--
Title: Conventional Commits, lowercase subject — e.g. `feat(cli): add openmoat doctor`.
Types: feat fix sec policy host docs test refactor perf build ci chore.
Labels (`type: …`, `area: …`, `size: …`, `risk: …`) are applied automatically. Keep changes
≤ 500 lines; larger PRs fail the size check unless a reviewer adds `size: override`.
-->

## What

<!-- One or two sentences a user would understand. -->

## Why

<!-- Issue link, ADR or doc section, or the incident/bug it addresses. -->

## Testing

<!-- Required. What you ran and what it showed. Behaviour changes need conformance fixtures. -->

- [ ] `scripts/ci/quality-gate.sh` passes locally
- [ ] Conformance fixtures added or updated for behaviour changes

## Security impact

<!-- Required. Does this change what an agent is allowed to do? New trust assumption,
     new I/O in a library crate, new dependency, new fail-open path? Write "none" if none. -->

## Release note

<!-- One line for CHANGELOG.md, written for users; or "none" for internal changes. -->
