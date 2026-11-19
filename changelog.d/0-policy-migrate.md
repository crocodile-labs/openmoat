### Added
- `openmoat policy migrate` rewrites a policy file in the current policy schema without changing a rule: it adds a missing `version:` and renames the old `ask`, shows the diff, applies only for a person at a terminal, keeps `<file>.before-migrate` and re-pins the installed policy (docs/POLICY.md §1.1, ADR-103) ([#0](https://github.com/crocodile-labs/openmoat/pull/0)).
