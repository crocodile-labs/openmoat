### Changed
- A policy's `version:` is read before anything else: a file for a newer schema says it needs a newer OpenMoat, one without `version:` says to add `version: 1` (or run `openmoat policy migrate`), and a field error names the policy schema version it was read against (ADR-103) ([#839](https://github.com/crocodile-labs/openmoat/pull/839)).
