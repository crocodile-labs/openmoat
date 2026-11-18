### Fixed
- The GitHub Action's `fail-on: deny` and `fail-on: never` now work: the step no longer ends at the check's own exit code on the first finding, so a review-only result passes under `deny` and nothing fails under `never`, as documented ([#831](https://github.com/crocodile-labs/openmoat/pull/831)).
