### Fixed
- `openmoat policy upgrade` no longer lists a narrow pattern the default folded into a broader one (0.17.0's `.vscode/tasks.json` into `.vscode/**`) as "Fewer interruptions": a pattern a rule still covers is counted as "now matched by a broader one", and the `openmoat watch` example in USAGE.md marks a deferred call `→` ([#765](https://github.com/crocodile-labs/openmoat/pull/765)).
