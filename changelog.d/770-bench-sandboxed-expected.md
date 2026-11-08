### Fixed
- `openmoat bench` counts a run as `sandboxed` only when every step the hook let through is one the scenario expects OpenMoat's OS sandbox to hold; one marked step no longer counts the whole run. The column is marked as expected, not run, under the table ([#770](https://github.com/crocodile-labs/openmoat/pull/770)).
