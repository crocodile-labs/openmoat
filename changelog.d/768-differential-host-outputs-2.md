### Fixed
- `openmoat sandbox show` for Codex now lists the reads its profile takes away: a write-deny glob has no read-only form, so sandboxed commands cannot read those files either, and a policy that allows by default gets only the paths it lists ([#768](https://github.com/crocodile-labs/openmoat/pull/768)).
