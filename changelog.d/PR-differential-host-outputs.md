### Added
- The sandbox differential suite also checks Codex's permissions profile, Cursor's `sandbox.json` and the masks `openmoat run` adds inside its grants on Linux: every sampled path the policy denies must be denied there too or named in the backend's report ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).

### Fixed
- `openmoat sandbox show` for Codex now lists the reads its profile takes away: a write-deny glob has no read-only form, so sandboxed commands cannot read those files either, and a policy that allows by default gets only the paths it lists ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
