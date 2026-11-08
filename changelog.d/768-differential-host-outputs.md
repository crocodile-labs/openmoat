### Added
- The sandbox differential suite also checks Codex's permissions profile, Cursor's `sandbox.json` and the masks `openmoat run` adds inside its grants on Linux: every sampled path the policy denies must be denied there too or named in the backend's report ([#768](https://github.com/crocodile-labs/openmoat/pull/768)).
