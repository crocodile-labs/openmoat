### Fixed
- `openmoat status`, `doctor` and `init` say "none besides OpenMoat's own hook" when the agents load no other hook, instead of "0 recorded", which read as if recording had failed ([#860](https://github.com/crocodile-labs/openmoat/pull/860)).
- `openmoat inventory --check` and `openmoat team` keep the bundle signature they verify in a private folder in the temp directory instead of `~/.moat/team/`, so the check also works where `~/.moat` is not writable, such as inside an agent's sandbox ([#860](https://github.com/crocodile-labs/openmoat/pull/860)).
