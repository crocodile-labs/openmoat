### Fixed
- `openmoat doctor --format json` names GitHub Copilot CLI's checks after the agent: a name as wide as the text output's column ran into its detail, so tools reading the JSON (OpenMoat Bar) did not find the agent's protection line ([#676](https://github.com/crocodile-labs/openmoat/pull/676)).
