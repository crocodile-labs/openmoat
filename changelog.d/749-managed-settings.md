### Security
- Writes to the agents' system-wide settings, which outrank the user's and can turn every hook off (Claude Code's managed settings folder, Gemini CLI's system settings, Codex's `/etc/codex`), are denied (`managed-settings`, hook only) ([#749](https://github.com/crocodile-labs/openmoat/pull/749)).
