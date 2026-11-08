### Fixed
- THREAT_MODEL.md no longer says Codex hides a command's `workdir`: it describes how `openmoat guard` decides a call from the session's directory when Codex sends a `cwd` outside the project, and the paragraph is now generated from each agent's spec so it cannot go stale again ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
