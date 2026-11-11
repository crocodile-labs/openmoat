### Fixed
- `openmoat doctor --accept` over a drifted lock no longer exits 64 on the line about MCP server values an older version kept in clear: the re-pin has already written the lock without them, and the line is now decided from the lock as it is on disk ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
