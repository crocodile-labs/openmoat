### Fixed
- A lock that pins a Codex `config.toml` both whole and by OpenMoat's profile part is caught as a bug when it is saved (in debug builds and tests), and an audit-log migration that finds another process already migrated decides from the version it read under the lock, refusing a newer schema, instead of starting over ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
