### Changed
- **Breaking** `openmoat-core`: `SandboxSettings` has a new public field `env_allow`, and `openmoat-hosts`: `HostSpec` a new public field `run_env`, which breaks code that builds them field by field ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
