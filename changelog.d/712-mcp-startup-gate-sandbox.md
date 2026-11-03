### Changed
- `openmoat mcp wrap` and `openmoat init --mcp-proxy` start servers under `openmoat run`'s sandbox by default wherever it can sandbox (macOS 13 or later, Linux); `--no-sandbox` (`--mcp-no-sandbox` for `init`) opts out, and wrapping an already wrapped server keeps its choice unless a flag is given ([#712](https://github.com/crocodile-labs/openmoat/pull/712)).
- `openmoat mcp proxy` started by hand, or by a client whose configuration OpenMoat does not read, no longer starts the server ([#712](https://github.com/crocodile-labs/openmoat/pull/712)).
