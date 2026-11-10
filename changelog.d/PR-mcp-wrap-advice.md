### Fixed
- `openmoat status` and `openmoat doctor` no longer advise `openmoat mcp wrap` for a goose extension of inline Python, which cannot be wrapped, and `openmoat mcp wrap` no longer warns about an OpenCode entry that names no program, such as `{"enabled": false}` or a `url` with no `type` ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
