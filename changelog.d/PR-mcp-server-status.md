### Added
- `openmoat status` and `openmoat doctor` show each MCP server OpenMoat can read as protected or unprotected, with why; under `require.run: full-boundary` an unprotected local server fails the requirement, which is reported because the agent starts its servers itself (ADR-077) ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
