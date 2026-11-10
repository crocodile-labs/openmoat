### Changed
- At a terminal, `openmoat init` now offers to run the agents' stdio MCP servers through `openmoat mcp proxy`, shows the change and asks before writing; `--no-mcp-proxy` opts out, a no is remembered per definition, and without a person nothing is rewritten (ADR-076) ([#779](https://github.com/crocodile-labs/openmoat/pull/779)).
