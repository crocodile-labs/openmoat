### Fixed
- `openmoat mcp proxy` gives a server 5 seconds, not one, to close its output and exit after the agent closes its input, so a server started under `openmoat run` is no longer stopped while its sandbox closes ([#852](https://github.com/crocodile-labs/openmoat/pull/852)).
