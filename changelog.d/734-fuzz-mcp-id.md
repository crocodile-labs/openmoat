### Security
- `openmoat mcp proxy` drops a server response that has no `id`: an error without one reached the agent host, which could take it for the answer to any request it was waiting for. Found by the `mcp_relay_framing` fuzz target ([#734](https://github.com/crocodile-labs/openmoat/pull/734)).
