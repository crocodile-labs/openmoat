### Fixed
- When `openmoat mcp proxy` refuses every call of a server that was not started, a request id holding U+2028 or a similar line separator is escaped in the reply, so no reader that splits lines on it sees two messages ([#785](https://github.com/crocodile-labs/openmoat/pull/785)).
