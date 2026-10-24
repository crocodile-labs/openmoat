### Security
- The egress proxy looks a session's taint up again on every recheck while it cannot read the audit log's newest event, instead of reusing the taint it last saw for up to the recheck age; a lookup that then fails still refuses the connection ([#658](https://github.com/crocodile-labs/openmoat/pull/658)).
