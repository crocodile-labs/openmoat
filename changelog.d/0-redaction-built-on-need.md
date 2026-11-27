### Changed
- `openmoat guard` spends about 12 ms less per call reading the session's earlier calls: the audit log's redaction builds each of its credential patterns only the first time a text could hold a match, instead of all of them on the first lookup; what is masked is unchanged ([#0](https://github.com/crocodile-labs/openmoat/pull/0)).
