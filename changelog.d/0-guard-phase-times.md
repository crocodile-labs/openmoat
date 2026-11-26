### Added
- Each call's audit row records how long `openmoat guard` spent in each of its phases (reading the call, the lock check, loading the policy, deciding, reading the session's earlier calls, the session cache, the audit write), in microseconds; `openmoat audit stats` prints p50, p95 and p99 per phase in text and `--format json`, and `openmoat bench` prints each phase's p50 and p95 for its ordinary work. Only durations and the phase names are recorded. The audit log moves to schema version 13 ([#0](https://github.com/crocodile-labs/openmoat/pull/0)).

### Changed
- Loading a policy deserializes the document once instead of twice: the schema version is read from the full parse ([#0](https://github.com/crocodile-labs/openmoat/pull/0)).
