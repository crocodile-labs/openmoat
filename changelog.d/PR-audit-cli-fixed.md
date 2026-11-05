### Fixed
- The first hook call after upgrading from 0.13 no longer copies the whole audit log to accept the `review` verdict: the schema step now widens its check in place, in milliseconds at any size. On a large log the copy ran past the guard's 30 s budget, was rolled back and started again on the next call, so every call was denied ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).
