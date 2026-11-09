### Security
- `openmoat run` no longer lets commands read the shared temp directories: `/tmp` and macOS's temp folder are left out of its read roots (the run keeps its own temp directory; macOS keeps its per-user caches), which also closes Kerberos ticket caches in `/tmp` on Linux without a network namespace (ADR-018) ([#775](https://github.com/crocodile-labs/openmoat/pull/775)).
