# openmoat-audit

Append-only local audit log for [OpenMoat](https://github.com/crocodile-labs/openmoat)
decisions.

One SQLite database in WAL mode with a busy timeout, safe for several concurrent
`openmoat guard` processes. Every stored command and reason passes `redact()` first,
which removes bearer/basic credentials, `key=value` secrets, well-known token
shapes (GitHub, OpenAI, AWS, Slack, Google, npm, GitLab, JWT) and URL passwords.
Event ids are shown as hex (`openmoat show 1f`). Events form a SHA-256 hash chain
(`store/chain.rs`, encoding in `docs/ARCHITECTURE.md` §7) that `Store::verify_chain`
and `openmoat doctor` check.

Schema changes bump `SCHEMA_VERSION` and ship a migration; a newer database than
the binary understands is refused rather than misread.
