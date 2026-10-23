# openmoat-audit

The append-only local audit log: one SQLite database in WAL mode with a busy timeout, safe for several concurrent `guard` processes; queries and export; `redact()`; the SHA-256 hash chain over events (`store/chain.rs`, encoding in docs/ARCHITECTURE.md §7) that `Store::verify_chain` and `openmoat doctor` check. Root rules: [AGENTS.md](../../AGENTS.md).

## Rules
- No secrets in the log (invariant 6): every stored command and reason passes `redact()` first. Never log a secret, not even in an error.
- Append-only: no update or delete of stored events; the chain must verify after every write path.
- A schema change bumps `SCHEMA_VERSION` in `store/schema.rs`, adds a migration step, keeps `Event` deserialisation backward compatible, and adds a test that opens a database written by the previous version.
- Typed `thiserror` errors; no printing (`print_stdout`/`print_stderr` are denied in `lib.rs`); every public item has a doc comment.
- Test-only tampering helpers stay behind the `test-support` feature.

## Test
- `cargo test -p openmoat-audit --all-features`: unit tests and `tests/token_shapes.rs`.
- A new token shape in `redact` gets a test whose made-up token is built at run time (write the `-` after a vendor prefix as `\x2d`), never a literal that looks real.

## Do not
- Weaken a redaction pattern without a test showing what it still catches.
- Change the chain encoding without an ADR and a migration.
