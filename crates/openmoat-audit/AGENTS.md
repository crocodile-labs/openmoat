# openmoat-audit

The append-only local audit log: one SQLite database in WAL mode with a busy timeout, safe for several concurrent `guard` processes; queries and export; `redact()`; the SHA-256 hash chain over events (`store/chain.rs`, encoding in docs/ARCHITECTURE.md §7) and each event's audit-key MAC of its hash (`key.rs`, ADR-101) that `Store::verify_chain` and `openmoat doctor` check. Root rules: [AGENTS.md](../../AGENTS.md).

## Rules
- No secrets in the log (invariant 6): every stored command and reason passes `redact()` first. Never log a secret, not even in an error.
- Append-only: no update or delete of stored events; the chain must verify after every write path.
- Every event is recorded with the audit key's MAC: `Store::record` refuses without the key (ADR-101), never writes an event without one. The key file's I/O is the CLI's (`audit_key.rs`); this crate only encodes, parses and computes.
- A schema change bumps `SCHEMA_VERSION` in `store/schema.rs`, adds a migration step, keeps `Event` deserialisation backward compatible, and adds a test that opens a database written by the previous version. The upgrade-path tests (`store/tests/upgrade_path.rs`, the CLI's `audit_key/tests/upgrade_path.rs` and e2e `upgrade_path`) build each older version's log with `testing::as_written_by`, from the same ladder steps; extend them to the version the change leaves behind.
- Typed `thiserror` errors; no printing (`print_stdout`/`print_stderr` are denied in `lib.rs`); every public item has a doc comment.
- Test-only tampering helpers stay behind the `test-support` feature.
- Live delivery's bodies (`delivery.rs`, ADR-081) mask every text again with `KnownSecrets` before it is encoded; a cell that does not decode fails the batch rather than going out unmasked. This crate builds the bytes and opens no connection.

## Test
- `cargo test -p openmoat-audit --all-features`: unit tests and `tests/token_shapes.rs`.
- A new token shape in `redact` gets a test whose made-up token is built at run time (write the `-` after a vendor prefix as `\x2d`), never a literal that looks real.

## Do not
- Weaken a redaction pattern without a test showing what it still catches.
- Change the chain encoding without an ADR and a migration.
