//! Database shells: the database file and the files their SQL names are writes,
//! reads only under `-readonly`.

use super::*;

#[test]
fn database_files_are_writes() {
    let atoms = parsed("sqlite3 -batch -cmd 'pragma x=1' dev.db 'delete from t'");
    assert!(has_write(&atoms, "/p/dev.db") && !has_read(&atoms, "/p/dev.db"));
    let atoms = parsed("sqlite3 :memory: \"attach 'other.db' as o; vacuum into './copy.db'\"");
    assert!(has_write(&atoms, "/p/copy.db"));
    assert!(
        !atoms
            .iter()
            .any(|a| matches!(a, AtomicAction::FsWrite { path } if path.ends_with(":memory:")))
    );
    assert!(has_write(
        &parsed("duckdb --init setup.sql data.duckdb"),
        "/p/data.duckdb"
    ));
    assert!(has_read(
        &parsed("duckdb -init setup.sql x.duckdb"),
        "/p/setup.sql"
    ));
}

#[test]
fn stdin_the_line_shows_is_sql() {
    let atoms = parsed("echo '.backup /tmp/b.db' | sqlite3 dev.db");
    assert!(has_write(&atoms, "/tmp/b.db") && has_write(&atoms, "/p/dev.db"));
}

#[test]
fn readonly_opens_for_reading() {
    let atoms = parsed("sqlite3 -readonly dev.db \"attach '/tmp/o.db' as o\"");
    assert!(has_read(&atoms, "/p/dev.db") && has_read(&atoms, "/tmp/o.db"));
    assert!(
        !atoms
            .iter()
            .any(|a| matches!(a, AtomicAction::FsWrite { .. }))
    );
}
