use openmoat_audit::{BreakKind, EventId, NewEvent};
use openmoat_core::{Decision, Verdict};

use super::*;

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    // Not `.moat`: a sandbox the tests may run in refuses writes to one.
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    (dir, home)
}

fn record(store: &Store) -> Result<EventId, openmoat_audit::StoreError> {
    let decision = Decision::single(Verdict::Allow, "dev-shell", "ok");
    store.record(&NewEvent {
        host: "claude-code",
        session_id: "s1",
        call_id: None,
        cwd: None,
        tool: "Bash",
        action: None,
        decision: &decision,
        latency_us: 1,
    })
}

/// A log of `n` events written through `open`, as `init` and calls leave it.
fn logged(home: &Home, n: usize) {
    open(home).unwrap();
    let store = open_existing(home).unwrap();
    for _ in 0..n {
        record(&store).unwrap();
    }
}

fn files_in(home: &Home) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(home.root())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn init_makes_a_private_key_and_every_event_is_keyed() {
    let (_dir, home) = home();
    logged(&home, 3);
    let key = read(&home).unwrap().unwrap();
    assert_eq!((key.after(), key.after_hash()), (EventId(0), None));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path(&home)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    // No temporary file is left; while it existed it was named `audit.key.*`,
    // which `kernel-self` denies with the key.
    assert!(
        !files_in(&home)
            .iter()
            .any(|n| Path::new(n).extension().is_some_and(|e| e == "tmp")),
        "{:?}",
        files_in(&home)
    );
    // A second writer, and a reader, use the same key.
    record(&open_existing(&home).unwrap()).unwrap();
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!((chain.events, chain.keyed, chain.broken), (4, 4, None));
}

#[test]
fn the_first_writer_after_an_upgrade_makes_a_key_starting_at_the_newest_event() {
    let (_dir, home) = home();
    logged(&home, 2);
    std::fs::remove_file(path(&home)).unwrap();
    openmoat_audit::testing::as_before_version_12(&home.audit_path()).unwrap();
    let store = open_existing(&home).unwrap();
    let key = read(&home).unwrap().unwrap();
    assert_eq!(key.after(), EventId(2));
    assert_eq!(
        key.after_hash().map(str::to_owned),
        store.hash_of(EventId(2)).unwrap()
    );
    record(&store).unwrap();
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!(chain.broken, None);
    assert_eq!((chain.events, chain.keyed), (3, 1));
}

/// The state a writable open beside this module left (the guard's taint cache
/// before the fix): upgraded to keyed events, no key, no keyed event. Writers
/// refuse and name `openmoat init`, which makes the key and keeps the log.
#[test]
fn an_upgrade_that_made_no_key_is_mended_by_init_keeping_the_log() {
    let (_dir, home) = home();
    logged(&home, 2);
    std::fs::remove_file(path(&home)).unwrap();
    openmoat_audit::testing::as_before_version_12(&home.audit_path()).unwrap();
    drop(Store::open_existing(&home.audit_path()).unwrap());
    let refused = format!("{:#}", open_existing(&home).err().unwrap());
    assert!(refused.contains("No event in it is keyed yet"), "{refused}");
    assert!(!path(&home).exists());
    assert_eq!(open(&home).unwrap(), None);
    let store = open_existing(&home).unwrap();
    assert_eq!(read(&home).unwrap().unwrap().after(), EventId(2));
    record(&store).unwrap();
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!((chain.events, chain.keyed, chain.broken), (3, 1, None));
}

#[test]
fn a_missing_key_over_events_refuses_every_write_and_no_writer_makes_one() {
    let (_dir, home) = home();
    logged(&home, 1);
    std::fs::remove_file(path(&home)).unwrap();
    let refused = open_existing(&home).err().unwrap();
    assert!(format!("{refused:#}").contains("is missing"), "{refused:#}");
    assert!(!path(&home).exists());
    assert!(missing_over_events(&home));
    // Read-only, the keyed event cannot be vouched for.
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!(chain.broken.unwrap().kind, BreakKind::KeyUnavailable);
}

/// A database writer strips the MACs, moves version 12's mark past them and
/// deletes the key: the log now looks as if nothing were keyed. No writer
/// makes a new key over it, and `doctor` still says the key is missing.
#[test]
fn stripped_macs_a_moved_mark_and_a_deleted_key_get_no_new_key() {
    let (_dir, home) = home();
    logged(&home, 2);
    openmoat_audit::testing::as_before_the_key(&home.audit_path()).unwrap();
    std::fs::remove_file(path(&home)).unwrap();
    assert!(open_existing(&home).is_err());
    assert!(!path(&home).exists());
    assert!(missing_over_events(&home));
}

#[test]
fn a_key_that_does_not_parse_refuses_every_write() {
    let (_dir, home) = home();
    logged(&home, 0);
    std::fs::remove_file(path(&home)).unwrap();
    crate::home::write_private_new(&path(&home), b"not a key\n").unwrap();
    let refused = open_existing(&home).err().unwrap();
    let text = format!("{refused:#}");
    assert!(text.contains("audit key file is not valid"), "{text}");
}

#[cfg(unix)]
#[test]
fn a_key_others_may_read_is_not_used_and_the_fix_never_removes_it_alone() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, home) = home();
    logged(&home, 1);
    std::fs::set_permissions(path(&home), std::fs::Permissions::from_mode(0o644)).unwrap();
    let refused = format!("{:#}", open_existing(&home).err().unwrap());
    assert!(refused.contains("mode 644"), "{refused}");
    assert!(refused.contains("never remove the key alone"), "{refused}");
    assert!(!refused.contains("remove the file"), "{refused}");
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!(chain.broken.unwrap().kind, BreakKind::KeyUnavailable);
}

#[test]
fn a_log_shorter_than_its_key_refuses_with_the_way_out() {
    let (_dir, home) = home();
    logged(&home, 1);
    let made = ChainKey::new(&[3; 32], EventId(5), Some(&"0".repeat(64)));
    std::fs::remove_file(path(&home)).unwrap();
    crate::home::write_private_new(&path(&home), made.encode().as_bytes()).unwrap();
    let refused = record(&open_existing(&home).unwrap()).err().unwrap();
    assert!(
        matches!(refused, openmoat_audit::StoreError::KeyAhead { .. }),
        "{refused}"
    );
    assert!(
        refused.to_string().contains("run `openmoat init`"),
        "{refused}"
    );
}

#[test]
fn init_on_a_new_log_keeps_the_old_key_beside_it_instead_of_deleting_it() {
    let (_dir, home) = home();
    logged(&home, 2);
    let old = std::fs::read(path(&home)).unwrap();
    // The person moves the log aside as evidence and runs `openmoat init`.
    std::fs::rename(home.audit_path(), home.root().join("evidence.db")).unwrap();
    let kept = open(&home).unwrap().unwrap();
    let name = kept.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("audit.key.") && Path::new(&name).extension().is_some_and(|e| e == "old"),
        "{name}"
    );
    assert_eq!(
        std::fs::read(&kept).unwrap(),
        old,
        "the old key still checks the old log"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&kept).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    assert_ne!(
        std::fs::read(path(&home)).unwrap(),
        old,
        "a new log, a new key"
    );
    record(&open_existing(&home).unwrap()).unwrap();
    // `init` again before any further call keeps the key it made.
    assert!(open(&home).unwrap().is_none());
}

#[test]
fn init_on_an_empty_log_replaces_a_key_made_for_a_longer_one() {
    let (_dir, home) = home();
    logged(&home, 0);
    let made = ChainKey::new(&[3; 32], EventId(5), Some(&"0".repeat(64)));
    std::fs::remove_file(path(&home)).unwrap();
    crate::home::write_private_new(&path(&home), made.encode().as_bytes()).unwrap();
    assert!(open(&home).unwrap().is_some());
    record(&open_existing(&home).unwrap()).unwrap();
    assert_eq!(read(&home).unwrap().unwrap().after(), EventId(0));
}
