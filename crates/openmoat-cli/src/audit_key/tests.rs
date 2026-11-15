use openmoat_audit::{BreakKind, NewEvent};
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

#[test]
fn init_makes_a_private_key_and_every_event_is_keyed() {
    let (_dir, home) = home();
    let store = open(&home).unwrap();
    for _ in 0..3 {
        record(&store).unwrap();
    }
    let key = read(&home).unwrap().unwrap();
    assert_eq!(key.after(), EventId(0));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path(&home)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    // A second writer, and a reader, use the same key.
    record(&open_existing(&home).unwrap()).unwrap();
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!((chain.events, chain.keyed, chain.broken), (4, 4, None));
}

#[test]
fn a_log_from_before_the_key_gets_one_that_starts_after_its_events() {
    let (_dir, home) = home();
    {
        let store = open(&home).unwrap();
        record(&store).unwrap();
        record(&store).unwrap();
    }
    // As if both were written before the upgrade: no key, and the mark of
    // version 12 after them.
    std::fs::remove_file(path(&home)).unwrap();
    openmoat_audit::testing::as_before_the_key(&home.audit_path()).unwrap();
    let store = open_existing(&home).unwrap();
    assert_eq!(read(&home).unwrap().unwrap().after(), EventId(2));
    record(&store).unwrap();
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!(chain.broken, None);
    assert_eq!((chain.events, chain.keyed), (3, 1));
    assert_eq!(chain.keyed_after, Some(EventId(2)));
}

#[test]
fn a_missing_key_with_keyed_events_refuses_every_write_and_no_new_key_is_made() {
    let (_dir, home) = home();
    record(&open(&home).unwrap()).unwrap();
    std::fs::remove_file(path(&home)).unwrap();
    let refused = open_existing(&home).err().unwrap();
    assert!(format!("{refused:#}").contains("is missing"), "{refused:#}");
    assert!(!path(&home).exists());
    // Read-only, the keyed event cannot be vouched for.
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!(chain.broken.unwrap().kind, BreakKind::KeyUnavailable);
}

#[test]
fn a_key_that_does_not_parse_refuses_every_write() {
    let (_dir, home) = home();
    drop(open(&home).unwrap());
    std::fs::remove_file(path(&home)).unwrap();
    crate::home::write_private_new(&path(&home), b"not a key\n").unwrap();
    let refused = open_existing(&home).err().unwrap();
    let text = format!("{refused:#}");
    assert!(text.contains("audit key file is not valid"), "{text}");
}

#[cfg(unix)]
#[test]
fn a_key_others_may_read_is_not_used() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, home) = home();
    record(&open(&home).unwrap()).unwrap();
    std::fs::set_permissions(path(&home), std::fs::Permissions::from_mode(0o644)).unwrap();
    let refused = open_existing(&home).err().unwrap();
    assert!(format!("{refused:#}").contains("mode 644"), "{refused:#}");
    let chain = home.open_audit().unwrap().verify_chain().unwrap();
    assert_eq!(chain.broken.unwrap().kind, BreakKind::KeyUnavailable);
}

#[test]
fn a_log_shorter_than_its_key_refuses_and_init_on_a_new_log_starts_a_new_key() {
    let (_dir, home) = home();
    {
        let store = open(&home).unwrap();
        record(&store).unwrap();
    }
    // The key was made when the log reached event 5, and the log now ends at 1.
    let made = ChainKey::new([3; 32], EventId(5));
    std::fs::remove_file(path(&home)).unwrap();
    crate::home::write_private_new(&path(&home), made.encode().as_bytes()).unwrap();
    let refused = record(&open_existing(&home).unwrap()).err().unwrap();
    assert!(
        matches!(refused, openmoat_audit::StoreError::KeyAhead { .. }),
        "{refused}"
    );
    // The person moves the log aside and runs `openmoat init`.
    std::fs::rename(home.audit_path(), home.root().join("audit.db.kept")).unwrap();
    let store = open(&home).unwrap();
    record(&store).unwrap();
    assert_eq!(read(&home).unwrap().unwrap().after(), EventId(0));
}
