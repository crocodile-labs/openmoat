use openmoat_audit::{CheckpointCheck, NewEvent};
use openmoat_core::{Decision, Verdict};

use super::*;

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    // Not `.moat`: a sandbox the tests may run in refuses writes to one.
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    (dir, home)
}

fn record(store: &Store) -> EventId {
    let decision = Decision::single(Verdict::Allow, "dev-shell", "ok");
    store
        .record(&NewEvent {
            host: "claude-code",
            session_id: "s1",
            call_id: None,
            cwd: None,
            tool: "Bash",
            action: None,
            decision: &decision,
            latency_us: 1,
        })
        .unwrap()
}

fn logged(home: &Home, n: usize) -> Store {
    crate::audit_key::open(home).unwrap();
    let store = crate::audit_key::open_existing(home).unwrap();
    for _ in 0..n {
        record(&store);
    }
    store
}

#[test]
fn the_key_is_private_named_under_the_audit_key_and_made_once() {
    let (_dir, home) = home();
    assert!(read(&home).unwrap().is_none());
    let (key, is_new) = ensure(&home).unwrap();
    assert!(is_new);
    let (again, is_new) = ensure(&home).unwrap();
    assert!(!is_new);
    assert_eq!(key.verifier(), again.verifier());
    // `kernel-self` denies `audit.key*`: the key, its temporary file, kept keys.
    assert!(KEY_FILE.starts_with(crate::audit_key::KEY_FILE));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path(&home)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    std::fs::write(path(&home), "not a key\n").unwrap();
    let error = format!("{:#}", read(&home).unwrap_err());
    assert!(
        error.contains(KEY_FILE) && !error.contains("not a key"),
        "{error}"
    );
}

#[test]
fn a_checkpoint_signed_now_holds_and_is_found_as_the_newest() {
    let (_dir, home) = home();
    let store = logged(&home, 5);
    let (key, _) = ensure(&home).unwrap();
    let written = sign_now(&home, &store, &key).unwrap();
    assert_eq!(written.checkpoint.size, 5);
    let (path, note) = latest(&home, key.verifier()).unwrap();
    assert_eq!(path, written.path);
    let opened = Checkpoint::open(&note, key.verifier()).unwrap();
    assert_eq!(
        store.check_checkpoint(&opened).unwrap(),
        CheckpointCheck::Holds { size: 5, total: 5 }
    );
}

#[test]
fn the_guard_signs_every_thousandth_event_from_the_saved_frontier() {
    let (_dir, home) = home();
    let store = logged(&home, 3);
    // No key: nothing, and the log records on (an install from before ADR-110).
    periodic(&home, &store, EventId(EVERY));
    assert!(!dir(&home).exists());
    let (key, _) = ensure(&home).unwrap();
    sign_now(&home, &store, &key).unwrap();
    record(&store);
    // Not at a multiple of `EVERY`: the newest is still the one of 3 events.
    periodic(&home, &store, EventId(4));
    let (_, note) = latest(&home, key.verifier()).unwrap();
    assert_eq!(Checkpoint::open(&note, key.verifier()).unwrap().size, 3);
    // At one, from the saved frontier: 4 events, as a full read finds.
    periodic(&home, &store, EventId(EVERY));
    let (_, note) = latest(&home, key.verifier()).unwrap();
    let newest = Checkpoint::open(&note, key.verifier()).unwrap();
    assert_eq!(newest.size, 4);
    assert_eq!(newest.root, store.frontier().unwrap().root());
}

#[test]
fn a_rotated_key_is_kept_and_its_checkpoints_still_verify() {
    let (_dir, home) = home();
    let store = logged(&home, 4);
    let (old, _) = ensure(&home).unwrap();
    let before = sign_now(&home, &store, &old).unwrap();
    let (new, kept) = rotate(&home).unwrap();
    let kept = kept.unwrap();
    assert!(
        kept.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(crate::audit_key::KEY_FILE)
    );
    assert_ne!(old.verifier(), new.verifier());
    assert_eq!(read(&home).unwrap().unwrap().verifier(), new.verifier());
    let after = sign_now(&home, &store, &new).unwrap();
    // Each opens with its own public key only; both state the same log.
    assert!(Checkpoint::open(&before.note, old.verifier()).is_ok());
    assert!(Checkpoint::open(&before.note, new.verifier()).is_err());
    let opened = Checkpoint::open(&after.note, new.verifier()).unwrap();
    assert_eq!(opened.root, before.checkpoint.root);
    assert_ne!(before.path, after.path);
}
