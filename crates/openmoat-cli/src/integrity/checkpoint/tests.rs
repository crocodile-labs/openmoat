//! A pinned file changed while a person's command waited for its answer is
//! never re-pinned unseen; the command's own files are.

use std::path::Path;

use super::*;
use crate::home::write_private;

const POLICY: &str = "version: 1\ndefaults: { '*': defer }\n";

/// A state directory with a policy and a grants file, both pinned.
fn pinned(dir: &Path) -> Home {
    let home = Home::at(dir.join("state"));
    write_private(&home.policy_path(), POLICY.as_bytes()).unwrap();
    write_private(&home.grants_path(), b"{\"version\":1,\"grants\":[]}\n").unwrap();
    let lock = Lock::pin(Path::new("/x/moat"), &super::super::state_files(&home)).unwrap();
    lock.save(&home.lock_path()).unwrap();
    home
}

#[test]
fn an_untouched_lock_verifies_and_re_pins() {
    let dir = tempfile::tempdir().unwrap();
    let home = pinned(dir.path());
    let checkpoint = Checkpoint::take(&home).unwrap();
    checkpoint.verify(&home, &[]).unwrap();
    // What the command writes itself is re-pinned.
    write_private(&home.grants_path(), b"{\"version\":1,\"grants\":[1]}\n").unwrap();
    let written = [home.grants_path()];
    let lock = repin_after(
        &home,
        Path::new("/x/moat"),
        HookPins::Keep,
        &checkpoint,
        &written,
    )
    .unwrap();
    assert_eq!(lock.verify(), Vec::<Drift>::new());
}

#[test]
fn a_pinned_file_changed_during_the_question_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = pinned(dir.path());
    let checkpoint = Checkpoint::take(&home).unwrap();
    // Something other than the command rewrites the policy while the person reads.
    write_private(&home.policy_path(), b"version: 1\ndefaults: allow\n").unwrap();
    let error = checkpoint.verify(&home, &[]).unwrap_err().to_string();
    assert!(error.contains("while OpenMoat waited"), "{error}");
    assert!(error.contains("policy.yaml"), "{error}");
    // The command's own files do not excuse another file.
    let written = [home.grants_path()];
    let refused = repin_after(
        &home,
        Path::new("/x/moat"),
        HookPins::Keep,
        &checkpoint,
        &written,
    );
    assert!(refused.is_err());
    // Nothing was re-pinned: the lock still shows the change as drift.
    let lock = Lock::load(&home.lock_path()).unwrap();
    assert_eq!(lock.verify().len(), 1);
}

#[test]
fn a_lock_re_pinned_during_the_question_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = pinned(dir.path());
    let checkpoint = Checkpoint::take(&home).unwrap();
    // The policy changed and a lock pinning the change put in place: on disk
    // nothing drifts, but it is not the lock that was checked.
    write_private(&home.policy_path(), b"version: 1\ndefaults: allow\n").unwrap();
    let forged = Lock::pin(Path::new("/x/moat"), &super::super::state_files(&home)).unwrap();
    forged.save(&home.lock_path()).unwrap();
    assert_eq!(forged.verify(), Vec::<Drift>::new());
    let error = checkpoint.verify(&home, &[]).unwrap_err().to_string();
    assert!(error.contains("no longer pins what was checked"), "{error}");
}

#[test]
fn without_a_lock_there_is_nothing_to_keep() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    write_private(&home.policy_path(), POLICY.as_bytes()).unwrap();
    let checkpoint = Checkpoint::take(&home).unwrap();
    checkpoint.verify(&home, &[]).unwrap();
}
