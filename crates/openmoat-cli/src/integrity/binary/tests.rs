use super::*;
use crate::integrity::Lock;

/// A lock naming the running test binary, with its digest and this release.
fn lock_for_this_binary() -> (Lock, PathBuf) {
    let exe = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let mut lock = Lock::pin(&exe, &[]).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let (digest, version) = record(&Home::at(scratch.path().to_path_buf()), &exe).unwrap();
    lock.binary_sha256 = Some(digest);
    lock.binary_version = Some(version);
    (lock, exe)
}

#[test]
fn the_recorded_binary_is_the_same_and_its_digest_is_cached() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().to_path_buf());
    let (lock, _) = lock_for_this_binary();
    assert_eq!(check(&home, &lock), SelfCheck::Same);
    let cache = dir.path().join(CACHE_FILE);
    let kept: Cached = serde_json::from_slice(&fs::read(&cache).unwrap()).unwrap();
    assert_eq!(Some(&kept.sha256), lock.binary_sha256.as_ref());
    // A second call reads the cache, so a cache that claims another digest for
    // a file that still looks the same is what the check compares.
    let forged = Cached {
        sha256: "0".repeat(64),
        ..kept
    };
    fs::write(&cache, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(matches!(check(&home, &lock), SelfCheck::Changed { .. }));
}

#[test]
fn other_bytes_of_the_same_release_deny_and_an_upgrade_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().to_path_buf());
    let (mut lock, exe) = lock_for_this_binary();
    lock.binary_sha256 = Some("f".repeat(64));
    let changed = check(&home, &lock);
    assert_eq!(changed, SelfCheck::Changed { path: exe });
    assert!(changed.deny_reason().unwrap().contains("openmoat init"));

    lock.binary_version = Some("0.0.1".to_owned());
    let upgraded = check(&home, &lock);
    assert_eq!(
        upgraded,
        SelfCheck::Upgraded {
            recorded: "0.0.1".to_owned()
        }
    );
    assert_eq!(upgraded.deny_reason(), None);
    assert!(upgraded.note().unwrap().contains("openmoat init"));
}

#[test]
fn an_old_lock_or_another_file_is_not_judged() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().to_path_buf());
    let (mut lock, _) = lock_for_this_binary();
    let other = dir.path().join("openmoat");
    fs::write(&other, b"another file").unwrap();
    lock.binary = other.to_string_lossy().into_owned();
    assert_eq!(check(&home, &lock), SelfCheck::OtherFile);
    lock.binary_sha256 = None;
    assert_eq!(check(&home, &lock), SelfCheck::NotRecorded);
    assert_eq!(SelfCheck::NotRecorded.deny_reason(), None);
}

#[test]
fn a_file_that_changes_is_hashed_again() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join(CACHE_FILE);
    let file = dir.path().join("bin");
    fs::write(&file, b"one").unwrap();
    let first = cached_digest(&cache, &file).unwrap();
    assert_eq!(first, crate::integrity::sha256_hex(b"one"));
    fs::write(&file, b"two!").unwrap();
    let second = cached_digest(&cache, &file).unwrap();
    assert_eq!(second, crate::integrity::sha256_hex(b"two!"));
}
