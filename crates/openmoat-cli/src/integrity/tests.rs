use super::*;

fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn pin_verify_and_detect_drift() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write(dir.path(), "policy.yaml", "version: 1\n");
    let hook = write(dir.path(), "settings.json", "{}");
    let absent = dir.path().join("never-written.json");

    let lock = Lock::pin(
        Path::new("/x/moat"),
        &[policy.clone(), hook.clone(), absent],
    )
    .unwrap();
    assert_eq!(lock.entries.len(), 2, "absent files are not pinned");
    assert!(lock.entries.keys().any(|k| k.ends_with("policy.yaml")));
    assert!(lock.verify().is_empty());

    fs::write(&policy, "version: 1\nallow: []\n").unwrap();
    fs::remove_file(&hook).unwrap();
    let drift = lock.verify();
    assert_eq!(drift.len(), 2);
    assert!(
        drift
            .iter()
            .any(|d| matches!(d, Drift::Modified(p) if p.ends_with("policy.yaml")))
    );
    assert!(
        drift
            .iter()
            .any(|d| matches!(d, Drift::Missing(p) if p.ends_with("settings.json")))
    );
}

#[cfg(unix)]
#[test]
fn replacing_a_pinned_file_with_a_symlink_is_drift() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write(dir.path(), "policy.yaml", "version: 1\n");
    let other = write(dir.path(), "other.yaml", "version: 1\n");
    let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&policy)).unwrap();

    fs::remove_file(&policy).unwrap();
    std::os::unix::fs::symlink(&other, &policy).unwrap();
    assert!(lock.pins(&policy), "a symlinked leaf keeps its identity");
    assert!(
        matches!(lock.verify_one(&policy), Some(Drift::Modified(p)) if p.ends_with("policy.yaml")),
        "same bytes through a link must still count as modified"
    );

    fs::remove_file(&policy).unwrap();
    assert!(matches!(lock.verify_one(&policy), Some(Drift::Missing(_))));
}

#[test]
fn round_trips_through_disk_and_rejects_other_versions() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write(dir.path(), "policy.yaml", "version: 1\n");
    let lock_path = dir.path().join("policy.lock");
    let lock = Lock::pin(Path::new("/x/moat"), &[policy]).unwrap();
    lock.save(&lock_path).unwrap();
    assert_eq!(Lock::load(&lock_path).unwrap(), lock);

    fs::write(
        &lock_path,
        r#"{"version":9,"pinned_at_ms":0,"binary":"","entries":{}}"#,
    )
    .unwrap();
    assert!(
        Lock::load(&lock_path)
            .unwrap_err()
            .to_string()
            .contains("version 9")
    );
}

#[test]
fn the_policy_bytes_checked_are_the_bytes_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let pinned = openmoat_core::DEFAULT_POLICY;
    let policy = write(dir.path(), "policy.yaml", pinned);
    let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&policy)).unwrap();
    let (drift, kept) = lock.verify_keeping(Some(&policy));
    assert!(drift.is_empty());
    let kept = kept.expect("an intact pinned file keeps the bytes it was checked by");
    // The file changes after the check: what is parsed is still what matched the pin.
    fs::write(&policy, "version: 1\n").unwrap();
    assert_eq!(kept, pinned.as_bytes());
    let parsed = crate::context::parse_policy(kept, &policy).unwrap();
    assert_eq!(parsed, openmoat_core::Policy::parse(pinned).unwrap());
    // Drifted bytes are never kept.
    let (drift, kept) = lock.verify_keeping(Some(&policy));
    assert_eq!(drift.len(), 1);
    assert!(kept.is_none());
}

#[test]
fn only_the_named_file_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write(dir.path(), "policy.yaml", "version: 1\n");
    let other = dir.path().join("policy.lock");
    let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&policy)).unwrap();
    assert_eq!(lock.verify_keeping(None), (Vec::new(), None));
    assert_eq!(lock.verify_keeping(Some(&other)), (Vec::new(), None));
}
