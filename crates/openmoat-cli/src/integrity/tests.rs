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
    let (drift, kept) = lock.verify_keeping(std::slice::from_ref(&policy), &[]);
    assert!(drift.is_empty());
    let kept = kept
        .get(&policy)
        .expect("an intact pinned file keeps the bytes it was checked by")
        .to_vec();
    // The file changes after the check: what is parsed is still what matched the pin.
    fs::write(&policy, "version: 1\n").unwrap();
    assert_eq!(kept, pinned.as_bytes());
    let parsed = crate::context::parse_policy(kept, &policy).unwrap();
    assert_eq!(parsed, openmoat_core::Policy::parse(pinned).unwrap());
    // Drifted bytes are never kept.
    let (drift, kept) = lock.verify_keeping(std::slice::from_ref(&policy), &[]);
    assert_eq!(drift.len(), 1);
    assert_eq!(kept.get(&policy), None);
}

#[test]
fn only_the_named_files_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write(dir.path(), "policy.yaml", "version: 1\n");
    let other = dir.path().join("policy.lock");
    let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&policy)).unwrap();
    assert_eq!(lock.verify_keeping(&[], &[]), (Vec::new(), Kept::default()));
    assert_eq!(
        lock.verify_keeping(std::slice::from_ref(&other), &[]),
        (Vec::new(), Kept::default()),
        "a file the lock does not pin is read from disk as before"
    );
}

#[test]
fn the_files_of_a_named_directory_are_kept_under_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let packs = dir.path().join("packs");
    fs::create_dir(&packs).unwrap();
    let pack = write(&packs, "team.yaml", "version: 1\n");
    let elsewhere = write(dir.path(), "team.yaml", "version: 1\n");
    let lock = Lock::pin(Path::new("/x/moat"), &[pack.clone(), elsewhere.clone()]).unwrap();
    let (drift, kept) = lock.verify_keeping(&[], std::slice::from_ref(&packs));
    assert!(drift.is_empty());
    fs::write(&pack, "version: 1\ndeny: []\n").unwrap();
    assert_eq!(kept.get(&pack), Some(b"version: 1\n".as_slice()));
    assert_eq!(
        kept.get(&elsewhere),
        None,
        "only files directly in the directory"
    );
}

/// A person who re-pins over a deleted state file (`openmoat doctor --accept`
/// over "approvals.json is missing") pins its absence: a file planted there
/// later is drift, not trusted unpinned from disk.
#[test]
fn a_state_file_missing_at_a_re_pin_cannot_be_planted_later() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    write_private(&home.policy_path(), b"version: 1\n").unwrap();
    let binary = Path::new("/x/moat");
    Lock::pin(binary, &[home.policy_path()])
        .unwrap()
        .save(&home.lock_path())
        .unwrap();
    let lock = repin(&home, binary, HookPins::Keep).unwrap();
    assert!(lock.verify().is_empty(), "{:?}", lock.verify());
    let planted = [
        (home.grants_path(), r#"{"version":2,"entries":[]}"#),
        (home.overlay_path(), "version: 1\nallow: []\n"),
        (home.hosts_path(), r#"{"version":1,"dirs":{}}"#),
        (
            home.environment_path(),
            r#"{"version":1,"captured_at_ms":1,"path":["/x"],"programs":{}}"#,
        ),
    ];
    for (path, text) in planted {
        write_private(&path, text.as_bytes()).unwrap();
        assert!(
            lock.verify()
                .iter()
                .any(|d| matches!(d, Drift::Modified(p) if p.ends_with(path.file_name().unwrap()))),
            "{} was planted after the re-pin",
            path.display()
        );
        fs::remove_file(&path).unwrap();
    }
    // Missing as pinned is no drift (`policy.d`, created above, stays).
    fs::remove_dir(home.overlay_path().parent().unwrap()).unwrap();
    let (drift, kept) = verify_state(&home, &lock);
    assert!(drift.is_empty(), "{drift:?}");
    assert!(
        crate::approvals::Grants::load_in(&kept)
            .unwrap()
            .entries
            .is_empty()
    );
}

/// The guidance for a hook file pinned elsewhere names every host's
/// directory variable, not only the first hosts'.
#[test]
fn a_hook_pinned_elsewhere_names_every_hosts_variable() {
    let moved = HookPinGap::moved_by();
    for variable in [
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "CURSOR_CONFIG_DIR",
        "COPILOT_HOME",
        "PI_CODING_AGENT_DIR",
        "GEMINI_CLI_HOME",
    ] {
        assert!(moved.contains(variable), "{moved}");
    }
}
