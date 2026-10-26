use super::*;

#[test]
fn round_trips_and_refuses_other_versions() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().to_path_buf());
    assert_eq!(Recorded::load(&home).unwrap(), Recorded::default());
    let mut recorded = Recorded::default();
    recorded
        .dirs
        .insert("codex".into(), PathBuf::from("/cfg/codex"));
    recorded.save(&home).unwrap();
    let loaded = Recorded::load(&home).unwrap();
    assert_eq!(loaded.dir(Host::Codex), Some(PathBuf::from("/cfg/codex")));
    assert_eq!(loaded.dir(Host::ClaudeCode), None);
    assert!(!loaded.owns(Path::new("/cfg/claude/settings.json.moat-backup")));
    fs::write(home.hosts_path(), r#"{"version":7,"dirs":{}}"#).unwrap();
    assert!(Recorded::load(&home).is_err());
}

#[test]
fn skips_only_hosts_left_out_of_a_non_empty_record() {
    let mut recorded = Recorded::default();
    assert!(!recorded.skipped(Host::Codex));
    recorded
        .dirs
        .insert("claude-code".into(), PathBuf::from("/cfg/claude"));
    assert!(recorded.skipped(Host::Codex));
    assert!(!recorded.skipped(Host::ClaudeCode));
}

/// Hermes Agent's profiles are directories laid out like its home; a file in
/// `profiles/` is none, and the record keeps them and says nothing of hosts
/// that have none.
#[test]
fn hermes_profiles_are_found_and_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let hermes = dir.path().join("hermes");
    fs::create_dir_all(hermes.join("profiles/work")).unwrap();
    fs::create_dir_all(hermes.join("profiles/play")).unwrap();
    fs::write(hermes.join("profiles/notes.txt"), "x").unwrap();
    let found = also_dirs(Host::Hermes, &hermes);
    assert_eq!(
        found,
        [hermes.join("profiles/play"), hermes.join("profiles/work")]
    );
    assert!(also_dirs(Host::Hermes, &dir.path().join("none")).is_empty());
    assert!(also_dirs(Host::Codex, &hermes).is_empty());

    let state = Home::at(dir.path().join("state"));
    let mut recorded = Recorded::default();
    recorded.also.insert("hermes".into(), found.clone());
    recorded.save(&state).unwrap();
    let loaded = Recorded::load(&state).unwrap();
    assert_eq!(loaded.also(Host::Hermes), found.as_slice());
    assert!(loaded.also(Host::Codex).is_empty());
    // A record without them reads as before, and is written as before.
    let text = r#"{"version":1,"dirs":{"codex":"/cfg/codex"}}"#;
    let old = Recorded::parse(text, Path::new("hosts.json")).unwrap();
    assert!(old.also.is_empty());
    assert!(!serde_json::to_string(&old).unwrap().contains("also"));
}
