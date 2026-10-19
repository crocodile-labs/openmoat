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
