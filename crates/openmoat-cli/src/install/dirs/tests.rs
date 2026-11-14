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
    assert_eq!(
        also_dirs(Host::Hermes, &dir.path().join("none")),
        Vec::<PathBuf>::new()
    );
    assert_eq!(also_dirs(Host::Codex, &hermes), Vec::<PathBuf>::new());

    let state = Home::at(dir.path().join("state"));
    let mut recorded = Recorded::default();
    recorded.also.insert("hermes".into(), found.clone());
    recorded.save(&state).unwrap();
    let loaded = Recorded::load(&state).unwrap();
    assert_eq!(loaded.also(Host::Hermes), found.as_slice());
    assert_eq!(loaded.also(Host::Codex), Vec::<PathBuf>::new());
    // A record without them reads as before, and is written as before.
    let text = r#"{"version":1,"dirs":{"codex":"/cfg/codex"}}"#;
    let old = Recorded::parse(text, Path::new("hosts.json")).unwrap();
    assert!(old.also.is_empty());
    assert!(!serde_json::to_string(&old).unwrap().contains("also"));
}

/// The rules OpenMoat wrote belong to the host whose sandbox writes them into
/// its hook file, and to no other: a host whose relaxed keys keep written
/// rules finds none of another host's.
#[test]
fn written_rules_are_the_writing_hosts_only() {
    let recorded = Recorded {
        claude_rules: vec!["Read(//**/.ssh/**)".to_owned()],
        ..Recorded::default()
    };
    let writes = |host: Host| {
        let spec = host.spec();
        spec.sandbox.as_ref().is_some_and(|s| {
            s.format == SandboxFormat::ClaudeSettings
                && spec
                    .install
                    .as_ref()
                    .is_some_and(|i| i.config_file == s.file)
        })
    };
    assert_eq!(Host::ALL.into_iter().filter(|h| writes(*h)).count(), 1);
    for host in Host::ALL {
        let expected: &[String] = if writes(host) {
            &recorded.claude_rules
        } else {
            &[]
        };
        assert_eq!(recorded.written_rules(host), expected, "{host:?}");
    }
}
