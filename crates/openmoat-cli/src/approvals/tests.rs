use super::*;

fn sh(command: &str) -> Action {
    approvable(
        &Action::Shell {
            command: command.to_owned(),
        },
        None,
        "/h",
    )
    .unwrap()
}

#[test]
fn overlay_ids_stay_unique_after_a_deletion() {
    let mut o = Overlay::default();
    for c in ["a", "b", "c"] {
        o.allow_command(c).unwrap();
    }
    o.allow.remove(0);
    assert_eq!(o.allow_command("d").unwrap().id, "approved-4");
    let ids: std::collections::BTreeSet<_> = o.allow.iter().map(|g| &g.id).collect();
    assert_eq!(ids.len(), o.allow.len());
}

#[test]
fn sites_dirs_and_removal() {
    let mut o = Overlay::default();
    assert_eq!(o.allow_site(" Docs.RS. ").unwrap().net, ["docs.rs"]);
    for bad in [
        "*",
        "*.example.com",
        "https://x.dev",
        "x.dev:443",
        "",
        "a..b",
        "::1",
    ] {
        let error = o.allow_site(bad).unwrap_err().to_string();
        assert!(error.contains("in the policy"), "{bad}: {error}");
    }
    let dir = o.allow_dir(&["/w/a".to_owned(), "/real/a".to_owned()]);
    assert_eq!(dir.id, "approved-2");
    assert_eq!(dir.fs_read, ["/w/a", "/w/a/**", "/real/a", "/real/a/**"]);
    assert_eq!(
        dir.fs_write[..4],
        ["/w/a", "/w/a/**", "/real/a", "/real/a/**"]
    );
    for left_out in [
        "!/w/a/.git/**",
        "!/w/a/**/.git/**",
        "!/real/a/**/.git/**",
        "!/w/a/**/.github/workflows/**",
        "!/real/a/**/.husky/**",
        "!/w/a/**/.vscode/tasks.json",
    ] {
        assert!(
            dir.fs_write.iter().any(|p| p == left_out),
            "{left_out}: `.git` and files run later are left out, as for the project"
        );
    }
    assert_eq!(o.remove("approved-1").unwrap().net, ["docs.rs"]);
    assert!(o.remove("approved-1").is_none());
    assert_eq!(o.allow.len(), 1);
}

/// 2026-10-03 00:00:00 UTC; tests pass time in, they never read the clock.
const NOW: i64 = 1_790_985_600_000;

#[test]
fn grants_match_exactly_per_host_session() {
    let mut g = Grants::default();
    g.grant(
        "claude-code",
        "s1",
        &sh(" npm install left-pad "),
        NOW,
        None,
    );
    g.grant("claude-code", "s1", &sh("npm install left-pad"), NOW, None);
    assert_eq!(g.entries.len(), 1, "duplicates collapse");
    assert!(g.matches("claude-code", "s1", &sh("npm install left-pad"), NOW));
    assert!(!g.matches("claude-code", "s2", &sh("npm install left-pad"), NOW));
    assert!(!g.matches("cursor", "s1", &sh("npm install left-pad"), NOW));
    assert!(!g.matches("claude-code", "s1", &sh("npm install left-pad --save"), NOW));
}

#[test]
fn a_call_without_a_session_id_matches_no_grant() {
    // Every call a host sends without a session id is recorded as "unknown";
    // a grant for that id would hold in all of them. A grants file that has
    // one anyway (written by hand, or by an older moat) must not apply.
    let mut g = Grants::default();
    g.grant("cursor", "unknown", &sh("npm install left-pad"), NOW, None);
    g.grant("cursor", "", &sh("npm install left-pad"), NOW, None);
    assert!(!g.matches("cursor", "unknown", &sh("npm install left-pad"), NOW));
    assert!(!g.matches("cursor", "", &sh("npm install left-pad"), NOW));
}

#[test]
fn a_grant_says_when_it_was_made() {
    let mut g = Grants::default();
    g.grant("claude-code", "s1", &sh("make"), NOW, None);
    assert_eq!(
        g.granted_at("claude-code", "s1", &sh("make"), NOW + 1),
        Some(NOW)
    );
    g.grant("claude-code", "s1", &sh("make"), NOW + 5, None);
    assert_eq!(
        g.granted_at("claude-code", "s1", &sh("make"), NOW + 6),
        Some(NOW + 5)
    );
    assert_eq!(
        g.granted_at("claude-code", "s2", &sh("make"), NOW + 6),
        None
    );
    assert_eq!(
        g.granted_at("claude-code", "unknown", &sh("make"), NOW + 6),
        None
    );
}

#[test]
fn grants_expire_after_the_ttl() {
    let mut g = Grants::default();
    g.grant("codex", "k1", &sh("cargo add serde"), NOW, None);
    let ok = |g: &Grants, at| g.matches("codex", "k1", &sh("cargo add serde"), at);
    assert!(ok(&g, NOW + GRANT_TTL_MS - 1));
    assert!(!ok(&g, NOW + GRANT_TTL_MS), "expired at the TTL");
    assert!(!ok(&g, NOW - 1), "a grant from the future is not valid");

    g.grant(
        "codex",
        "k1",
        &sh("cargo add serde"),
        NOW + GRANT_TTL_MS,
        None,
    );
    assert_eq!(g.entries.len(), 1);
    assert!(ok(&g, NOW + GRANT_TTL_MS + 1), "granting again restarts it");
}

#[test]
fn version_1_grants_migrate_and_one_without_a_timestamp_is_expired() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals.json");
    let v1 = format!(
        r#"{{"version":1,"entries":[{{"host":"codex","session_id":"k1","command":"ls"}},
        {{"host":"codex","session_id":"k2","command":" ls ","granted_at_ms":{NOW}}}]}}"#
    );
    fs::write(&path, v1).unwrap();
    let g = Grants::load(&path).unwrap();
    assert_eq!(g.version, 2);
    assert_eq!(g.entries[0].granted_at_ms, 0);
    assert!(!g.matches("codex", "k1", &sh("ls"), NOW));
    assert!(g.matches("codex", "k2", &sh("ls"), NOW));
    fs::write(&path, r#"{"version":3,"entries":[]}"#).unwrap();
    assert!(Grants::load(&path).is_err(), "a newer file is refused");
}

#[test]
fn the_audit_row_a_grant_saw_is_kept_and_an_old_grant_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals.json");
    let mut g = Grants::default();
    g.grant("codex", "k1", &sh("ls"), NOW, Some(42));
    g.grant("codex", "k2", &sh("ls"), NOW, None);
    g.save(&path, NOW).unwrap();
    let g = Grants::load(&path).unwrap();
    let row = |s| g.newest("codex", s, &sh("ls"), NOW).unwrap().audit_row;
    assert_eq!(row("k1"), Some(42));
    assert_eq!(row("k2"), None);
}

#[test]
fn saving_prunes_expired_grants() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals.json");
    let mut g = Grants::default();
    g.grant("codex", "old", &sh("ls"), NOW - GRANT_TTL_MS, None);
    g.grant("codex", "new", &sh("ls"), NOW - 1, None);
    assert_eq!(g.active(NOW).count(), 1);
    g.save(&path, NOW).unwrap();
    let loaded = Grants::load(&path).unwrap();
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].session_id, "new");
}

#[test]
fn grants_and_overlay_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let grants_path = dir.path().join("approvals.json");
    let mut g = Grants::default();
    g.grant("codex", "k1", &sh("cargo add serde"), NOW, None);
    g.save(&grants_path, NOW).unwrap();
    assert_eq!(Grants::load(&grants_path).unwrap(), g);
    assert_eq!(
        Grants::load(&dir.path().join("missing.json")).unwrap(),
        Grants::default()
    );

    let overlay_path = dir.path().join("approved.yaml");
    let mut o = Overlay::default();
    assert_eq!(
        o.allow_command("npm install left-pad").unwrap().id,
        "approved-1"
    );
    assert_eq!(
        o.allow_command("pip install requests").unwrap().id,
        "approved-2"
    );
    o.save(&overlay_path).unwrap();
    let loaded = Overlay::load(&overlay_path).unwrap();
    assert_eq!(loaded.allow.len(), 2);
    assert_eq!(loaded.allow[1].shell, ["pip install requests"]);
    assert!(
        loaded.allow[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("moat allow --always")
    );

    fs::write(
        &overlay_path,
        "version: 1\nallow:\n  - id: sneaky\n    shell: ['*']\n",
    )
    .unwrap();
    assert!(
        Overlay::load(&overlay_path)
            .unwrap_err()
            .to_string()
            .contains("approved-")
    );
}
