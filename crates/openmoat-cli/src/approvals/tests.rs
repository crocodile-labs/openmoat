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

/// The project every call of these tests is in.
const PROJECT: &str = "/p";

/// A host session in [`PROJECT`].
fn at<'a>(host: &'a str, session_id: &'a str) -> Scope<'a> {
    Scope {
        host,
        session_id,
        project: PROJECT,
    }
}

#[test]
fn grants_match_exactly_per_host_session() {
    let mut g = Grants::default();
    g.grant(
        at("claude-code", "s1"),
        &sh(" npm install left-pad "),
        NOW,
        None,
    );
    g.grant(
        at("claude-code", "s1"),
        &sh("npm install left-pad"),
        NOW,
        None,
    );
    assert_eq!(g.entries.len(), 1, "duplicates collapse");
    assert!(g.matches(at("claude-code", "s1"), &sh("npm install left-pad"), NOW));
    assert!(!g.matches(at("claude-code", "s2"), &sh("npm install left-pad"), NOW));
    assert!(!g.matches(at("cursor", "s1"), &sh("npm install left-pad"), NOW));
    assert!(!g.matches(
        at("claude-code", "s1"),
        &sh("npm install left-pad --save"),
        NOW
    ));
}

#[test]
fn a_shell_grant_applies_only_in_the_project_it_was_approved_in() {
    let mut g = Grants::default();
    g.grant(at("claude-code", "s1"), &sh("make"), NOW, None);
    let elsewhere = Scope {
        project: "/other",
        ..at("claude-code", "s1")
    };
    assert!(g.matches(at("claude-code", "s1"), &sh("make"), NOW));
    assert!(!g.matches(elsewhere, &sh("make"), NOW), "another project");

    // Approving it in the other project too keeps both.
    g.grant(elsewhere, &sh("make"), NOW, None);
    assert_eq!(g.entries.len(), 2);
    assert!(g.matches(at("claude-code", "s1"), &sh("make"), NOW));
    assert!(g.matches(elsewhere, &sh("make"), NOW));

    // A file grant names absolute paths and holds in any project.
    let read = Action::FsRead {
        path: "/p/notes.md".to_owned(),
    };
    g.grant(at("cursor", "c1"), &read, NOW, None);
    let from = Scope {
        project: "/other",
        ..at("cursor", "c1")
    };
    assert!(g.matches(from, &read, NOW));

    // Unless it also answers the session's taint asks: that is project-bound.
    g.cover_taint(at("cursor", "c1"), &read);
    assert!(g.covering_taint(at("cursor", "c1"), NOW).is_some());
    assert!(g.covering_taint(from, NOW).is_none());
}

#[test]
fn a_grant_written_without_a_project_applies_nowhere() {
    // As an earlier release wrote them: no `project` field.
    let file = serde_json::json!({"version": 2, "entries": [
        {"host": "codex", "session_id": "k1", "action": {"shell": {"command": "ls"}},
            "granted_at_ms": NOW},
        {"host": "codex", "session_id": "k1", "action": {"fs_read": {"path": "/p/a"}},
            "granted_at_ms": NOW},
        {"host": "codex", "session_id": "k1", "action": {"fs_read": {"path": "/p/b"}},
            "granted_at_ms": NOW, "covers_taint": true},
    ]});
    let g = Grants::parse(&file.to_string(), Path::new("approvals.json")).unwrap();
    let unbound: Vec<bool> = g.entries.iter().map(Grant::unbound).collect();
    assert_eq!(unbound, [true, false, true]);
    assert!(!g.matches(at("codex", "k1"), &sh("ls"), NOW));
    let read = |path: &str| Action::FsRead {
        path: path.to_owned(),
    };
    assert!(g.matches(at("codex", "k1"), &read("/p/a"), NOW));
    assert!(!g.matches(at("codex", "k1"), &read("/p/b"), NOW));
    assert!(g.covering_taint(at("codex", "k1"), NOW).is_none());

    // Approving it again binds it and replaces the unbound one.
    let mut g = g;
    g.grant(at("codex", "k1"), &sh("ls"), NOW, None);
    assert!(g.matches(at("codex", "k1"), &sh("ls"), NOW));
    assert_eq!(g.entries.iter().filter(|e| e.unbound()).count(), 1);
}

#[test]
fn the_project_is_the_repository_root_with_links_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let repo = dir.path().join("repo");
    let deep = repo.join("src/app");
    fs::create_dir_all(&deep).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::write(repo.join(".git"), "gitdir: elsewhere\n").unwrap();
    let real = crate::context::path_string(&fs::canonicalize(&repo).unwrap());
    assert_eq!(project_of(&deep, &home), real);
    assert_eq!(project_of(&repo, &home), real);
    let plain = dir.path().join("plain");
    fs::create_dir_all(&plain).unwrap();
    let plain_real = crate::context::path_string(&fs::canonicalize(&plain).unwrap());
    assert_eq!(
        project_of(&plain, &home),
        plain_real,
        "no repository: the directory"
    );
}

#[test]
fn a_call_without_a_session_id_matches_no_grant() {
    // Every call a host sends without a session id is recorded as "unknown";
    // a grant for that id would hold in all of them. A grants file that has
    // one anyway (written by hand, or by an older moat) must not apply.
    let mut g = Grants::default();
    g.grant(
        at("cursor", "unknown"),
        &sh("npm install left-pad"),
        NOW,
        None,
    );
    g.grant(at("cursor", ""), &sh("npm install left-pad"), NOW, None);
    assert!(!g.matches(at("cursor", "unknown"), &sh("npm install left-pad"), NOW));
    assert!(!g.matches(at("cursor", ""), &sh("npm install left-pad"), NOW));
}

#[test]
fn a_grant_says_when_it_was_made() {
    let mut g = Grants::default();
    g.grant(at("claude-code", "s1"), &sh("make"), NOW, None);
    assert_eq!(
        g.granted_at(at("claude-code", "s1"), &sh("make"), NOW + 1),
        Some(NOW)
    );
    g.grant(at("claude-code", "s1"), &sh("make"), NOW + 5, None);
    assert_eq!(
        g.granted_at(at("claude-code", "s1"), &sh("make"), NOW + 6),
        Some(NOW + 5)
    );
    assert_eq!(
        g.granted_at(at("claude-code", "s2"), &sh("make"), NOW + 6),
        None
    );
    assert_eq!(
        g.granted_at(at("claude-code", "unknown"), &sh("make"), NOW + 6),
        None
    );
}

#[test]
fn grants_expire_after_the_ttl() {
    let mut g = Grants::default();
    g.grant(at("codex", "k1"), &sh("cargo add serde"), NOW, None);
    let ok = |g: &Grants, when| g.matches(at("codex", "k1"), &sh("cargo add serde"), when);
    assert!(ok(&g, NOW + GRANT_TTL_MS - 1));
    assert!(!ok(&g, NOW + GRANT_TTL_MS), "expired at the TTL");
    assert!(!ok(&g, NOW - 1), "a grant from the future is not valid");

    g.grant(
        at("codex", "k1"),
        &sh("cargo add serde"),
        NOW + GRANT_TTL_MS,
        None,
    );
    assert_eq!(g.entries.len(), 1);
    assert!(ok(&g, NOW + GRANT_TTL_MS + 1), "granting again restarts it");
}

#[test]
fn version_1_grants_migrate_unbound_and_one_without_a_timestamp_is_expired() {
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
    assert!(!g.entries[0].active(NOW));
    assert!(g.entries[1].active(NOW) && g.entries[1].unbound());
    assert!(
        !g.matches(at("codex", "k2"), &sh("ls"), NOW),
        "a command grant that names no project applies nowhere"
    );
    fs::write(&path, r#"{"version":3,"entries":[]}"#).unwrap();
    assert!(Grants::load(&path).is_err(), "a newer file is refused");
}

#[test]
fn the_audit_row_a_grant_saw_is_kept_and_an_old_grant_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals.json");
    let mut g = Grants::default();
    g.grant(at("codex", "k1"), &sh("ls"), NOW, Some(42));
    g.grant(at("codex", "k2"), &sh("ls"), NOW, None);
    g.save(&path, NOW).unwrap();
    let g = Grants::load(&path).unwrap();
    let row = |s| g.newest(at("codex", s), &sh("ls"), NOW).unwrap().audit_row;
    assert_eq!(row("k1"), Some(42));
    assert_eq!(row("k2"), None);
}

#[test]
fn saving_prunes_expired_grants() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals.json");
    let mut g = Grants::default();
    g.grant(at("codex", "old"), &sh("ls"), NOW - GRANT_TTL_MS, None);
    g.grant(at("codex", "new"), &sh("ls"), NOW - 1, None);
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
    g.grant(at("codex", "k1"), &sh("cargo add serde"), NOW, None);
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
            .contains("openmoat allow --always")
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

#[test]
fn an_approved_near_miss_install_also_allows_its_near_miss_atom() {
    let mut o = Overlay::default();
    assert_eq!(
        o.allow_command("cd app && npm i lodahs").unwrap().shell,
        [
            "cd app && npm i lodahs",
            "@package-near-miss npm lodahs lodash"
        ]
    );
    assert_eq!(
        o.allow_command("npm i left-pad").unwrap().shell,
        ["npm i left-pad"]
    );
    // the rule written still counts as covering the command
    assert!(o.covers(&Action::Shell {
        command: "cd app && npm i lodahs".into()
    }));
}

/// A file grant holds only while its file resolves where it did when approved:
/// a granted file replaced by a symlink to another file is asked about again.
#[cfg(unix)]
#[test]
fn a_granted_file_swapped_for_a_symlink_is_asked_again() {
    let dir = tempfile::tempdir().unwrap();
    let root = crate::context::path_string(&fs::canonicalize(dir.path()).unwrap());
    let (file, elsewhere) = (format!("{root}/notes.txt"), format!("{root}/bashrc"));
    fs::write(&file, "x").unwrap();
    fs::write(&elsewhere, "y").unwrap();
    let write = Action::FsWrite { path: file.clone() };
    let mut g = Grants::default();
    g.grant(at("claude-code", "s1"), &write, NOW, None);
    assert!(g.matches(at("claude-code", "s1"), &write, NOW));
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
    assert!(
        !g.matches(at("claude-code", "s1"), &write, NOW),
        "now a link"
    );
    // approved again as the link, it holds while the link points there
    g.grant(at("claude-code", "s1"), &write, NOW, None);
    assert!(g.matches(at("claude-code", "s1"), &write, NOW));
    assert_eq!(g.entries.len(), 1);
}
