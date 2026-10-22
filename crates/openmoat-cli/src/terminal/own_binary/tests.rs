use super::*;

/// A fake filesystem: each path resolves to the file named in `links`.
fn resolver<'a>(links: &'a [(&'a str, &'a str)]) -> impl Fn(&Path) -> Option<PathBuf> + 'a {
    move |p: &Path| {
        links
            .iter()
            .find(|(from, _)| Path::new(from) == p)
            .map(|(_, to)| PathBuf::from(to))
    }
}

#[test]
fn the_recorded_binary_and_its_links_are_recorded() {
    let fs = resolver(&[
        (
            "/usr/local/bin/openmoat",
            "/opt/cellar/openmoat/0.9.0/bin/openmoat",
        ),
        (
            "/opt/cellar/openmoat/0.9.0/bin/openmoat",
            "/opt/cellar/openmoat/0.9.0/bin/openmoat",
        ),
    ]);
    let recorded = Path::new("/usr/local/bin/openmoat");
    assert!(is_recorded(recorded, recorded, &fs));
    assert!(is_recorded(
        Path::new("/opt/cellar/openmoat/0.9.0/bin/openmoat"),
        recorded,
        &fs
    ));
}

#[test]
fn the_moat_alias_beside_the_recorded_binary_counts() {
    let fs = resolver(&[
        ("/usr/local/bin/openmoat", "/usr/local/bin/openmoat"),
        ("/usr/local/bin/moat", "/usr/local/bin/moat"),
    ]);
    assert!(is_recorded(
        Path::new("/usr/local/bin/moat"),
        Path::new("/usr/local/bin/openmoat"),
        &fs
    ));
}

#[test]
fn a_copy_or_a_renamed_binary_is_not_the_recorded_one() {
    let fs = resolver(&[
        ("/usr/local/bin/openmoat", "/usr/local/bin/openmoat"),
        ("/tmp/x", "/tmp/x"),
        ("/tmp/link", "/tmp/x"),
    ]);
    let recorded = Path::new("/usr/local/bin/openmoat");
    assert!(!is_recorded(Path::new("/tmp/x"), recorded, &fs));
    assert!(!is_recorded(Path::new("/tmp/link"), recorded, &fs));
}

#[test]
fn a_path_that_does_not_resolve_matches_nothing() {
    let fs = resolver(&[("/usr/local/bin/openmoat", "/usr/local/bin/openmoat")]);
    assert!(!is_recorded(
        Path::new("/gone/openmoat"),
        Path::new("/usr/local/bin/openmoat"),
        &fs
    ));
    assert!(!is_recorded(
        Path::new("/usr/local/bin/openmoat"),
        Path::new("/gone"),
        &fs
    ));
}

#[test]
fn only_the_commands_own_names_count_as_started_by_name() {
    for name in [
        "/usr/local/bin/openmoat",
        "moat",
        "./openmoat",
        "/opt/bin/moat",
    ] {
        assert!(started_by_name(Path::new(name)), "{name}");
    }
    for name in [
        "/tmp/x",
        "OpenMoat",
        "/usr/local/bin/OPENMOAT",
        "openmoat-copy",
        "/usr/local/bin/openmoat.sh",
        "",
    ] {
        assert!(!started_by_name(Path::new(name)), "{name}");
    }
    assert_eq!(
        started_by_name(Path::new("C:/bin/openmoat.EXE")),
        cfg!(windows)
    );
}

/// A lock in `dir` recording `binary`; returns its path.
fn lock_in(dir: &Path, binary: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("policy.lock");
    let lock =
        serde_json::json!({"version": 1, "pinned_at_ms": 0, "binary": binary, "entries": {}});
    std::fs::write(&path, lock.to_string()).unwrap();
    path
}

const INSTALLED: &str = "/usr/local/bin/openmoat";

fn installed() -> impl Fn(&Path) -> Option<PathBuf> {
    resolver(&[
        (INSTALLED, INSTALLED),
        ("/tmp/copy/openmoat", "/tmp/copy/openmoat"),
        // a link under another name to the installed binary
        ("/tmp/x", INSTALLED),
        ("/usr/local/bin/OpenMoat", INSTALLED),
    ])
}

#[test]
fn an_empty_moat_home_does_not_skip_the_default_homes_lock() {
    let dir = tempfile::tempdir().unwrap();
    let moved = dir.path().join("empty").join("policy.lock");
    let default = lock_in(&dir.path().join("home/state"), INSTALLED);
    let locks = [moved, default];
    let copy = Path::new("/tmp/copy/openmoat");
    let refused = check(
        "openmoat uninstall",
        &locks,
        Some(copy),
        Some(copy),
        installed(),
    );
    assert!(refused.is_err_and(|e| {
        e.to_string()
            .contains("must be run by the installed openmoat")
    }));
    let own = Path::new(INSTALLED);
    assert!(
        check(
            "openmoat uninstall",
            &locks,
            Some(own),
            Some(own),
            installed()
        )
        .is_ok()
    );
}

#[test]
fn every_lock_found_must_record_the_running_binary() {
    let dir = tempfile::tempdir().unwrap();
    let moved = lock_in(&dir.path().join("moved"), "/tmp/copy/openmoat");
    let default = lock_in(&dir.path().join("home/state"), INSTALLED);
    let copy = Path::new("/tmp/copy/openmoat");
    let both = [moved.clone(), default];
    assert!(check("openmoat allow", &both, Some(copy), Some(copy), installed()).is_err());
    assert!(
        check(
            "openmoat allow",
            &[moved],
            Some(copy),
            Some(copy),
            installed()
        )
        .is_ok()
    );
}

#[test]
fn no_lock_anywhere_lets_the_command_run_and_an_unreadable_one_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let copy = Path::new("/tmp/copy/openmoat");
    let none = [
        dir.path().join("a/policy.lock"),
        dir.path().join("b/policy.lock"),
    ];
    assert!(check("openmoat allow", &none, Some(copy), Some(copy), installed()).is_ok());

    let broken = dir.path().join("policy.lock");
    std::fs::write(&broken, "{ not a lock").unwrap();
    let refused = check(
        "openmoat allow",
        &[broken],
        Some(copy),
        Some(copy),
        installed(),
    );
    assert!(refused.is_err_and(|e| e.to_string().contains("cannot check which binary")));

    // a directory where the lock should be cannot be read as one
    let not_a_file = dir.path().join("dir.lock");
    std::fs::create_dir(&not_a_file).unwrap();
    assert!(
        check(
            "openmoat allow",
            &[not_a_file],
            Some(copy),
            Some(copy),
            installed()
        )
        .is_err()
    );
}

#[test]
fn a_link_under_another_name_or_case_is_refused_though_it_resolves_to_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let locks = [lock_in(dir.path(), INSTALLED)];
    for started in ["/tmp/x", "/usr/local/bin/OpenMoat"] {
        let path = Path::new(started);
        assert!(is_recorded(path, Path::new(INSTALLED), installed()));
        let refused = check(
            "openmoat allow",
            &locks,
            Some(path),
            Some(path),
            installed(),
        );
        assert!(
            refused.is_err_and(|e| e.to_string().contains("must be started as `openmoat`")),
            "{started}"
        );
    }
    // the running file is checked too, whatever argv[0] says
    let named = Path::new("/somewhere/openmoat");
    let copy = Path::new("/tmp/copy/openmoat");
    assert!(
        check(
            "openmoat allow",
            &locks,
            Some(copy),
            Some(named),
            installed()
        )
        .is_err()
    );
}
