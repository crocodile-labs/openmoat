use super::*;

#[test]
fn every_file_that_decides_or_records_a_call_is_listed() {
    let home = Home::at(PathBuf::from("/h/.moat"));
    let listed: Vec<PathBuf> = files(&home).into_iter().map(|(_, p, _)| p).collect();
    for path in [
        home.root().to_path_buf(),
        home.lock_path(),
        home.policy_path(),
        home.grants_path(),
        home.overlay_path(),
        home.audit_path(),
        crate::proxy_session::key_path(&home),
        crate::proxy_ca::key_path(&home),
    ] {
        assert!(listed.contains(&path), "{}", path.display());
    }
}

#[cfg(unix)]
#[test]
fn a_file_others_may_write_is_a_problem_row() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir(home.root()).unwrap();
    std::fs::set_permissions(home.root(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(home.policy_path(), "x").unwrap();
    std::fs::set_permissions(home.policy_path(), std::fs::Permissions::from_mode(0o666)).unwrap();
    let mut report = Report::new(crate::render::Deferred::quiet());
    rows(&mut report, &home);
    assert_eq!(report.problems.len(), 1, "{:?}", report.problems);
    assert!(
        report.problems[0].1.contains("chmod go-rwx"),
        "{:?}",
        report.problems
    );
}
