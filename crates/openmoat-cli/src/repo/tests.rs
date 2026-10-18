use super::*;

fn project() -> (tempfile::TempDir, Home, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    let root = dir.path().join("project");
    fs::create_dir_all(&root).unwrap();
    (dir, home, root)
}

#[test]
fn no_policy_directory_or_a_file_in_its_place_is_no_repo_policy() {
    let (_dir, home, root) = project();
    assert!(find(&home, &root).unwrap().is_none());
    // The empty placeholder `moat run --isolate` leaves at `.moat`.
    fs::write(root.join(home::DIR_NAME), "").unwrap();
    assert!(find(&home, &root).unwrap().is_none());
}

#[test]
fn a_policy_that_exists_but_is_no_file_or_malformed_is_an_error() {
    let (_dir, home, root) = project();
    let path = root.join(home::DIR_NAME).join("policy.yaml");
    fs::create_dir_all(&path).unwrap();
    let error = format!("{:#}", find(&home, &root).err().unwrap());
    assert!(error.contains("not a regular file"), "{error}");
    fs::remove_dir(&path).unwrap();
    fs::write(&path, "version: 1\ndeny: [\n").unwrap();
    let error = format!("{:#}", find(&home, &root).err().unwrap());
    assert!(error.contains("invalid repository policy"), "{error}");
}
