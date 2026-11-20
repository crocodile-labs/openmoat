use super::*;

/// A state directory and a home directory, both temporary.
fn dirs() -> (tempfile::TempDir, Home, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    let user = dir.path().join("me");
    fs::create_dir_all(&user).unwrap();
    (dir, home, user)
}

#[test]
fn each_value_has_the_shape_a_key_scanner_looks_for_and_says_whose_it_is() {
    for target in &TARGETS {
        let values = target.values().unwrap();
        let text = target.content(&values);
        for value in &values {
            assert!(
                value.to_ascii_lowercase().contains("openmoatdecoy"),
                "{value}"
            );
            assert!(
                value.len() >= openmoat_core::canary::MIN_VALUE_LEN,
                "{value}"
            );
            assert!(text.contains(value.as_str()), "{text}");
        }
        // A key scanner, and the audit log's masks, see a key.
        assert!(
            openmoat_audit::token_shape(&values[0]).is_some(),
            "{}",
            values[0]
        );
        // Two plantings never share a value.
        assert_ne!(target.values().unwrap(), values);
    }
}

#[test]
fn a_decoy_goes_only_where_its_folder_is_and_nothing_is_at_its_name() {
    let (_dir, home, user) = dirs();
    // `~/.aws` is missing: no decoy there, and no folder is made.
    fs::write(user.join(".npmrc.bak"), "the person's own backup").unwrap();
    let offers = offers(&Record::default(), &user);
    let paths: Vec<&str> = offers.iter().map(|o| o.target.path).collect();
    assert_eq!(paths, ["~/.git-credentials.bak"]);
    let mut record = Record::default();
    let planted = plant(&home, &mut record, &offers).unwrap();
    assert_eq!(planted, [user.join(".git-credentials.bak")]);
    assert!(!user.join(".aws").exists());
    assert_eq!(
        fs::read_to_string(user.join(".npmrc.bak")).unwrap(),
        "the person's own backup"
    );
    // Recorded, and not offered again.
    let loaded = Record::load(&home).unwrap();
    assert_eq!(loaded, record);
    assert!(super::offers(&loaded, &user).is_empty());
    let decoys = loaded.decoys();
    assert_eq!(decoys.paths, ["~/.git-credentials.bak"]);
    assert_eq!(decoys.values, loaded.decoys[0].values);
}

#[cfg(unix)]
#[test]
fn a_link_at_a_decoys_name_is_never_followed() {
    let (dir, home, user) = dirs();
    let elsewhere = dir.path().join("elsewhere");
    std::os::unix::fs::symlink(&elsewhere, user.join(".npmrc.bak")).unwrap();
    let all: Vec<Offer> = TARGETS
        .iter()
        .map(|target| Offer {
            target,
            file: target.file(&user),
        })
        .filter(|o| o.file.parent().is_some_and(Path::is_dir))
        .collect();
    let planted = plant(&home, &mut Record::default(), &all).unwrap();
    assert!(!elsewhere.exists());
    assert!(!planted.contains(&user.join(".npmrc.bak")));
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &fs::metadata(user.join(".git-credentials.bak"))
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn uninstall_deletes_exactly_the_decoys_that_are_still_as_planted() {
    let (_dir, home, user) = dirs();
    fs::create_dir(user.join(".aws")).unwrap();
    let mut record = Record::default();
    plant(&home, &mut record, &offers(&Record::default(), &user)).unwrap();
    assert_eq!(record.decoys.len(), 3);
    // The person wrote into one; another is gone already.
    fs::write(user.join(".npmrc.bak"), "mine now").unwrap();
    fs::remove_file(user.join(".git-credentials.bak")).unwrap();
    fs::write(user.join("unrelated"), "x").unwrap();
    let done = remove(&home, &user).unwrap();
    assert_eq!(
        done,
        [
            (user.join(".aws/credentials.bak"), Removed::Deleted),
            (user.join(".git-credentials.bak"), Removed::Gone),
            (user.join(".npmrc.bak"), Removed::Changed),
        ]
    );
    assert!(!user.join(".aws/credentials.bak").exists());
    assert!(user.join(".aws").is_dir());
    assert_eq!(
        fs::read_to_string(user.join(".npmrc.bak")).unwrap(),
        "mine now"
    );
    assert!(user.join("unrelated").exists());
    // The record stays, empty, so the lock still pins what it holds.
    assert_eq!(Record::load(&home).unwrap().decoys, []);
    assert!(record_path(&home).is_file());
    assert_eq!(remove(&home, &user).unwrap(), []);
}

#[test]
fn a_record_of_another_version_is_refused() {
    let (_dir, home, _user) = dirs();
    fs::create_dir_all(home.root()).unwrap();
    fs::write(record_path(&home), r#"{"version":2,"decoys":[]}"#).unwrap();
    assert!(Record::load(&home).is_err());
    fs::write(record_path(&home), "{").unwrap();
    assert!(Record::load(&home).is_err());
}
