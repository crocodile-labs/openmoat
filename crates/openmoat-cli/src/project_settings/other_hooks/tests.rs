use super::*;

/// Cline's other `PreToolUse` files and plugins are found, OpenMoat's own
/// file and other events' files are not.
#[test]
fn cline_hooks_beside_openmoats_are_found() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let config = user_home.join(".cline");
    let ours = config.join("hooks/PreToolUse");
    let project = dir.path().join("proj");
    fs::create_dir_all(ours.parent().unwrap()).unwrap();
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::write(&ours, "#!/bin/sh\n").unwrap();
    fs::write(config.join("hooks/PostToolUse"), "").unwrap();
    let find = || found(Host::Cline, &config, &ours, &project, &user_home);
    assert_eq!(find(), Vec::<PathBuf>::new());

    let beside = config.join("hooks/PreToolUse.py");
    let person = user_home.join("Documents/Cline/Hooks/PreToolUse");
    let workspace = project.join(".clinerules/hooks/PreToolUse.sh");
    let plugin = config.join("plugins/rewriter");
    for path in [&beside, &person, &workspace] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "").unwrap();
    }
    fs::create_dir_all(&plugin).unwrap();
    assert_eq!(find(), vec![person, beside, workspace, plugin]);

    // A host whose spec names no other hooks finds none.
    assert_eq!(
        found(Host::Goose, &config, &ours, &project, &user_home),
        Vec::<PathBuf>::new()
    );
}
