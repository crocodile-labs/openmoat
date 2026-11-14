use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, ProjectFile, ProjectOff};

use super::{Off, turned_off};

/// A home holding a git project, and both.
fn project() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let project = home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    (dir, home, project)
}

fn write(root: &Path, file: &ProjectFile, text: &str) {
    let path = root.join(file.path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// Each host whose spec gives a project file that turns its hook off.
fn examples() -> Vec<(Host, ProjectFile)> {
    Host::ALL
        .into_iter()
        .filter_map(|host| match host.spec().hook_off.project {
            ProjectOff::Files { example, .. } => Some((host, example)),
            ProjectOff::Nothing { .. } => None,
        })
        .collect()
}

fn found(host: Host, cwd: &Path, home: &Path) -> Vec<Off> {
    let keys = host
        .spec()
        .hook_off
        .session_override
        .as_ref()
        .map_or(&[][..], |o| o.keys);
    turned_off(cwd, home, host, &home.join("hook-file"), keys)
}

/// Every host's example turns its hook off, in the working directory and
/// at the project root above it; the host's reader names it.
#[test]
fn each_hosts_example_turns_its_hook_off_where_the_host_loads_it() {
    let hosts = examples();
    assert!(hosts.len() >= 7, "{hosts:?}");
    for (host, example) in hosts {
        let (_dir, home, project) = project();
        write(&project, &example, example.text);
        let off = found(host, &project, &home);
        assert_eq!(off.len(), 1, "{host:?}: {off:?}");
        assert!(off[0].path.ends_with(example.path), "{host:?}: {off:?}");
        assert!(!off[0].what.is_empty(), "{host:?}");
        let sub = project.join("src/deep");
        fs::create_dir_all(&sub).unwrap();
        assert!(
            !found(host, &sub, &home).is_empty(),
            "{host:?}: the root's file"
        );
        // An override replaces the example's key, so it covers it.
        let overridable = host.spec().hook_off.session_override.is_some();
        assert_eq!(off[0].overridden, overridable, "{host:?}");
    }
}

/// The benign neighbours: the same file turning nothing off, the example
/// under another folder (a fixture, a template), and text the host cannot
/// parse, which it refuses to load.
#[test]
fn files_that_turn_nothing_off_or_are_not_loaded_pass() {
    for (host, example) in examples() {
        let (_dir, home, project) = project();
        let empty = if Path::new(example.path)
            .extension()
            .is_some_and(|e| e == "toml")
        {
            "[features]\nhooks = true\n"
        } else {
            "{}\n"
        };
        write(&project, &example, empty);
        let elsewhere = ProjectFile::new("fixtures/repo", "");
        let copy = project.join(elsewhere.path).join(example.path);
        fs::create_dir_all(copy.parent().unwrap()).unwrap();
        fs::write(&copy, example.text).unwrap();
        assert_eq!(found(host, &project, &home), Vec::new(), "{host:?}");
        write(&project, &example, "{ not json\n[[");
        assert_eq!(found(host, &project, &home), Vec::new(), "{host:?}");
    }
}

/// A key the override does not replace keeps the file from being covered.
#[test]
fn an_override_covers_only_its_own_keys() {
    for (host, example) in examples() {
        let Some(over) = &host.spec().hook_off.session_override else {
            continue;
        };
        let (_dir, home, project) = project();
        write(&project, &example, example.text);
        assert!(found(host, &project, &home)[0].overridden, "{host:?}");
        // The same file, with the override's keys removed, turns nothing off.
        let text: serde_json::Value = serde_json::from_str(example.text).unwrap();
        let mut rest = text.as_object().unwrap().clone();
        rest.retain(|key, _| !over.keys.contains(&key.as_str()));
        write(&project, &example, &serde_json::to_string(&rest).unwrap());
        assert_eq!(found(host, &project, &home), Vec::new(), "{host:?}");
    }
}

/// The home directory is no project: its files are the person's own.
#[test]
fn the_home_directory_is_not_a_project() {
    for (host, example) in examples() {
        let (_dir, home, _project) = project();
        write(&home, &example, example.text);
        assert_eq!(found(host, &home, &home), Vec::new(), "{host:?}");
    }
}
