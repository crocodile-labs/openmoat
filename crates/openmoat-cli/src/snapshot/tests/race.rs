//! A folder swapped for a link after the restore checked it, as a process
//! of the agent still running could do: the write and the delete still
//! happen in the folder that was checked, never through the link.

use std::os::unix::fs::symlink;

use super::*;

/// `root/a/b` checked, then `a` moved away and replaced by a link to
/// `outside`, which has a `b` of its own.
fn swapped(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let root = dir.join("root");
    let outside = dir.join("outside");
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::create_dir_all(outside.join("b")).unwrap();
    (root, outside, dir.join("root/a.moved"))
}

fn swap(root: &Path, outside: &Path, moved: &Path) {
    fs::rename(root.join("a"), moved).unwrap();
    symlink(outside, root.join("a")).unwrap();
}

#[test]
fn a_write_after_a_swap_lands_in_the_checked_folder() {
    let dir = tempfile::tempdir().unwrap();
    let (root, outside, moved) = swapped(dir.path());
    let target = paths::checked_target(&root, "a/b/authorized_keys", false).unwrap();
    swap(&root, &outside, &moved);
    let content = paths::Content::File {
        bytes: b"planted",
        executable: false,
    };
    paths::put(&target, &content).unwrap();
    assert!(!outside.join("b/authorized_keys").exists());
    assert_eq!(
        fs::read(moved.join("b/authorized_keys")).unwrap(),
        b"planted"
    );
    // Nothing is left under the temporary name either.
    assert_eq!(fs::read_dir(outside.join("b")).unwrap().count(), 0);
}

#[test]
fn a_delete_after_a_swap_removes_nothing_outside() {
    let dir = tempfile::tempdir().unwrap();
    let (root, outside, moved) = swapped(dir.path());
    fs::write(root.join("a/b/victim"), "project").unwrap();
    fs::write(outside.join("b/victim"), "keep").unwrap();
    let target = paths::checked_target(&root, "a/b/victim", false).unwrap();
    swap(&root, &outside, &moved);
    paths::remove(&target).unwrap();
    assert_eq!(
        fs::read_to_string(outside.join("b/victim")).unwrap(),
        "keep"
    );
    assert!(!moved.join("b/victim").exists());
}

/// Where the folder cannot be held open (Windows), a swap after the check
/// is found by the check made again right before the rename or the delete,
/// and refused.
#[test]
fn without_folder_calls_a_swap_is_found_and_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (root, outside, moved) = swapped(dir.path());
    fs::write(root.join("a/b/victim"), "project").unwrap();
    fs::write(outside.join("b/victim"), "keep").unwrap();
    let write = paths::other::checked_target(&root, "a/b/new", false).unwrap();
    let delete = paths::other::checked_target(&root, "a/b/victim", false).unwrap();
    swap(&root, &outside, &moved);
    let content = paths::Content::File {
        bytes: b"planted",
        executable: false,
    };
    assert!(paths::other::put(&write, &content).is_err());
    assert!(paths::other::remove(&delete).is_err());
    assert_eq!(fs::read_dir(outside.join("b")).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(outside.join("b/victim")).unwrap(),
        "keep"
    );
    // Unswapped, it writes and deletes as before.
    fs::remove_file(root.join("a")).unwrap();
    fs::rename(&moved, root.join("a")).unwrap();
    paths::other::put(&write, &content).unwrap();
    paths::other::remove(&delete).unwrap();
    assert_eq!(fs::read(root.join("a/b/new")).unwrap(), b"planted");
    assert!(!root.join("a/b/victim").exists());
}

#[test]
fn a_link_on_the_path_is_refused_and_a_link_at_the_name_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (root, outside, _) = swapped(dir.path());
    symlink(&outside, root.join("l")).unwrap();
    assert_eq!(
        paths::checked_target(&root, "l/b/x", true).err(),
        Some(Blocked::Parent("l".to_owned()))
    );
    fs::write(outside.join("secret"), "keep").unwrap();
    symlink(outside.join("secret"), root.join("a/b/name")).unwrap();
    let target = paths::checked_target(&root, "a/b/name", false).unwrap();
    let content = paths::Content::File {
        bytes: b"restored",
        executable: true,
    };
    paths::put(&target, &content).unwrap();
    assert_eq!(fs::read_to_string(outside.join("secret")).unwrap(), "keep");
    let written = fs::symlink_metadata(root.join("a/b/name")).unwrap();
    assert!(written.is_file());
    // Missing folders are made, as real folders.
    let made = paths::checked_target(&root, "new/deep/file", true).unwrap();
    paths::put(&made, &content).unwrap();
    assert!(
        fs::symlink_metadata(root.join("new/deep"))
            .unwrap()
            .is_dir()
    );
    assert_eq!(
        paths::checked_target(&root, "a/b", false).err(),
        Some(Blocked::Folder)
    );
}
