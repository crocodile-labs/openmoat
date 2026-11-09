//! Unix: each state file's permission bits and owning user, read without
//! following a final symbolic link.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use super::Found;

/// Group and other write bits.
const OTHERS_WRITE: u32 = 0o022;
/// Group and other read bits.
const OTHERS_READ: u32 = 0o044;

/// The note when the user this process runs as cannot be told.
pub(super) const NOT_CHECKED: &str = "state files      modes and owners not checked: could not tell which \
                                      user this is (the temp directory is not writable)";

/// The user this process runs as: the owner of a file it creates (std has no
/// `getuid`, and the crate forbids `unsafe`). The file is created owner-only
/// in the temp directory and removed at once.
pub(super) fn current_user() -> Option<u32> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let probe =
        std::env::temp_dir().join(format!(".openmoat-owner-{}-{nanos}", std::process::id()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .ok()?;
    let uid = file.metadata().ok().map(|m| m.uid());
    drop(file);
    let _ = fs::remove_file(&probe);
    uid
}

/// The mode and owner of `path`, `None` when there is nothing there; `me` is
/// [`current_user`].
pub(super) fn inspect(path: &Path, me: u32) -> Option<Found> {
    let meta = fs::symlink_metadata(path).ok()?;
    Some(judge(
        path,
        meta.permissions().mode(),
        meta.uid(),
        me,
        meta.file_type().is_symlink(),
    ))
}

/// [`inspect`] of a file with `mode`, owned by `uid`.
fn judge(path: &Path, mode: u32, uid: u32, me: u32, link: bool) -> Found {
    let bits = mode & 0o7777;
    let owner = if uid == me {
        "you".to_owned()
    } else {
        format!("uid {uid}")
    };
    let shown_path = path.display();
    // A link's own mode means nothing (`lrwxrwxrwx` on Linux); what it points
    // at is pinned by the lock's digests, which hash the target path too.
    if link {
        return Found {
            shown: format!("symbolic link, owner {owner}"),
            problem: None,
            readable: Some(
                "is a symbolic link: whoever may change where it points chooses this file; the \
                 lock notices a new target, but keep the file itself here"
                    .to_owned(),
            ),
        };
    }
    let shown = format!("mode {bits:03o}, owner {owner}");
    let problem = if uid != me {
        Some(format!(
            "is owned by uid {uid}, not by you (uid {me}): that user can change it under the \
             lock; `sudo chown {me} {shown_path}`, then check what it holds"
        ))
    } else if bits & OTHERS_WRITE != 0 {
        Some(format!(
            "has mode {bits:03o}: other users may change it under the lock; \
             `chmod go-rwx {shown_path}`, then check what it holds"
        ))
    } else {
        None
    };
    let readable = (bits & OTHERS_READ != 0).then(|| {
        format!("has mode {bits:03o}: other users may read it; `chmod go-rwx {shown_path}`")
    });
    Found {
        shown,
        problem,
        readable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_only_files_are_fine() {
        let found = judge(
            Path::new("/h/.moat/policy.lock"),
            0o100_600,
            501,
            501,
            false,
        );
        assert_eq!(found.shown, "mode 600, owner you");
        assert_eq!(found.problem, None);
        assert_eq!(found.readable, None);
        let dir = judge(Path::new("/h/.moat"), 0o040_700, 501, 501, false);
        assert_eq!(dir.problem, None);
    }

    #[test]
    fn others_writing_or_owning_is_a_problem_and_reading_a_warning() {
        let path = Path::new("/h/.moat/policy.yaml");
        let writable = judge(path, 0o100_666, 501, 501, false);
        assert!(writable.problem.unwrap().contains("chmod go-rwx"));
        assert!(writable.readable.is_some());
        let readable = judge(path, 0o100_644, 501, 501, false);
        assert_eq!(readable.problem, None);
        assert!(readable.readable.unwrap().contains("may read"));
        let theirs = judge(path, 0o100_600, 0, 501, false);
        assert_eq!(theirs.shown, "mode 600, owner uid 0");
        assert!(theirs.problem.unwrap().contains("owned by uid 0"));
        let link = judge(path, 0o120_777, 501, 501, true);
        assert_eq!(link.problem, None);
        assert!(link.readable.unwrap().contains("symbolic link"));
    }

    #[test]
    fn this_process_owns_what_it_creates() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"").unwrap();
        let me = current_user().unwrap();
        assert_eq!(fs::metadata(&file).unwrap().uid(), me);
        let found = inspect(&file, me).unwrap();
        assert!(found.shown.ends_with("owner you"), "{found:?}");
        assert_eq!(inspect(&dir.path().join("missing"), me), None);
    }
}
