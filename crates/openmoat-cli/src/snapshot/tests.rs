use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::{EvalContext, Policy};

use super::capture::Denied;
use super::git::ShadowGit;
use super::lock::Held;
use super::paths::{self, Blocked, in_state_folder, is_plain};
use super::restore::{Applied, parse_raw_for_tests};
use super::*;

mod store;

/// A project and a store side by side in a fresh temporary directory, with
/// a policy that denies reading `**/app.secret` and `**/*.key` (names the
/// default policy does not deny, so a test run under OpenMoat can write them).
struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    denied: Denied,
}

fn git_program() -> PathBuf {
    crate::environment::find_on_path("git").expect("git on PATH")
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    fs::create_dir_all(&project).unwrap();
    let project = fs::canonicalize(&project).unwrap();
    let store_dir = dir.path().join("store");
    let git = ShadowGit::new(git_program(), store_dir.clone(), project.clone());
    git.init().unwrap();
    let store = Store {
        dir: store_dir,
        project: project.clone(),
        git,
    };
    let policy = Policy::parse(
        "version: 1\ndeny:\n  - id: secrets\n    fs.read: ['**/app.secret', '**/*.key']\n",
    )
    .unwrap();
    let root = crate::context::path_string(&project);
    let ctx = EvalContext {
        home: "/nonexistent-home".to_owned(),
        project: Some(root.clone()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: root,
        case_insensitive_paths: cfg!(any(target_os = "macos", windows)),
    };
    let denied = Denied::new(policy, &ctx).unwrap();
    Fixture {
        _dir: dir,
        store,
        denied,
    }
}

impl Fixture {
    fn root(&self) -> &Path {
        self.store.project()
    }

    fn write(&self, rel: &str, text: &str) {
        let path = self.root().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.root().join(rel)).unwrap()
    }

    fn take(&self, reason: Reason) -> Listed {
        self.take_with(reason, Limits::default())
    }

    fn take_with(&self, reason: Reason, limits: Limits) -> Listed {
        self.try_take(limits, reason, Some("run-1"))
            .unwrap()
            .snapshot()
            .clone()
    }

    /// The store's lock. Waits like the commands do: a git child another
    /// test thread forks keeps a copy of the lock file's descriptor until it
    /// starts git, so a lock just let go may be held for a moment more.
    fn held(&self) -> Held {
        self.store.lock(LOCK_WAIT).unwrap()
    }

    fn try_take(&self, limits: Limits, reason: Reason, session: Option<&str>) -> Result<Taken> {
        self.store
            .take(&self.held(), &self.denied, limits, reason, session)
    }

    fn apply(&self, plan: &Plan) -> Applied {
        self.store.apply(&self.held(), plan).unwrap()
    }

    fn files(&self, snapshot: &Listed) -> Vec<String> {
        let out = self
            .store
            .git
            .text(&["ls-tree", "-r", "--name-only", &snapshot.tree], None)
            .unwrap();
        out.lines().map(str::to_owned).collect()
    }

    /// Restore `target` over the files now, as `openmoat restore` does.
    fn restore(&self, target: &Listed) -> (Plan, Applied) {
        let undo = self.take(Reason::PreRestore);
        let plan = self.store.plan(target.clone(), undo, &[]).unwrap();
        let applied = self.apply(&plan);
        (plan, applied)
    }
}

#[test]
fn a_snapshot_keeps_files_and_leaves_out_secrets_ignored_and_large_files() {
    let f = fixture();
    f.write("src/main.rs", "fn main() {}\n");
    f.write("app.secret", "TOKEN=fake\n");
    f.write("keys/server.key", "fake key\n");
    f.write(".gitignore", "target/\n");
    f.write("target/out.bin", "built\n");
    f.write("big.bin", &"x".repeat(2048));
    let limits = Limits {
        file_bytes: 1024,
        ..Limits::default()
    };
    let s = f.take_with(Reason::Manual, limits);
    assert_eq!(f.files(&s), [".gitignore", "src/main.rs"]);
    let left: Vec<(&str, LeftOut)> = s
        .meta
        .left_out
        .iter()
        .map(|o| (o.path.as_str(), o.why))
        .collect();
    assert_eq!(
        left,
        [
            ("app.secret", LeftOut::Denied),
            ("big.bin", LeftOut::TooLarge),
            ("keys/server.key", LeftOut::Denied),
        ]
    );
    assert_eq!(s.meta.reason, Reason::Manual);
    assert_eq!(s.meta.session.as_deref(), Some("run-1"));
    // No object in the store holds the secret's bytes.
    let all = f
        .store
        .git
        .text(&["cat-file", "--batch-all-objects", "--batch"], None)
        .unwrap();
    assert!(!all.contains("TOKEN=fake"), "{all}");
    assert!(!all.contains("fake key"), "{all}");
}

/// A `.gitattributes` (the project's, or one an agent planted) that converts
/// line endings, expands `$Id$` or re-encodes changes no byte of a snapshot:
/// what comes back is what was there.
#[test]
fn a_restore_gives_back_the_bytes_whatever_the_gitattributes_say() {
    let f = fixture();
    f.write(
        ".gitattributes",
        "* text=auto eol=crlf\n*.id ident\n*.u16 text working-tree-encoding=UTF-16\n",
    );
    let files: [(&str, Vec<u8>); 4] = [
        ("crlf.txt", b"one\r\ntwo\r\n".to_vec()),
        ("lf.txt", b"one\ntwo\n".to_vec()),
        ("version.id", b"$Id: 0123456789abcdef $\n".to_vec()),
        ("wide.u16", b"\xff\xfeh\0i\0\n\0".to_vec()),
    ];
    for (name, bytes) in &files {
        fs::write(f.root().join(name), bytes).unwrap();
    }
    let before = f.take(Reason::Manual);
    for (name, _) in &files {
        fs::write(f.root().join(name), b"changed\n").unwrap();
    }
    let (_, applied) = f.restore(&before);
    assert_eq!(applied.skipped, [], "{applied:?}");
    for (name, bytes) in &files {
        assert_eq!(&fs::read(f.root().join(name)).unwrap(), bytes, "{name}");
    }
}

#[test]
fn an_unchanged_project_adds_no_snapshot() {
    let f = fixture();
    f.write("a.txt", "a\n");
    let first = f.take(Reason::RunStart);
    let again = f
        .try_take(Limits::default(), Reason::RunExit, None)
        .unwrap();
    assert_eq!(again, Taken::Unchanged(first));
    assert_eq!(f.store.list().unwrap().len(), 1);
}

/// Run 1 changes a file; run 2 starts on the files run 1 left, so its start
/// snapshot has the tree of run 1's exit. A plain `openmoat restore` after
/// run 2 must go back to run 2's start, not undo run 1's work too.
#[test]
fn every_run_records_its_start_even_when_nothing_changed() {
    let f = fixture();
    let take = |reason, session: &str| {
        f.try_take(Limits::default(), reason, Some(session))
            .unwrap()
    };
    f.write("a.txt", "before run 1\n");
    take(Reason::RunStart, "run-1");
    f.write("a.txt", "run 1's work\n");
    let exit = take(Reason::RunExit, "run-1").snapshot().clone();
    let start = take(Reason::RunStart, "run-2");
    assert!(matches!(start, Taken::New(_)), "{start:?}");
    let start = start.snapshot().clone();
    assert_eq!(start.tree, exit.tree, "the same files, stored once");
    f.write("a.txt", "run 2's mistake\n");
    take(Reason::RunExit, "run-2");
    let newest_start = f
        .store
        .list()
        .unwrap()
        .into_iter()
        .rev()
        .find(|s| s.meta.reason == Reason::RunStart)
        .unwrap();
    assert_eq!(newest_start.meta.session.as_deref(), Some("run-2"));
    f.restore(&newest_start);
    assert_eq!(f.read("a.txt"), "run 1's work\n");
    // Once a start is recorded, the same run's start on the same files adds nothing.
    take(Reason::RunStart, "run-3");
    assert!(matches!(
        take(Reason::RunStart, "run-3"),
        Taken::Unchanged(_)
    ));
}

#[test]
fn too_many_files_or_bytes_take_no_snapshot() {
    let f = fixture();
    f.write("a.txt", "aaaa");
    f.write("b.txt", "bbbb");
    let few = Limits {
        files: 1,
        ..Limits::default()
    };
    let err = f.try_take(few, Reason::Manual, None).unwrap_err();
    assert!(
        format!("{err:#}").contains("more than the limit of 1"),
        "{err:#}"
    );
    let small = Limits {
        total_bytes: 4,
        ..Limits::default()
    };
    assert!(f.try_take(small, Reason::Manual, None).is_err());
    assert_eq!(f.store.list().unwrap(), []);
}

#[test]
fn a_restore_puts_back_changed_and_deleted_files_and_deletes_new_ones() {
    let f = fixture();
    f.write("a.txt", "a\n");
    f.write("dir/b.txt", "b\n");
    f.write("app.secret", "TOKEN=fake\n");
    let before = f.take(Reason::RunStart);
    f.write("a.txt", "broken\n");
    fs::remove_file(f.root().join("dir/b.txt")).unwrap();
    f.write("new.txt", "agent\n");
    fs::remove_file(f.root().join("app.secret")).unwrap();
    let (plan, applied) = f.restore(&before);
    let kinds: Vec<(&str, ChangeKind)> = plan
        .changes
        .iter()
        .map(|c| (c.path.as_str(), c.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            ("a.txt", ChangeKind::Changed),
            ("dir/b.txt", ChangeKind::Added),
            ("new.txt", ChangeKind::Deleted),
        ]
    );
    assert_eq!((applied.written, applied.deleted), (2, 1), "{applied:?}");
    assert_eq!(f.read("a.txt"), "a\n");
    assert_eq!(f.read("dir/b.txt"), "b\n");
    assert!(!f.root().join("new.txt").exists());
    // The snapshot never held the secret, so the restore does not make one up.
    assert!(!f.root().join("app.secret").exists());
    // The undo snapshot holds the state the restore replaced.
    assert_eq!(f.files(&plan.undo), ["a.txt", "new.txt"]);
}

#[test]
fn a_restore_leaves_what_the_snapshot_left_out() {
    let f = fixture();
    f.write("big.bin", &"x".repeat(2048));
    f.write("a.txt", "a\n");
    let limits = Limits {
        file_bytes: 1024,
        ..Limits::default()
    };
    let before = f.take_with(Reason::RunStart, limits);
    // Smaller now, so the undo snapshot holds it; the snapshot to restore did not.
    f.write("big.bin", "small\n");
    let (plan, applied) = f.restore(&before);
    assert_eq!(plan.kept, ["big.bin"]);
    assert_eq!(plan.changes, []);
    assert_eq!(applied.deleted, 0);
    assert_eq!(f.read("big.bin"), "small\n");
}

#[test]
fn a_restore_names_a_file_the_undo_snapshot_could_not_keep() {
    let f = fixture();
    f.write("notes.txt", "mine\n");
    let before = f.take(Reason::RunStart);
    // The agent makes the project ignore the file, then rewrites it.
    f.write(".gitignore", "notes.txt\n");
    f.write("notes.txt", "agent\n");
    let undo = f.take(Reason::PreRestore);
    let plan = f.store.plan(before, undo, &[]).unwrap();
    let notes = plan.changes.iter().find(|c| c.path == "notes.txt").unwrap();
    assert_eq!(notes.kind, ChangeKind::Changed);
    assert!(
        notes.no_copy.as_deref().unwrap().contains("ignore"),
        "{notes:?}"
    );
    f.apply(&plan);
    assert_eq!(f.read("notes.txt"), "mine\n");
}

/// `notes.local` was there and ignored when the snapshot was taken; the agent
/// stops ignoring it, so the undo snapshot holds it. The snapshot to restore
/// does not cover it, so the restore must leave it, not delete it.
#[test]
fn a_restore_keeps_a_file_that_was_ignored_when_the_snapshot_was_taken() {
    let f = fixture();
    f.write(".gitignore", "*.local\nbuild/\n");
    f.write("notes.local", "mine\n");
    f.write("build/out/x.o", "built\n");
    f.write("a.txt", "a\n");
    let before = f.take(Reason::RunStart);
    assert_eq!(before.meta.ignored, ["build/", "notes.local"]);
    f.write(".gitignore", "");
    f.write("new.txt", "agent\n");
    let (plan, applied) = f.restore(&before);
    assert_eq!(
        plan.not_covered,
        ["build/out/x.o", "notes.local"],
        "{plan:?}"
    );
    assert_eq!(applied.deleted, 1, "only new.txt goes: {applied:?}");
    assert_eq!(f.read("notes.local"), "mine\n");
    assert_eq!(f.read("build/out/x.o"), "built\n");
    assert!(!f.root().join("new.txt").exists());
    assert_eq!(f.read(".gitignore"), "*.local\nbuild/\n");
}

#[test]
fn a_restore_limited_to_paths_changes_only_those() {
    let f = fixture();
    f.write("a.txt", "a\n");
    f.write("b.txt", "b\n");
    let before = f.take(Reason::RunStart);
    f.write("a.txt", "x\n");
    f.write("b.txt", "y\n");
    let undo = f.take(Reason::PreRestore);
    let plan = f.store.plan(before, undo, &["a.txt".to_owned()]).unwrap();
    f.apply(&plan);
    assert_eq!(f.read("a.txt"), "a\n");
    assert_eq!(f.read("b.txt"), "y\n");
}

/// An agent replaced a folder with a link to a folder outside the project
/// and made the project ignore the link: the restore must not write through it.
#[cfg(unix)]
#[test]
fn a_restore_never_writes_through_a_link_left_in_the_project() {
    let f = fixture();
    f.write("src/lib.rs", "lib\n");
    let before = f.take(Reason::RunStart);
    let outside = f.root().parent().unwrap().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::remove_dir_all(f.root().join("src")).unwrap();
    std::os::unix::fs::symlink(&outside, f.root().join("src")).unwrap();
    f.write(".gitignore", "src\n");
    let (_, applied) = f.restore(&before);
    assert!(!outside.join("lib.rs").exists(), "wrote through the link");
    assert_eq!(applied.skipped.len(), 1, "{applied:?}");
    assert!(applied.skipped[0].1.contains("`src`"), "{applied:?}");
}

#[cfg(unix)]
#[test]
fn links_and_executable_bits_come_back_as_they_were() {
    use std::os::unix::fs::PermissionsExt as _;
    let f = fixture();
    f.write("run.sh", "#!/bin/sh\n");
    fs::set_permissions(f.root().join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("run.sh", f.root().join("link")).unwrap();
    let before = f.take(Reason::RunStart);
    fs::remove_file(f.root().join("run.sh")).unwrap();
    fs::remove_file(f.root().join("link")).unwrap();
    f.write("link", "a file now\n");
    f.restore(&before);
    let mode = fs::metadata(f.root().join("run.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "{mode:o}");
    assert_eq!(
        fs::read_link(f.root().join("link")).unwrap(),
        PathBuf::from("run.sh")
    );
}

#[test]
fn a_name_with_a_line_break_is_kept_and_restored() {
    if cfg!(windows) {
        return;
    }
    let f = fixture();
    f.write("odd\nname.txt", "odd\n");
    let before = f.take(Reason::RunStart);
    assert_eq!(f.files(&before).len(), 1);
    fs::remove_file(f.root().join("odd\nname.txt")).unwrap();
    let (_, applied) = f.restore(&before);
    assert_eq!(applied.written, 1, "{applied:?}");
    assert_eq!(f.read("odd\nname.txt"), "odd\n");
}

#[test]
fn a_snapshot_is_found_by_a_unique_prefix_only() {
    let f = fixture();
    f.write("a.txt", "a\n");
    let s = f.take(Reason::Manual);
    assert_eq!(f.store.find(&s.id[..6]).unwrap(), s);
    assert!(f.store.find("zz").is_err());
    assert!(f.store.find("../x").is_err());
}

#[test]
fn plain_paths_and_state_folders() {
    for good in ["a", "a/b.txt", "odd\nname", ".gitignore", ".github/x"] {
        assert!(is_plain(good), "{good}");
    }
    for bad in ["", "/etc/passwd", "a/../b", "./a", "a//b", "a\\b", "a/"] {
        assert!(!is_plain(bad), "{bad:?}");
    }
    for state in [
        ".git/config",
        "sub/.GIT/hooks/x",
        ".moat/policy.yaml",
        "a/.Moat",
    ] {
        assert!(in_state_folder(state), "{state}");
    }
    assert!(!in_state_folder(".github/workflows/ci.yml"));
    assert!(!in_state_folder("a.git/x"));
}

#[test]
fn checked_target_refuses_names_outside_the_project() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    for bad in [
        "../x",
        "/etc/passwd",
        ".git/hooks/pre-commit",
        "a/.moat/policy.yaml",
    ] {
        assert_eq!(
            paths::checked_target(&root, bad, true),
            Err(Blocked::Name),
            "{bad}"
        );
    }
    assert!(!dir.path().join("x").exists());
    assert!(!root.join("a").exists());
}

#[test]
fn raw_differences_are_read_record_by_record() {
    let z = "0".repeat(40);
    let a = "a".repeat(40);
    let raw = format!(
        ":100644 100644 {a} {a} M\0a b\0:000000 100755 {z} {a} A\0new\nline\0:120000 000000 {a} {z} D\0gone\0"
    );
    assert_eq!(
        parse_raw_for_tests(raw.as_bytes()),
        [
            ('M', "100644".to_owned(), "a b".to_owned()),
            ('A', "100755".to_owned(), "new\nline".to_owned()),
            ('D', "000000".to_owned(), "gone".to_owned()),
        ]
    );
}
