//! Throwaway git repositories for the push check's tests, each in its own
//! temporary directory with a bare repository as its `origin`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fake GitHub token of the right shape, built at run time so this source
/// holds no token-shaped text.
pub fn fake_token() -> String {
    format!("ghp_{}", "Fake0Token".repeat(4))
}

pub struct Repo {
    _dir: tempfile::TempDir,
    pub work: PathBuf,
    pub origin: PathBuf,
}

impl Repo {
    /// A repository on `main` with one commit, pushed to `origin` with
    /// `main` tracking `origin/main`.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        let origin = dir.path().join("origin.git");
        // No template: no sample hooks are copied into either repository.
        let init = ["init", "-q", "--template=", "-b", "main"];
        git(
            dir.path(),
            &[&init[..], &["--bare", path(&origin)]].concat(),
        );
        git(dir.path(), &[&init[..], &[path(&work)]].concat());
        let repo = Self {
            _dir: dir,
            work,
            origin,
        };
        repo.git(&["remote", "add", "origin", path(&repo.origin)]);
        repo.commit("README.md", "hello\n", "first");
        repo.git(&["push", "-q", "-u", "origin", "main"]);
        repo
    }

    pub fn git(&self, args: &[&str]) -> String {
        git(&self.work, args)
    }

    /// Write `file` (relative) and commit it.
    pub fn commit(&self, file: &str, text: &str, message: &str) {
        let target = self.work.join(file);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, text).unwrap();
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", message]);
    }

    pub fn dir(&self) -> String {
        self.work.to_str().unwrap().replace('\\', "/")
    }
}

/// The `git` on this test's search path, by its absolute path.
pub fn git_program() -> PathBuf {
    let path: Vec<PathBuf> = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .filter(|dir| dir.is_absolute())
        .collect();
    crate::environment::find_in(&path, &[], "git").expect("git on PATH")
}

/// An environment snapshot that pins [`git_program`], as `openmoat init` records it.
pub fn snapshot() -> crate::environment::Snapshot {
    serde_json::from_value(serde_json::json!({
        "version": 1,
        "captured_at_ms": 0,
        "path": [],
        "programs": { "git": git_program() },
    }))
    .unwrap()
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Run git in `dir` with a fixed identity and no signing; panic on failure.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
        .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}
