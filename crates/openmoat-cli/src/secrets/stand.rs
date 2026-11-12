//! Stand-in programs for the tests of `command` sources: shell scripts in a
//! folder the test policy keeps from the agent with a deny `fs.write` rule.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use openmoat_core::{Policy, SecretCommand};

use super::Place;
use super::command::Program;

/// The tests' time limit. What runs is a fresh private copy of the program,
/// and macOS checks a new program file the first time it starts, which takes
/// a while when many tests start one at once; the tests of the limit itself
/// set a shorter one.
const LIMIT: Duration = Duration::from_secs(10);

/// A folder beside the test binary: the system's temp folder is `/tmp` on
/// Linux, where no command source may be.
pub fn scratch() -> tempfile::TempDir {
    let exe = std::env::current_exe().unwrap();
    tempfile::Builder::new()
        .prefix("cmd-source-")
        .tempdir_in(exe.parent().unwrap())
        .unwrap()
}

pub struct Stand {
    _dir: tempfile::TempDir,
    /// The folder, resolved; also the person's home.
    pub root: String,
    /// OpenMoat's state directory, beside it.
    state: tempfile::TempDir,
    /// A policy that denies writes to the folder.
    pub policy: Policy,
}

impl Stand {
    pub fn new() -> Self {
        let dir = scratch();
        let root = std::fs::canonicalize(dir.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let policy = Policy::parse(&format!(
            "version: 1\ndeny:\n  - id: credential-programs\n    fs.write: ['{root}/**']\n"
        ))
        .unwrap();
        Self {
            _dir: dir,
            root,
            state: scratch(),
            policy,
        }
    }

    /// Where the proxy would run the programs from.
    pub fn place(&self) -> Place<'_> {
        Place {
            home: &self.root,
            state: self.state.path(),
            writable: &[],
        }
    }

    /// The state directory.
    pub fn state(&self) -> &Path {
        self.state.path()
    }

    /// An executable `name` running `body`.
    pub fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = Path::new(&self.root).join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// The source running `run` for 15 minutes.
    pub fn source(run: &[&str]) -> SecretCommand {
        SecretCommand {
            run: run.iter().map(|w| (*w).to_owned()).collect(),
            lifetime: "15m".into(),
            refresh_before: None,
            home: openmoat_core::SecretCommandHome::Private,
        }
    }

    /// `path --print` made ready under `policy`, with the tests' time limit.
    pub fn program(&self, path: &Path, policy: &Policy) -> anyhow::Result<Program> {
        let path = path.to_string_lossy();
        Program::prepare(
            "t",
            &Self::source(&[&path, "--print"]),
            policy,
            &self.place(),
        )
        .map(|p| p.with_time_limit(LIMIT))
    }

    /// `/bin/sh -c body --print`: a program only an administrator can change,
    /// so no policy rule is needed.
    pub fn shell(&self, body: &str) -> Program {
        self.shell_with(&Self::source(&["/bin/sh", "-c", body, "sh", "--print"]))
    }

    /// [`Stand::shell`] of a source the test shaped.
    pub fn shell_with(&self, source: &SecretCommand) -> Program {
        let open = Policy::parse("version: 1\n").unwrap();
        Program::prepare("t", source, &open, &self.place())
            .unwrap()
            .with_time_limit(LIMIT)
    }
}
