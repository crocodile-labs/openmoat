//! Installation-time snapshot of the search path and where key programs live.
//!
//! `moat init` records `PATH` and the absolute location of security-relevant
//! programs in `~/.moat/environment.json` (pinned by the policy lock). `moat guard`
//! resolves command names through this snapshot, never through the environment
//! the hook inherited, so a poisoned `PATH` or a planted `git` cannot change which
//! binary the kernel believes is about to run.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::ProgramResolver;
use serde::{Deserialize, Serialize};

use crate::context::path_string;
use crate::home::{Home, write_private};

const SNAPSHOT_VERSION: u32 = 1;

/// Programs whose location is recorded at install time.
pub const PINNED_PROGRAMS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "git",
    "gh",
    "ssh",
    "scp",
    // checks policy signatures (`signing.rs`, ADR-031)
    "ssh-keygen",
    "curl",
    "wget",
    "sudo",
    "node",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "bun",
    "python",
    "python3",
    "pip",
    "pip3",
    "uv",
    "cargo",
    "rustc",
    "go",
    "swift",
    "docker",
    "kubectl",
    "terraform",
    "aws",
    "gcloud",
    "az",
    "make",
    "brew",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub captured_at_ms: i64,
    /// Search path directories, in order, as seen by `moat init`.
    pub path: Vec<PathBuf>,
    /// Program name → absolute path found at install time.
    pub programs: BTreeMap<String, PathBuf>,
    /// Windows executable extensions (`PATHEXT`) in search order, lowercase.
    /// Captured with the search path so the hook's environment cannot change it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pathext: Vec<String>,
}

/// Used when `PATHEXT` is unset or empty, and for snapshots written before it
/// was recorded.
const DEFAULT_PATHEXT: &[&str] = &[".com", ".exe", ".bat", ".cmd"];

impl Snapshot {
    /// Capture the current process's search path and resolve the pinned programs.
    pub fn capture() -> Self {
        let path: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        let pathext = if cfg!(windows) {
            parse_pathext(&std::env::var("PATHEXT").unwrap_or_default())
        } else {
            Vec::new()
        };
        let mut programs = BTreeMap::new();
        for name in PINNED_PROGRAMS {
            if let Some(found) = find_in(&path, &pathext, name) {
                programs.insert((*name).to_owned(), found);
            }
        }
        Self {
            version: SNAPSHOT_VERSION,
            captured_at_ms: crate::time::now_ms(),
            path,
            programs,
            pathext,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading environment snapshot {}", path.display()))?;
        Self::parse(&text, path)
    }

    /// [`Snapshot::load`] of `home`'s snapshot, from the bytes the lock check
    /// kept when it kept them ([`Home::load_state`]).
    pub fn load_in(home: &Home) -> Result<Self> {
        home.load_state(&home.environment_path(), Self::parse, Self::load)
    }

    /// The snapshot in `text`, read from `path` (named in errors).
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        let snapshot: Self = serde_json::from_str(text)
            .with_context(|| format!("parsing environment snapshot {}", path.display()))?;
        if snapshot.version != SNAPSHOT_VERSION {
            bail!(
                "environment snapshot {} has version {}; this build supports {SNAPSHOT_VERSION}",
                path.display(),
                snapshot.version
            );
        }
        Ok(snapshot)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)? + "\n";
        write_private(path, text.as_bytes())
    }
}

impl ProgramResolver for Snapshot {
    fn resolve(&self, program: &str) -> Option<String> {
        find_in(&self.path, &self.pathext, program).map(|p| path_string(&p))
    }

    fn pinned(&self, program: &str) -> Option<String> {
        self.programs.get(program).map(|p| path_string(p))
    }
}

/// A [`Snapshot`] that also knows OpenMoat's own binary: the one the policy
/// lock records (`binary`) and its `moat` alias beside it, so the guard decides
/// a command that runs that file under another name as `openmoat`
/// ([`ProgramResolver::own_binaries`]).
pub struct WithOwnBinary<'a> {
    pub snapshot: &'a Snapshot,
    pub binary: &'a str,
}

impl ProgramResolver for WithOwnBinary<'_> {
    fn resolve(&self, program: &str) -> Option<String> {
        self.snapshot.resolve(program)
    }

    fn pinned(&self, program: &str) -> Option<String> {
        self.snapshot.pinned(program)
    }

    fn own_binaries(&self) -> Vec<String> {
        let binary = Path::new(self.binary);
        std::iter::once(binary.to_path_buf())
            .chain(crate::install::other_name(binary))
            .map(|p| path_string(&p))
            .collect()
    }
}

/// Where `program` is, as the snapshot `moat init` recorded resolves it: the
/// pinned location, else the first on the recorded search path. `None`
/// without a snapshot, so a poisoned `PATH` never picks the program.
pub fn program(home: &Home, program: &str) -> Option<PathBuf> {
    Snapshot::load_in(home).ok()?.program(program)
}

impl Snapshot {
    /// [`program`] in this snapshot, for a program OpenMoat itself runs. Only
    /// an absolute location counts: a relative search-path entry (`.`,
    /// `node_modules/.bin`) names a directory of whatever repository the
    /// command runs in, where an agent can put a program of that name.
    pub fn program(&self, program: &str) -> Option<PathBuf> {
        let absolute: Vec<PathBuf> = self
            .path
            .iter()
            .filter(|dir| dir.is_absolute())
            .cloned()
            .collect();
        self.programs
            .get(program)
            .filter(|p| p.is_absolute())
            .cloned()
            .or_else(|| find_in(&absolute, &self.pathext, program))
    }
}

/// `PATHEXT` (`.COM;.EXE;…`) as lowercase extensions; the default list when empty.
fn parse_pathext(raw: &str) -> Vec<String> {
    let exts: Vec<String> = raw
        .split(';')
        .map(str::trim)
        .filter(|e| e.starts_with('.') && e.len() > 1)
        .map(str::to_ascii_lowercase)
        .collect();
    if exts.is_empty() {
        DEFAULT_PATHEXT.iter().map(|e| (*e).to_owned()).collect()
    } else {
        exts
    }
}

/// First executable named `program` in `dirs`, following the platform's rules:
/// on Windows the name as given, then with each `pathext` extension.
pub fn find_in(dirs: &[PathBuf], pathext: &[String], program: &str) -> Option<PathBuf> {
    let candidates: Vec<String> = if cfg!(windows) {
        let default: Vec<String>;
        let exts = if pathext.is_empty() {
            default = parse_pathext("");
            &default
        } else {
            pathext
        };
        std::iter::once(program.to_owned())
            .chain(exts.iter().map(|e| format!("{program}{e}")))
            .collect()
    } else {
        vec![program.to_owned()]
    };
    dirs.iter()
        .filter(|d| !d.as_os_str().is_empty())
        .flat_map(|d| candidates.iter().map(move |c| d.join(c)))
        .find(|p| is_executable(p))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn executable(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn resolves_in_search_path_order_and_skips_non_executables() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("git"), "not executable").unwrap();
        let real = executable(&second, "git");
        let snap = Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_ms: 0,
            path: vec![first.clone(), second.clone()],
            programs: BTreeMap::from([("git".to_owned(), real.clone())]),
            pathext: Vec::new(),
        };
        assert_eq!(snap.resolve("git").as_deref(), Some(real.to_str().unwrap()));
        assert_eq!(snap.pinned("git").as_deref(), Some(real.to_str().unwrap()));
        assert_eq!(snap.resolve("nope"), None);

        let planted = executable(&first, "git");
        assert_eq!(
            snap.resolve("git").as_deref(),
            Some(planted.to_str().unwrap())
        );
    }

    /// A program OpenMoat runs itself (`git` for the push check, `ssh-keygen`)
    /// is never found through a relative search-path entry, which names a
    /// directory of the repository the call runs in.
    #[cfg(unix)]
    #[test]
    fn a_program_openmoat_runs_is_never_found_through_a_relative_entry() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("system");
        fs::create_dir_all(&system).unwrap();
        let real = executable(&system, "git");
        let snap = |path: Vec<PathBuf>, pinned: Option<PathBuf>| Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_ms: 0,
            path,
            programs: pinned
                .map(|p| BTreeMap::from([("git".to_owned(), p)]))
                .unwrap_or_default(),
            pathext: Vec::new(),
        };
        let relative = PathBuf::from("node_modules/.bin");
        let found = snap(vec![relative.clone(), system.clone()], None).program("git");
        assert_eq!(found, Some(real.clone()));
        let pinned_relative = snap(vec![system], Some(relative.join("git"))).program("git");
        assert_eq!(pinned_relative, Some(real), "a relative pin is no pin");
        assert_eq!(snap(vec![relative], None).program("git"), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_resolution_follows_the_recorded_pathext() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("tool.ps1"), "").unwrap();
        let dirs = [dir.path().to_path_buf()];
        assert_eq!(find_in(&dirs, &[], "tool"), None);
        let found = find_in(&dirs, &[".ps1".to_owned()], "tool").unwrap();
        assert!(path_string(&found).ends_with("/tool.ps1"), "{found:?}");
    }

    #[test]
    fn pathext_is_parsed_lowercase_with_a_default() {
        assert_eq!(
            parse_pathext(".COM;.EXE; .PS1 ;;bad"),
            [".com", ".exe", ".ps1"]
        );
        assert_eq!(parse_pathext(""), DEFAULT_PATHEXT);
        let old: Snapshot =
            serde_json::from_str(r#"{"version":1,"captured_at_ms":0,"path":[],"programs":{}}"#)
                .unwrap();
        assert!(
            old.pathext.is_empty(),
            "snapshots without pathext still load"
        );
    }

    #[test]
    fn round_trips_and_rejects_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("environment.json");
        let snap = Snapshot::capture();
        snap.save(&file).unwrap();
        assert_eq!(Snapshot::load(&file).unwrap(), snap);
        fs::write(
            &file,
            r#"{"version":7,"captured_at_ms":0,"path":[],"programs":{}}"#,
        )
        .unwrap();
        assert!(
            Snapshot::load(&file)
                .unwrap_err()
                .to_string()
                .contains("version 7")
        );
    }
}
