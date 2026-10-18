//! What `moat allow` approves of an asked action, and how it is shown.

use openmoat_core::Action;

/// An asked action as a grant or `--always` rule names it: a shell command
/// trimmed, or files with each path made absolute against `cwd` (`~` expanded,
/// `.` and `..` collapsed) the way the engine reads it. `None` for what `moat
/// allow` cannot approve (MCP tools, sites, a foreign shell, a patch naming no
/// file) and for a relative path without a `cwd`. `cwd` and `home` are in canonical slash form.
#[must_use]
pub fn approvable(action: &Action, cwd: Option<&str>, home: &str) -> Option<Action> {
    let absolute = |p: &String| openmoat_core::resolve_path(p, home, None, cwd);
    // A patch naming no file is unparseable, and stays an `ask`.
    let all = |paths: &[String]| {
        let all: Vec<String> = paths.iter().map(absolute).collect::<Option<_>>()?;
        (!all.is_empty()).then_some(all)
    };
    Some(match action {
        Action::Shell { command } => Action::Shell {
            command: command.trim().to_owned(),
        },
        Action::FsRead { path } => Action::FsRead {
            path: absolute(path)?,
        },
        Action::FsWrite { path } => Action::FsWrite {
            path: absolute(path)?,
        },
        Action::Patch { writes } => Action::Patch {
            writes: all(writes)?,
        },
        Action::ReadFiles { paths } => Action::ReadFiles { paths: all(paths)? },
        _ => return None,
    })
}

/// The paths a file action reads and writes; both empty for anything else.
#[must_use]
pub fn files(action: &Action) -> (&[String], &[String]) {
    match action {
        Action::FsRead { path } => (std::slice::from_ref(path), &[]),
        Action::ReadFiles { paths } => (paths, &[]),
        Action::FsWrite { path } => (&[], std::slice::from_ref(path)),
        Action::Patch { writes } => (&[], writes),
        _ => (&[], &[]),
    }
}

/// What an approvable action does, for a person: `run "…"`, `read …`, `write …`.
#[must_use]
pub fn describe(action: &Action) -> String {
    if let Action::Shell { command } = action {
        return format!("run \"{command}\"");
    }
    let (reads, writes) = files(action);
    let verb = if writes.is_empty() { "read" } else { "write" };
    format!("{verb} {}", [reads, writes].concat().join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::{Grants, Overlay};

    /// 2026-10-03 00:00:00 UTC.
    const NOW: i64 = 1_790_985_600_000;

    #[test]
    fn file_grants_match_the_exact_absolute_paths() {
        let read = |path: &str, cwd| {
            let action = Action::FsRead {
                path: path.to_owned(),
            };
            approvable(&action, cwd, "/h")
        };
        let asked = read("src/../notes.md", Some("/p")).unwrap();
        assert_eq!(describe(&asked), "read /p/notes.md");
        assert_eq!(read("~/notes.md", None), read("/h/notes.md", None));
        assert_eq!(read("notes.md", None), None, "relative without a cwd");
        let mut g = Grants::default();
        g.grant("cursor", "c1", &asked, NOW, None);
        assert!(g.matches("cursor", "c1", &read("/p/notes.md", None).unwrap(), NOW));
        assert!(!g.matches("cursor", "c1", &read("/p/other.md", None).unwrap(), NOW));
        let write = Action::FsWrite {
            path: "/p/notes.md".to_owned(),
        };
        assert!(
            !g.matches("cursor", "c1", &write, NOW),
            "a read is not a write"
        );

        let mut o = Overlay::default();
        assert!(!o.covers(&asked));
        let rule = o.allow_files(&["/p/notes.md".to_owned()], &[]).unwrap();
        assert_eq!(rule.fs_read, ["/p/notes.md"]);
        assert!(rule.fs_write.is_empty());
        assert!(o.covers(&asked) && !o.covers(&write));
        assert!(o.allow_files(&[], &["/p/*.md".to_owned()]).is_err());
    }
}
