//! Agents' hook settings in the project that do not exist yet.
//!
//! `kernel-self` denies writing the files an agent reads its hook settings
//! from in a project (`.claude/settings.local.json`, `.gemini/settings.json`,
//! `.github/copilot/settings.local.json`, `.codex/hooks.json`,
//! `.cursor/hooks.json`, …): one with `disableAllHooks` or hooks of its own
//! makes the next session run without OpenMoat's hook. Landlock grants the
//! project whole, and a mount needs a path to cover, so one that is missing
//! when the agent starts could be created by any command. `moat run` (its
//! network namespace and `--isolate`) therefore creates each for the session
//! and binds it read-only: the folders above it (bound onto themselves, so
//! they cannot be renamed away) and the file, holding `{}` for a JSON file so
//! every agent reads it as settings that change nothing. They are removed
//! when the session ends, each only while it is still as it was made.

use super::{Mount, nested_write_denials};
use crate::sandbox::patterns::{AGENT_CONFIG, folders_above};
use openmoat_core::ir::Enforcement;

/// A file or folder created in the project for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    /// Where, absolute.
    pub path: String,
    /// A folder rather than a file.
    pub dir: bool,
    /// What a file holds.
    pub contents: &'static str,
}

impl Placeholder {
    /// An empty file.
    pub fn empty_file(path: String) -> Self {
        Self {
            path,
            dir: false,
            contents: "",
        }
    }
}

/// What the project's missing hook settings need: the placeholders to
/// create, outermost first, and the mounts over them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Created before the agent starts, removed after it ends.
    pub placeholders: Vec<Placeholder>,
    /// Folders bound onto themselves, then the files bound read-only.
    pub mounts: Vec<Mount>,
}

/// How a project path is found when the session starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Nothing there.
    Missing,
    /// A directory, not a link to one.
    Dir,
    /// A file, a link or anything else.
    Other,
}

/// The project-relative hook settings `kernel-self` (any `**/` write deny of
/// `ir` below a folder, without a glob) names: `.claude/settings.local.json`,
/// `.gemini/settings.json`, `.copilot/hooks`.
pub fn protected(ir: &Enforcement) -> Vec<String> {
    nested_write_denials(ir)
}

/// The plan for the hook settings of `ir` missing in the project `real`
/// (resolved), as `found` sees each path; `dir_below` says which are folders
/// below which writing is denied (`.copilot/hooks`), made as empty folders.
/// One below a link or a file is left out: a command cannot create it
/// through a file, and writing through a link leaves the project.
pub fn plan(
    ir: &Enforcement,
    real: &str,
    found: &dyn Fn(&str) -> Found,
    dir_below: &dyn Fn(&str) -> bool,
) -> Plan {
    let mut out = Plan::default();
    'settings: for rest in protected(ir) {
        let path = format!("{real}/{rest}");
        if found(&path) != Found::Missing {
            continue;
        }
        let mut folders = Vec::new();
        for folder in folders_above(&rest) {
            let folder = format!("{real}/{folder}");
            match found(&folder) {
                Found::Other => continue 'settings,
                Found::Dir => {}
                Found::Missing => folders.push(folder),
            }
        }
        for folder in folders {
            if !out.placeholders.iter().any(|p| p.path == folder) {
                out.mounts.push(Mount::ReadWrite(folder.clone()));
                out.placeholders.push(Placeholder {
                    path: folder,
                    dir: true,
                    contents: "",
                });
            }
        }
        let dir = dir_below(&path);
        let json = std::path::Path::new(&rest)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        let contents = if !dir && json { "{}" } else { "" };
        out.placeholders.push(Placeholder {
            path: path.clone(),
            dir,
            contents,
        });
        out.mounts.push(Mount::ReadOnly(path));
    }
    config_folders(&mut out, real, found, dir_below);
    // folders first, outermost first: a bind onto a folder must come before
    // the read-only file inside it
    out.mounts.sort_by_key(|m| match m {
        Mount::ReadWrite(p) => (0, super::depth(p)),
        other => (1, super::depth(super::path_of(other))),
    });
    out
}

/// Add to `out` the folders of an agent's configuration ([`AGENT_CONFIG`]:
/// `.claude/hooks`, `.github/hooks`, `.pi/extensions`) missing in the project
/// `real` below which `dir_below` says writing is denied, each made an empty
/// folder for the session and bound read-only (ADR-089): a hook written there
/// after the start would be loaded by the agent's next session, outside any
/// sandbox, and a mount over a folder covers files created in it later, where
/// one over a file cannot. Only where every folder above it is there already or
/// made for the hook settings (`.claude`), so a project gets no folders of
/// agents it has none of.
fn config_folders(
    out: &mut Plan,
    real: &str,
    found: &dyn Fn(&str) -> Found,
    dir_below: &dyn Fn(&str) -> bool,
) {
    let subtrees = AGENT_CONFIG.iter().filter_map(|entry| {
        let rest = entry.strip_prefix("**/")?.strip_suffix("/**")?;
        (!folders_above(rest).is_empty()).then_some(rest)
    });
    for rest in subtrees {
        let path = format!("{real}/{rest}");
        if found(&path) != Found::Missing || !dir_below(&path) {
            continue;
        }
        let held = folders_above(rest).iter().all(|folder| {
            let folder = format!("{real}/{folder}");
            found(&folder) == Found::Dir
                || out.placeholders.iter().any(|p| p.dir && p.path == folder)
        });
        if held && !out.placeholders.iter().any(|p| p.path == path) {
            out.placeholders.push(Placeholder {
                path: path.clone(),
                dir: true,
                contents: "",
            });
            out.mounts.push(Mount::ReadOnly(path));
        }
    }
}

/// [`Found`] for `path` on this machine, links not followed.
pub fn on_disk(path: &str) -> Found {
    match std::fs::symlink_metadata(path) {
        Err(_) => Found::Missing,
        Ok(meta) if meta.is_dir() => Found::Dir,
        Ok(_) => Found::Other,
    }
}
