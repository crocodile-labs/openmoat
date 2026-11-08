//! The Linux-only part of the profile: denies by name in the workspace roots,
//! where bubblewrap can mount over a path a deny glob would miss (see the
//! module documentation of [`super`]).

use openmoat_core::Kind;
use openmoat_core::ir::Enforcement;
use toml_edit::{Item, value};

use super::{Generated, Mode};
use crate::sandbox::patterns::{Spot, has_glob, literal_tree, push_unique, split, spot};

/// Directories Codex keeps read-only in every workspace root itself
/// (`codex-rs/protocol/src/permissions.rs`), so they need no mount of ours.
const CODEX_PROTECTED: &[&str] = &[".git", ".agents", ".codex", ".aws"];

/// The most spellings one deny glob is written in by [`case_variants`]: every
/// letter case of a name of up to five letters (`.envrc`).
const MAX_CASE_VARIANTS: usize = 32;

/// The single names a write deny covers anywhere, as a node (`**/.claude`) or
/// a tree (`**/.moat/**`).
pub(super) fn denied_dirs(ir: &Enforcement) -> Vec<String> {
    let mut names = Vec::new();
    for rule in &ir.fs.write.deny {
        let (positive, _) = split(&rule.patterns);
        for pattern in positive {
            if let Spot::Anywhere(rest) = spot(pattern)
                && let Some(name) = literal_tree(rest).filter(|n| !n.contains('/'))
            {
                push_unique(&mut names, name.to_owned());
            }
        }
    }
    names
}

/// On Linux, also deny each `**/<name>` workspace deny's name directly in the
/// workspace roots, so a command cannot create it there. A deny below a
/// directory (`**/.claude/settings.local.json`) is not written by path: two such
/// paths below one missing directory would both mount over it, and bubblewrap
/// then fails to start any command. Instead, when the policy denies writing the
/// directory itself (`.claude`, `.cursor`), that directory is made read-only in
/// the workspace roots, which bubblewrap mounts over once when it is missing.
/// Any other directory is left out: a missing `bin` would be mounted over for
/// `bin/moat`, which breaks builds. What stays creatable is reported.
pub fn deny_names(generated: &mut Generated) {
    let Some(workspace) = generated
        .profile
        .get_mut("filesystem")
        .and_then(|fs| fs.get_mut(":workspace_roots"))
        .and_then(Item::as_table_mut)
    else {
        return;
    };
    let globs: Vec<String> = workspace
        .iter()
        .filter(|(key, mode)| key.starts_with("**/") && mode.as_str() == Some("deny"))
        .map(|(key, _)| key.to_owned())
        .collect();
    let mut read_only = Vec::new();
    for path in globs.iter().filter_map(|g| g.strip_prefix("**/")) {
        match path.split_once('/') {
            None if !has_glob(path) => {
                workspace.insert(path, value(Mode::Deny.as_str()));
            }
            Some((dir, _))
                if generated.denied_dirs.iter().any(|d| d == dir)
                    && !CODEX_PROTECTED.contains(&dir)
                    && !workspace.contains_key(dir) =>
            {
                workspace.insert(dir, value(Mode::Read.as_str()));
                read_only.push(dir.to_owned());
            }
            _ => {}
        }
    }
    if !read_only.is_empty() {
        generated.report.loss(
            Kind::FsWrite,
            "codex.linux-agent-dirs",
            format!(
                "on Linux sandboxed commands cannot write in a workspace root's {}, so they \
                 cannot plant another agent's settings there; while a command runs a missing \
                 one shows up as an empty file",
                read_only
                    .iter()
                    .map(|d| format!("`{d}`"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
        );
    }
    case_variants(workspace, &globs, &mut generated.report);
    if !globs.is_empty() {
        generated.report.allowance(
            Kind::FsWrite,
            "codex.linux-write-globs",
            globs,
            "Codex on Linux hides only the files a deny glob matches when a command starts, \
             so sandboxed commands may create a missing match, except a name directly in a \
             workspace root (`.env`, `.envrc`) and anything in its `.claude` or `.cursor`, \
             which the profile also denies or makes read-only by path; the hook still denies \
             the agent's own writes",
        );
    }
}

/// Also deny each `**/` glob of the workspace roots in every other ASCII
/// letter case. Codex on Linux hides the files a glob matches, compared
/// case-sensitively, when a command starts; in a directory that folds case
/// (ext4 or f2fs with `chattr +F`) a file spelled `.ENV` is the project's
/// `.env`, yet `**/.env` does not match it. Which directories fold case is
/// not known when the profile is written (the workspace roots are Codex's), so
/// the spellings are written on every Linux profile: on a disk that keeps case
/// they deny only files of those other names. Written as globs, never as names
/// in the roots, which bubblewrap would create as empty files. A glob with
/// more spellings than [`MAX_CASE_VARIANTS`] is reported instead.
fn case_variants(
    workspace: &mut toml_edit::Table,
    globs: &[String],
    report: &mut crate::sandbox::Report,
) {
    let mut past_cap = Vec::new();
    for glob in globs {
        match spellings(glob) {
            Some(spellings) => {
                for spelling in spellings {
                    if !workspace.contains_key(&spelling) {
                        workspace.insert(&spelling, value(Mode::Deny.as_str()));
                    }
                }
            }
            None => past_cap.push(glob.clone()),
        }
    }
    if !past_cap.is_empty() {
        report.loss(
            Kind::FsWrite,
            "codex.linux-case-variants",
            format!(
                "Codex on Linux compares deny globs with file names in their letter case, so in \
                 a directory that folds case (`chattr +F`) a file that exists in another case is \
                 not hidden by {}; the profile writes every case of shorter names only, and the \
                 hook still decides the agent's own reads and writes",
                past_cap
                    .iter()
                    .map(|g| format!("`{g}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
}

/// Every ASCII letter case of `glob` other than its own, or `None` when there
/// are more than [`MAX_CASE_VARIANTS`] or it holds a character class or a
/// brace, whose letters are not plain name letters.
fn spellings(glob: &str) -> Option<Vec<String>> {
    if glob.contains(['[', '{', '\\']) {
        return None;
    }
    let letters: Vec<usize> = glob
        .char_indices()
        .filter(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .collect();
    let count = 1_usize.checked_shl(u32::try_from(letters.len()).ok()?)?;
    if count > MAX_CASE_VARIANTS {
        return None;
    }
    let lower = glob.to_ascii_lowercase();
    let mut out = Vec::new();
    for mask in 0..count {
        let mut spelling = lower.clone().into_bytes();
        for (bit, &at) in letters.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                spelling[at] = spelling[at].to_ascii_uppercase();
            }
        }
        let spelling = String::from_utf8(spelling).ok()?;
        if spelling != glob {
            out.push(spelling);
        }
    }
    Some(out)
}
