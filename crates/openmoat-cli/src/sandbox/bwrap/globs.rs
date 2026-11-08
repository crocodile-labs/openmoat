//! Masks for deny rules whose glob is in the last name only, outside the
//! project: `/tmp/krb5cc_*` in the read root `/tmp`. Landlock grants the read
//! root whole, so each entry of the folder that matches when the session
//! starts is hidden (a read deny) or bound read-only (a write deny), as a
//! literal path is. An entry created later stays open, as listed
//! (`bwrap.created-later`).

use openmoat_core::AtomicAction;
use openmoat_core::ir::{Effect, Enforcement};

use super::{Mount, denials, path_of};
use crate::sandbox::links;
use crate::sandbox::patterns::{has_glob, is_below};

/// More entries than this in one folder and the rest are not looked at: a
/// temp directory with that many is not listed whole at every start.
const MAX_ENTRIES: usize = 100_000;

/// The masks for the entries of `trees` (outermost first) that a deny rule
/// with a glob in its last name matches, outside the project `real`.
pub(super) fn name_glob_masks(
    ir: &Enforcement,
    trees: &[Mount],
    real: Option<&str>,
) -> anyhow::Result<Vec<Mount>> {
    let checker = deny_rules_only(ir).checker()?;
    let mut masks = Vec::new();
    for dir in folders(ir) {
        let dir = links::real_path(&dir);
        let in_project = real.is_some_and(|p| dir == p || is_below(&dir, p));
        let holder = trees.iter().rev().find(|m| {
            let tree = path_of(m);
            dir == tree || is_below(&dir, tree)
        });
        let writable = match holder {
            _ if in_project => continue,
            Some(Mount::ReadWrite(_)) => true,
            Some(Mount::ReadOnly(_)) => false,
            // Not visible (a `tmpfs`, nothing).
            _ => continue,
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_ENTRIES) {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let path = format!("{}/{name}", dir.trim_end_matches('/'));
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            let denied = |atom| checker.check_os(&atom) == Some(Effect::Deny);
            let reading = AtomicAction::FsRead { path: path.clone() };
            let writing = AtomicAction::FsWrite { path: path.clone() };
            if denied(reading) {
                masks.push(Mount::Hide { path, dir: is_dir });
            } else if writable && denied(writing) {
                masks.push(Mount::ReadOnly(path));
            }
        }
    }
    Ok(masks)
}

/// `ir` with its deny rules alone: an entry is masked because a deny rule
/// names it, never because the policy's default would refuse it, which in a
/// granted folder Landlock does not either.
fn deny_rules_only(ir: &Enforcement) -> Enforcement {
    let mut only = ir.clone();
    for access in [&mut only.fs.read, &mut only.fs.write] {
        access.default = Effect::Allow;
        access.allow.clear();
    }
    only
}

/// The literal folders of absolute deny patterns whose only glob is in the
/// last name (`/tmp` for `/tmp/krb5cc_*` and `/tmp/krb5cc_*/**`).
fn folders(ir: &Enforcement) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for access in [&ir.fs.read, &ir.fs.write] {
        for pattern in denials(access).filter(|p| p.starts_with('/')) {
            let pattern = pattern.strip_suffix("/**").unwrap_or(pattern);
            let Some((dir, name)) = pattern.rsplit_once('/') else {
                continue;
            };
            let dir = if dir.is_empty() { "/" } else { dir };
            if has_glob(name) && !has_glob(dir) && !found.iter().any(|d| d == dir) {
                found.push(dir.to_owned());
            }
        }
    }
    found
}
