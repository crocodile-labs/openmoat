//! The Windows tier of `openmoat run` (ADR-115): what the agent's
//! write-restricted token may write, as access-list entries for SIDs of the
//! run's own. Pure: `commands/run/windows.rs` applies the plan with Win32
//! calls; this file only decides, so its tests run on every system.
//!
//! A write-restricted token (`CreateRestrictedToken` with `WRITE_RESTRICTED`)
//! makes Windows check every write twice: once against the person's own SIDs,
//! as for any of their programs, and once against the token's restricting
//! SIDs, and the write goes through only when both checks grant it. Reads are
//! checked once, as the person: **the token does not restrict reads**, so
//! every read deny rule stays the hook's alone.
//!
//! The restricting SIDs are `Everyone`, the logon session's SID (what a
//! console program writes to: the console, the window station), a SID for
//! the objects the agent's processes create ([`objects_sid`]), and one SID
//! per write root ([`root_sid`]). Each write root gets one inherited allow
//! entry for its SID; nothing else on the machine names those SIDs, so the
//! agent's writes outside the roots fail unless the place grants `Everyone`
//! write. The entries are kept after the run: the next run in the project
//! finds them and changes nothing, where adding one makes Windows hand it to
//! every file below, which takes time in a large tree. They name SIDs no
//! account has, so they give no one else anything.
//!
//! Inside a root the policy's write denies that name a literal place
//! (`${project}/.git/**`, `**/.vscode`) get a deny entry for the root's SID on
//! that place, and a deny of `DELETE` on each folder between the root and it,
//! so the folder cannot be renamed away and replaced. Only places that exist
//! when the run starts can carry an entry; one made later, and every glob a
//! literal place cannot stand for (`**/*.code-workspace`, a `.git` deeper than
//! the root's top), stay the hook's. The run's report names them.

use openmoat_core::ir::{Access, Effect, Enforcement};
use openmoat_core::{AtomicAction, Kind};
use sha2::{Digest as _, Sha256};

use super::patterns::{Spot, has_glob, is_below, literal_tree, push_unique, split, spot};
use super::{Grants, Report};
use crate::state_acl::RawAce;

/// What a root's SID may do there: read, write, run and delete what is below,
/// and nothing over its access list or owner (no `WRITE_DAC`, `WRITE_OWNER`).
/// No `FILE_DELETE_CHILD` either: with it, a folder's SID could delete an
/// entry the deny below protects.
pub const GRANT_MASK: u32 = 0x0013_01BF;

/// What a deny entry takes away from a root's SID: every write right of a
/// file or folder (`FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_EA`,
/// `FILE_DELETE_CHILD`, `FILE_WRITE_ATTRIBUTES`, `DELETE`, `WRITE_DAC`,
/// `WRITE_OWNER`), and no read right.
pub const DENY_MASK: u32 = 0x000D_0156;

/// `DELETE`: what the folders above a denied place lose, so none is renamed.
pub const DELETE: u32 = 0x0001_0000;

/// Object inherit and container inherit: the entry reaches everything below.
pub const INHERIT: u8 = 0x03;

/// The flag of an entry Windows inherited rather than one set on the object.
const INHERITED: u8 = 0x10;

/// The prefix every SID of the run has: the form of a domain account's SID
/// (`S-1-5-21-a-b-c-rid`), with sub-authorities from a hash, so no real
/// domain's 96-bit identifier collides with one in practice. Not a capability
/// SID (`S-1-15-3-…`): Windows matches those against an app container's
/// capabilities, not a token's restricting SIDs.
const SID_PREFIX: &str = "S-1-5-21";

/// The allowance id for the denies the token cannot hold.
pub const UNHELD: &str = "windows.hook-only";

/// One access-list entry to set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The file or folder, slash-separated.
    pub path: String,
    /// The SID the entry names.
    pub sid: String,
    /// An allow entry; otherwise a deny entry.
    pub allows: bool,
    pub mask: u32,
    /// Whether the entry reaches everything below ([`INHERIT`]).
    pub inherit: bool,
}

/// What the agent may write: the roots with their SIDs, and the entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Each write root and its SID.
    pub roots: Vec<(String, String)>,
    /// Every entry to set, the roots' allow entries first.
    pub entries: Vec<Entry>,
}

impl Plan {
    /// The SIDs the token is restricted to besides `Everyone`, the logon
    /// session's and [`objects_sid`]: one per root.
    pub fn sids(&self) -> Vec<String> {
        let mut sids = Vec::new();
        for (_, sid) in &self.roots {
            push_unique(&mut sids, sid.clone());
        }
        sids
    }
}

/// The plan and what it leaves to the hook.
#[derive(Debug, Default)]
pub struct Generated {
    pub plan: Plan,
    pub report: Report,
}

/// A SID made from `label`: [`SID_PREFIX`] and four sub-authorities from its
/// SHA-256.
fn sid_of(label: &str) -> String {
    let digest = Sha256::digest(label.as_bytes());
    let mut sid = SID_PREFIX.to_owned();
    for chunk in digest.as_chunks::<4>().0.iter().take(4) {
        let value = u32::from_be_bytes(*chunk);
        sid.push('-');
        sid.push_str(&value.to_string());
    }
    sid
}

/// The SID that may write below `root`: the same for the same folder in
/// every run, whatever the case of its letters, so a later run finds the
/// entry the first one set.
pub fn root_sid(root: &str) -> String {
    sid_of(&format!("openmoat-run-write\0{}", root.to_lowercase()))
}

/// The SID the token's default access list grants, so the agent's
/// processes can write the pipes and other objects they create.
pub fn objects_sid() -> String {
    sid_of("openmoat-run-objects")
}

/// Whether `path` is an absolute Windows path below a drive's or share's top
/// (`C:/x`, `//server/share/x`).
fn windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":/";
    let share = path.starts_with("//") && !path.starts_with("//?/") && !path.starts_with("//./");
    drive || share
}

/// Whether `path` is a whole drive or the filesystem's root.
fn drive_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    path == "/" || (bytes.len() <= 3 && bytes.len() >= 2 && bytes[1] == b':')
}

/// The plan for the IR `ir` and the run's `grants`; `exists` says whether a
/// place is there now (only a place that exists can carry an entry).
pub fn generate(
    ir: &Enforcement,
    grants: &Grants,
    exists: &dyn Fn(&str) -> bool,
) -> anyhow::Result<Generated> {
    let mut g = Generated::default();
    let roots = roots(ir, grants, &mut g.report)?;
    for root in &roots {
        if !exists(root) {
            let message = format!(
                "`{root}` does not exist, so the run cannot grant it; create it before the run"
            );
            g.report.loss(Kind::FsWrite, "windows.write-root", message);
            continue;
        }
        let sid = root_sid(root);
        g.plan.entries.push(Entry {
            path: root.clone(),
            sid: sid.clone(),
            allows: true,
            mask: GRANT_MASK,
            inherit: true,
        });
        g.plan.roots.push((root.clone(), sid));
    }
    let mut unheld = Vec::new();
    let denied = denied_patterns(&ir.fs.write);
    for pattern in &denied {
        let mut inside = false;
        for (root, sid) in g.plan.roots.clone() {
            match target(pattern, &root) {
                Target::Outside => continue,
                Target::Place(place) if exists(&place) => deny(&mut g.plan, &root, &sid, &place),
                Target::Place(place) => push_unique(&mut unheld, place),
                Target::Unplaceable => push_unique(&mut unheld, pattern.clone()),
            }
            inside = true;
        }
        // `**/x` and `<root>/**/x` also match below the top, where no entry is set.
        let deeper = matches!(spot(pattern), Spot::Anywhere(_)) || pattern.contains("/**/");
        if inside && deeper {
            push_unique(&mut unheld, pattern.clone());
        }
    }
    if !unheld.is_empty() {
        let message = "the write-restricted token cannot refuse these inside a write root (a \
                       glob, a place below the root's top, or one that does not exist yet): the \
                       hook still decides them";
        g.report.allowance(Kind::FsWrite, UNHELD, unheld, message);
    }
    let reads: Vec<String> = ir
        .fs
        .read
        .deny
        .iter()
        .flat_map(|r| r.patterns.iter().cloned())
        .collect();
    if !reads.is_empty() {
        let message = "a write-restricted token does not restrict reads: every read the policy \
                       denies is open to the agent's commands, and the hook alone decides it";
        g.report
            .allowance(Kind::FsRead, "windows.reads", reads, message);
    }
    let message = "no Windows Filtering Platform filter: the proxy variables send programs \
                   through OpenMoat's proxy, and a program that ignores them connects directly";
    g.report
        .allowance(Kind::Net, "windows.network", Vec::new(), message);
    Ok(g)
}

/// The trees the agent may write: the literal trees the policy's write
/// allow rules name that no deny covers, the run's temp directory and the
/// `--write` paths. A policy that allows every write, or a grant of a whole
/// drive, is refused: the token would then hold nothing.
fn roots(ir: &Enforcement, grants: &Grants, report: &mut Report) -> anyhow::Result<Vec<String>> {
    if ir.fs.write.default == Effect::Allow {
        anyhow::bail!(
            "the policy allows every write (`defaults: {{fs.write: allow}}`), so a \
             write-restricted token would hold nothing; `openmoat run` on Windows needs writes \
             denied by default"
        );
    }
    let checker = ir.checker()?;
    let mut roots = Vec::new();
    for rule in &ir.fs.write.allow {
        for pattern in split(&rule.patterns).0 {
            let Some(tree) = literal_tree(pattern) else {
                let message =
                    format!("`{pattern}` cannot be granted as a path, so it stays denied");
                report.loss(Kind::FsWrite, &rule.id, message);
                continue;
            };
            let atom = AtomicAction::FsWrite {
                path: tree.to_owned(),
            };
            if checker.check_os(&atom) == Some(Effect::Deny) {
                let message = format!("`{tree}` is inside a denied path, so it is not granted");
                report.loss(Kind::FsWrite, &rule.id, message);
            } else {
                push_unique(&mut roots, tree.to_owned());
            }
        }
    }
    for path in grants.tmpdir.iter().chain(&grants.writes) {
        push_unique(&mut roots, path.clone());
    }
    let mut kept = Vec::new();
    for root in roots {
        if drive_root(&root) {
            anyhow::bail!(
                "`{root}` is a whole drive: `openmoat run` on Windows grants writes on folders, \
                 never a drive"
            );
        }
        if windows_path(&root) {
            kept.push(root);
        } else {
            let message = format!("`{root}` is not a Windows path, so it is not granted");
            report.loss(Kind::FsWrite, "windows.write-root", message);
        }
    }
    Ok(kept)
}

/// The write denies and the `!` exceptions of the allow rules.
fn denied_patterns(access: &Access) -> Vec<String> {
    let mut patterns = Vec::new();
    let denied = access.deny.iter().flat_map(|r| split(&r.patterns).0);
    let excluded = access.allow.iter().flat_map(|r| split(&r.patterns).1);
    for pattern in denied.chain(excluded) {
        push_unique(&mut patterns, pattern.to_owned());
    }
    patterns
}

/// Where a deny pattern falls for one root.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// Not inside the root.
    Outside,
    /// The one place inside the root it names at the root's top.
    Place(String),
    /// Inside the root, but no single place stands for it.
    Unplaceable,
}

/// Where `pattern` falls for `root`: `<root>/x` and `<root>/x/**` name `x`;
/// `**/x`, `**/x/**` and `<root>/**/x…` name `x` at the root's top; any other
/// glob inside the root names no place.
fn target(pattern: &str, root: &str) -> Target {
    let at_top = |rest: &str| match literal_tree(rest) {
        Some(name) if !name.starts_with('/') => Target::Place(format!("{root}/{name}")),
        _ => Target::Unplaceable,
    };
    if let Spot::Anywhere(rest) = spot(pattern) {
        return at_top(rest);
    }
    let inside = |p: &str| is_below(p, root);
    if let Some(rest) = pattern
        .strip_prefix(root)
        .and_then(|r| r.strip_prefix("/**/"))
    {
        return at_top(rest);
    }
    match literal_tree(pattern) {
        Some(place) if inside(place) => Target::Place(place.to_owned()),
        Some(_) => Target::Outside,
        None => {
            let base = pattern
                .split(['*', '?', '[', '{'])
                .next()
                .unwrap_or(pattern);
            if base.starts_with(&format!("{}/", root.trim_end_matches('/'))) && has_glob(pattern) {
                Target::Unplaceable
            } else {
                Target::Outside
            }
        }
    }
}

/// A deny entry for `sid` on `place`, and a deny of `DELETE` on every folder
/// between `root` and it.
fn deny(plan: &mut Plan, root: &str, sid: &str, place: &str) {
    let entry = Entry {
        path: place.to_owned(),
        sid: sid.to_owned(),
        allows: false,
        mask: DENY_MASK,
        inherit: true,
    };
    if !plan.entries.contains(&entry) {
        plan.entries.push(entry);
    }
    let mut above = place;
    while let Some((parent, _)) = above.rsplit_once('/') {
        if !is_below(parent, root) {
            break;
        }
        let entry = Entry {
            path: parent.to_owned(),
            sid: sid.to_owned(),
            allows: false,
            mask: DELETE,
            inherit: false,
        };
        if !plan.entries.contains(&entry) {
            plan.entries.push(entry);
        }
        above = parent;
    }
}

/// Whether `entry` still has to be set on a place whose explicit entries are
/// `aces`: no entry set on the place itself (not inherited) names its SID
/// with the same kind, at least its rights and its inheritance.
pub fn needs_change(aces: &[RawAce], entry: &Entry) -> bool {
    !aces.iter().any(|ace| {
        ace.flags & INHERITED == 0
            && ace.allows == entry.allows
            && ace.sid.eq_ignore_ascii_case(&entry.sid)
            && ace.mask & entry.mask == entry.mask
            && (!entry.inherit || ace.flags & INHERIT == INHERIT)
    })
}

#[cfg(test)]
mod tests;
