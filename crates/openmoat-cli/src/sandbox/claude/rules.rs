//! The `permissions.deny` rules OpenMoat writes into Claude Code's user
//! settings.
//!
//! On every OS each `denyRead` and `denyWrite` entry a policy deny rule produced
//! is also a `Read(//…)` or `Edit(//…)` rule. Claude Code applies those rules
//! itself, so its file tools refuse the policy's secrets and OpenMoat's own
//! files when the hook does not run at all (a missing or killed `moat`, which
//! the host treats as no answer). The rule syntax (the permissions docs, "Read
//! and Edit"): `//` anchors at the filesystem root, a single `/` would anchor
//! at `~/.claude` in user settings; a path names its subtree too, as in
//! gitignore; on Windows paths are matched in POSIX form, `C:\x` as `/c/x`.
//!
//! On Linux `Read(./**/…)` and `Edit(./…)` rules are added for the sandbox
//! runtime's sake (see the module documentation of [`super`]); on every OS the
//! `Edit(./<dir>/<name>)` rules that keep another agent's directory in the
//! working directory from being moved (`nodes.rs`).

use openmoat_core::Kind;

use super::{Filesystem, Generated, Report};
use crate::sandbox::patterns::push_unique;

impl Filesystem {
    /// The `Read(//…)` and `Edit(//…)` rules for every entry a policy deny rule
    /// produced and the sandbox block still lists (a directory node left out
    /// there would cover its subtree here too).
    pub(super) fn static_rules(&self, report: &mut Report) -> Vec<String> {
        let mut rules = Vec::new();
        for (tool, denied, listed) in [
            ("Read", &self.denied_read, &self.deny_read),
            ("Edit", &self.denied_write, &self.deny_write),
        ] {
            for entry in denied.iter().filter(|e| listed.contains(e)) {
                if let Some(path) = rule_path(entry) {
                    push_unique(&mut rules, format!("{tool}({path})"));
                }
            }
        }
        if !rules.is_empty() {
            report.loss(
                Kind::FsRead,
                "claude-code.static-denies",
                "Claude Code's own deny rules for these paths hold for its file tools when the \
                 hook does not run, and refuse an exception the hook allows (such as \
                 `.env.example`) too"
                    .into(),
            );
        }
        rules
    }
}

/// Add an `Edit(//…)` rule for each of `paths`, the `moat` binary's literal
/// paths ([`sandbox_paths`](crate::install::self_paths::sandbox_paths)): the
/// `**/bin/moat` globs miss a binary installed under another name or prefix.
/// Like every rule here, `hosts.json` records the ones added, so `uninstall`
/// removes exactly those.
pub fn deny_edit(generated: &mut Generated, paths: &[String]) {
    for path in paths.iter().filter_map(|p| rule_path(p)) {
        push_unique(&mut generated.deny_rules, format!("Edit({path})"));
    }
}

/// `entry`, an absolute `denyRead` or `denyWrite` entry in slash form, as the
/// path of a permission rule; `None` for a network (UNC) path, which the docs
/// give no spelling for.
fn rule_path(entry: &str) -> Option<String> {
    if entry.starts_with("//") {
        return None;
    }
    if entry.starts_with('/') {
        return Some(format!("/{entry}"));
    }
    let mut chars = entry.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(drive), Some(':'), Some('/')) if drive.is_ascii_alphabetic() => {
            Some(format!("//{}/{}", drive.to_ascii_lowercase(), &entry[3..]))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
