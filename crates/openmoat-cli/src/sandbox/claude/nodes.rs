//! Directory nodes the policy denies writing (`**/.cursor`, `~/.claude`), which
//! `denyWrite` cannot name without covering their whole subtree.

use openmoat_core::Kind;

use super::{CLAUDE_DIR, Filesystem, Report};
use crate::sandbox::patterns::{has_glob, is_below, push_unique};

impl Filesystem {
    /// A directory node in `denyWrite` (no rename or delete of `.claude`) would
    /// make its whole subtree read-only, `.claude/worktrees/*` included, so a
    /// node with more specific entries below it is left out and listed.
    pub(super) fn drop_directory_nodes(&mut self, report: &mut Report) {
        let dropped: Vec<String> = self
            .nodes
            .iter()
            .filter(|node| !self.trees.contains(node))
            .filter(|node| self.deny_write.iter().any(|e| is_below(e, node)))
            .cloned()
            .collect();
        if dropped.is_empty() {
            return;
        }
        self.deny_write.retain(|e| !dropped.contains(e));
        report.allowance(
            Kind::FsWrite,
            "claude-code.directory-nodes",
            dropped,
            "a directory in denyWrite covers its subtree, so these directory nodes are left out \
             and only the files below them are denied. On macOS Claude Code keeps each directory \
             above a literal denyWrite path from being renamed or removed: the home's, the \
             working directory's through `Edit(./…)` rules, its own `.claude`; elsewhere (a \
             subdirectory, Linux) a sandboxed command may move one, and the hook denies the \
             agent moving one (`kernel-self`)",
        );
    }

    /// The `Edit(./<dir>/<name>)` rules, on every OS, for each file the policy
    /// denies writing directly below a directory node `denyWrite` leaves out
    /// (`claude-code.directory-nodes` in `report`; `.claude` is Claude Code's
    /// own and keeps its settings itself). Claude Code merges the rule into its
    /// sandbox as a literal path in the working directory, and on macOS its
    /// sandbox keeps every directory above a literal `denyWrite` path from
    /// being renamed or removed, which a `**/` glob does not get: so a command
    /// cannot move the working directory's `.cursor`, `.codex`, `.copilot` or
    /// `.gemini` away and put another in its place, while the files inside
    /// stay as writable as before. On Linux they are among [`Self::edit_rules`].
    pub(super) fn node_rules(&self, report: &Report) -> Vec<String> {
        let dropped = report
            .allowances
            .iter()
            .filter(|a| a.rule == "claude-code.directory-nodes")
            .flat_map(|a| &a.patterns);
        let dirs: Vec<&str> = dropped
            .filter_map(|node| node.strip_prefix("/**/"))
            .filter(|dir| !dir.contains('/') && !has_glob(dir) && *dir != CLAUDE_DIR)
            .collect();
        let mut rules = Vec::new();
        for entry in &self.deny_write {
            let path = entry.strip_suffix("/**").unwrap_or(entry);
            let Some((dir, name)) = path.strip_prefix("/**/").and_then(|r| r.split_once('/'))
            else {
                continue;
            };
            if dirs.contains(&dir) && !name.contains('/') && !has_glob(name) {
                push_unique(&mut rules, format!("Edit(./{dir}/{name})"));
            }
        }
        rules
    }
}
