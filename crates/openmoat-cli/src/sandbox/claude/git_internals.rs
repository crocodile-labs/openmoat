//! The `.git` subtree exception: user settings cannot name the project, so
//! the policy's `.git/**` write deny is lowered to the exec vectors below and
//! the rest of `.git` becomes an allowance. On Linux, where the runtime drops
//! those globs, the working directory's own vectors are also denied by path.

use openmoat_core::Kind;

use super::Filesystem;
use super::Report;
use crate::sandbox::patterns::push_unique;

/// Paths in `.git` that make git run code or read another repository's
/// (`core.hooksPath`, `core.fsmonitor`, filters and aliases live in config),
/// denied although the rest of `.git` is writable. A directory in `denyWrite`
/// covers its subtree, which is what `hooks` needs.
const GIT_EXEC_VECTORS: &[&str] = &[
    "/**/.git/hooks",
    "/**/.git/hooks/**",
    "/**/.git/config",
    "/**/.git/config.worktree",
    "/**/.git/info/attributes",
    "/**/.git/worktrees/*/config.worktree",
    "/**/.git/worktrees/*/commondir",
    "/**/.git/modules/**/hooks",
    "/**/.git/modules/**/hooks/**",
    "/**/.git/modules/**/config",
    "/**/.git/modules/**/config.worktree",
    "/**/.git/modules/**/info/attributes",
    "/**/.git/modules/**/commondir",
];

/// The vectors in the working directory's `.git` itself, which Linux denies by
/// path (`Edit(./…)`). A linked worktree's `commondir` and the submodules'
/// vectors sit below names host-wide settings cannot know, so they stay globs.
const GIT_LITERALS: &[&str] = &[
    ".git/hooks",
    ".git/config",
    ".git/config.worktree",
    ".git/info/attributes",
];

impl Filesystem {
    /// The policy keeps the project's `.git` from writes, but user settings
    /// cannot name the project, and denying `.git` everywhere breaks `git commit`.
    /// Only what makes git run code or follow another repository is denied
    /// (ADR-021, amendment of 2026-10-06); the rest of `.git` is an allowance.
    pub(super) fn git_internals(&mut self, report: &mut Report) {
        for vector in GIT_EXEC_VECTORS {
            push_unique(&mut self.deny_write, (*vector).to_owned());
        }
        report.allowance(
            Kind::FsWrite,
            "claude-code.git-internals",
            vec!["/**/.git/**".to_owned()],
            "user settings cannot name the project, so sandboxed commands may write `.git` \
             (objects, refs, index: `git commit` works) in every directory, except what makes git \
             run code or follow another repository (hooks, config, config.worktree, \
             info/attributes, a linked worktree's commondir, the same in submodules); a script \
             can still rewrite history, and the hook still asks for file-tool writes to `.git`",
        );
    }

    /// On Linux, the `Edit(./.git/…)` rules for [`GIT_LITERALS`] when the
    /// `.git` exception applies. The runtime mounts over a denied path's first
    /// missing component, so in a working directory without `.git` none can be
    /// created there; it denies `.git/hooks` and `.git/config` itself only when
    /// `.git` is a directory, and skips a path below a file (a linked worktree's
    /// `.git`).
    pub(super) fn git_literals(&self, rules: &mut Vec<String>, report: &mut Report) {
        if !self.deny_write.iter().any(|e| e == GIT_EXEC_VECTORS[0]) {
            return;
        }
        for path in GIT_LITERALS {
            push_unique(rules, format!("Edit(./{path})"));
        }
        report.loss(
            Kind::FsWrite,
            "claude-code.linux-git-rules",
            "on Linux `.git` hooks, config, config.worktree and info/attributes are denied by path \
             in the working directory, so where it has no `.git` yet sandboxed commands cannot \
             create one there (`git init` in that directory fails)"
                .into(),
        );
    }
}

#[cfg(test)]
mod tests;
