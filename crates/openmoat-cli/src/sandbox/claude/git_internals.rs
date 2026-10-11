//! The `.git` subtree exception: user settings cannot name the project, so
//! the policy's `.git/**` write deny is lowered to the exec vectors below and
//! the rest of `.git` becomes an allowance.

use openmoat_core::Kind;

use super::Filesystem;
use super::Report;
use crate::sandbox::patterns::push_unique;

/// The allowance's id in the report.
const GIT_INTERNALS: &str = "claude-code.git-internals";

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

impl Filesystem {
    /// The policy keeps the project's `.git` from writes, but user settings
    /// cannot name the project, and denying `.git` everywhere breaks `git commit`.
    /// Only what makes git run code or follow another repository is denied
    /// (ADR-021, amendment of 2026-10-06); the rest of `.git` is an allowance.
    /// The vectors already name every `.git` directory, nested ones included,
    /// so the policy's `.git/**` and `**/.git/**` exclusions both lower to them once.
    pub(super) fn git_internals(&mut self, report: &mut Report) {
        if report.allowances.iter().any(|a| a.rule == GIT_INTERNALS) {
            return;
        }
        for vector in GIT_EXEC_VECTORS {
            push_unique(&mut self.deny_write, (*vector).to_owned());
        }
        report.allowance(
            Kind::FsWrite,
            GIT_INTERNALS,
            vec!["/**/.git/**".to_owned()],
            "user settings cannot name the project, so sandboxed commands may write `.git` \
             (objects, refs, index: `git commit` works) in every directory, except what makes git \
             run code or follow another repository (hooks, config, config.worktree, \
             info/attributes, a linked worktree's commondir, the same in submodules); a script \
             can still rewrite history or create a `.git` file (`gitdir: …`) in a subdirectory, \
             and the hook still asks for file-tool writes to any `.git`",
        );
    }
}
