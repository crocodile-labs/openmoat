//! `.git` in Claude Code's sandbox: writable for `git commit`, except what makes
//! git run code, in the project and in a directory `moat allow --dir` granted.

use openmoat_core::DEFAULT_POLICY;

use super::{generated, list};

#[test]
fn git_is_writable_except_what_makes_it_run_code() {
    let out = generated(DEFAULT_POLICY);
    let deny = list(&out, "/filesystem/denyWrite");
    for whole in ["/**/.git", "/**/.git/**", "/**/**/.git", "/**/**/.git/**"] {
        assert!(
            !deny.contains(&whole.to_owned()),
            "git commit needs {whole}"
        );
    }
    for vector in [
        "/**/.git/hooks",
        "/**/.git/hooks/**",
        "/**/.git/config",
        "/**/.git/config.worktree",
        "/**/.git/info/attributes",
        "/**/.git/worktrees/*/config.worktree",
        "/**/.git/worktrees/*/commondir",
        "/**/.git/modules/**/hooks",
        "/**/.git/modules/**/config",
    ] {
        assert!(deny.contains(&vector.to_owned()), "{vector}: {deny:?}");
    }
    // the root's `.git/**` and the nested `**/.git/**` exclusions lower to it once
    let allowances: Vec<_> = (out.report.allowances.iter())
        .filter(|a| a.rule == "claude-code.git-internals")
        .collect();
    assert!(matches!(allowances[..], [a] if a.patterns == ["/**/.git/**"]));
    assert!(
        !out.report.losses.iter().any(|l| l.message.contains(".git")),
        "{:?}",
        out.report.losses
    );
    assert!(
        deny.contains(&"/**/.moat".to_owned()),
        "other exceptions stay denied"
    );
}

#[test]
fn a_policy_that_denies_git_keeps_it_denied() {
    let out = generated(
        "version: 1\ndeny:\n  - id: g\n    fs.write: ['**/.git/**']\nallow:\n  - id: p\n    fs.write: ['${project}/**', '!${project}/.git/**']\n",
    );
    let deny = list(&out, "/filesystem/denyWrite");
    assert!(deny.contains(&"/**/.git".to_owned()), "{deny:?}");
}

/// `moat allow --dir` leaves `.git` out of its write grant: the directory is
/// writable and `git commit` works there, and only what makes git run code is
/// denied, as in the project.
#[test]
fn an_allowed_directory_keeps_git_writable_except_what_runs_code() {
    let out = generated(
        "version: 1\nallow:\n  - id: approved-1\n    fs.read: ['/w/lib', '/w/lib/**']\n    \
         fs.write: ['/w/lib', '/w/lib/**', '!/w/lib/.git/**', '!/w/lib/**/.git/**']\n",
    );
    let allow = list(&out, "/filesystem/allowWrite");
    assert!(allow.contains(&"/w/lib".to_owned()), "{allow:?}");
    let deny = list(&out, "/filesystem/denyWrite");
    assert!(!deny.iter().any(|d| d.starts_with("/w/lib")), "{deny:?}");
    assert!(deny.contains(&"/**/.git/hooks".to_owned()), "{deny:?}");
    assert!(
        !out.report
            .losses
            .iter()
            .any(|l| l.message.contains("/w/lib")),
        "{:?}",
        out.report.losses
    );
}

/// Files CI or a commit hook runs later (`runs-later`): the hook asks, the
/// sandbox denies none of them and lists them once.
#[test]
fn files_run_later_are_asked_by_the_hook_not_denied_by_the_sandbox() {
    let out = generated(DEFAULT_POLICY);
    let deny = list(&out, "/filesystem/denyWrite");
    for name in [
        ".github",
        ".husky",
        "Jenkinsfile",
        ".gitlab-ci.yml",
        "tasks.json",
    ] {
        assert!(!deny.iter().any(|d| d.contains(name)), "{name}: {deny:?}");
    }
    let listed: Vec<_> = (out.report.allowances.iter())
        .filter(|a| a.rule == "claude-code.runs-later")
        .collect();
    assert!(
        matches!(listed[..], [a] if a.patterns.iter().any(|p| p == "**/.github/workflows/**")),
        "{:?}",
        out.report.allowances
    );
}
