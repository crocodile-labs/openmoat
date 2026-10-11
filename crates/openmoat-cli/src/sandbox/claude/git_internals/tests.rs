use openmoat_core::DEFAULT_POLICY;

use super::super::tests::{generated, generated_for};

const LITERALS: [&str; 4] = [
    "Edit(./.git/hooks)",
    "Edit(./.git/config)",
    "Edit(./.git/config.worktree)",
    "Edit(./.git/info/attributes)",
];

/// The Linux runtime drops the `/**/.git/…` globs, so the working directory's
/// own exec vectors are denied by path; macOS keeps the globs.
#[test]
fn linux_denies_the_working_directory_git_internals_by_path() {
    let linux = generated_for(DEFAULT_POLICY, true);
    for rule in LITERALS {
        assert!(
            linux.deny_rules.contains(&rule.to_owned()),
            "{rule}: {:?}",
            linux.deny_rules
        );
    }
    assert!(
        linux
            .report
            .losses
            .iter()
            .any(|l| l.rule == "claude-code.linux-git-rules"),
        "`git init` in a working directory without `.git` is reported: {:?}",
        linux.report.losses
    );
    let mac = generated(DEFAULT_POLICY);
    assert!(
        !mac.deny_rules.iter().any(|r| r.contains(".git/")),
        "{:?}",
        mac.deny_rules
    );
}

/// Without the `.git` exception the policy's own deny covers all of `.git`.
#[test]
fn a_policy_that_denies_git_needs_no_literals() {
    let out = generated_for(
        "version: 1\ndeny:\n  - id: g\n    fs.write: ['**/.git/**']\n",
        true,
    );
    for rule in LITERALS {
        assert!(
            !out.deny_rules.contains(&rule.to_owned()),
            "{rule}: {:?}",
            out.deny_rules
        );
    }
    assert!(
        out.deny_rules.contains(&"Edit(//**/.git/**)".to_owned()),
        "{:?}",
        out.deny_rules
    );
}
