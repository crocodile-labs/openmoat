use openmoat_core::{DEFAULT_POLICY, Policy};

use super::super::tests::generated;
use super::super::{Generated, generate};
use super::{deny_edit, rule_path};
use crate::sandbox::lower_for_hosts;

/// The default policy lowered for a Windows home (`C:/Users/me`).
fn generated_on_windows() -> Generated {
    let policy = Policy::parse(DEFAULT_POLICY).expect("lints");
    let ir = lower_for_hosts(&policy, "C:/Users/me", None, Vec::new(), true).expect("lowers");
    generate(&ir, None, false).expect("generates")
}

fn has(out: &Generated, rule: &str) -> bool {
    out.deny_rules.iter().any(|r| r == rule)
}

/// With the hook gone, Claude Code's file tools still refuse the policy's
/// secrets and OpenMoat's own files: the deny rules are written on every OS.
#[test]
fn every_os_gets_deny_rules_for_secrets_and_kernel_files() {
    let mac = generated(DEFAULT_POLICY);
    for rule in [
        "Read(//Users/me/.ssh)",
        "Read(//Users/me/.aws)",
        "Read(//**/.env)",
        "Read(//**/.env.*)",
        "Edit(//Users/me/.ssh)",
        "Edit(//Users/me/.moat)",
        "Edit(//**/.moat/**)",
        "Edit(//Users/me/.claude/settings.json)",
        "Edit(//**/.claude/settings.local.json)",
        "Edit(//**/.codex/hooks.json)",
        "Edit(//**/bin/moat)",
        "Edit(//**/bin/moat.exe)",
        "Edit(//**/apps/moat/current)",
        "Edit(//Users/me/.zshrc)",
    ] {
        assert!(has(&mac, rule), "{rule}: {:?}", mac.deny_rules);
    }
    for rule in &mac.deny_rules {
        // `Edit(./.cursor/hooks.json)` and the like keep another agent's
        // directory in the working directory in place (`nodes.rs`).
        let node = rule.starts_with("Edit(./.") && rule.matches('/').count() == 2;
        assert!(
            rule.starts_with("Read(//") || rule.starts_with("Edit(//") || node,
            "{rule}"
        );
        assert!(
            !rule.contains(".git/"),
            "the hook asks for `.git`, never denies: {rule}"
        );
    }
    assert!(
        !has(&mac, "Edit(//Users/me/.claude)"),
        "a directory node the sandbox leaves out would cover `.claude/worktrees`"
    );
    assert!(
        mac.report
            .losses
            .iter()
            .any(|l| l.rule == "claude-code.static-denies"),
        "{:?}",
        mac.report.losses
    );
}

/// Windows paths are matched in POSIX form, `C:\Users\me` as `/c/Users/me`.
#[test]
fn windows_rules_name_the_drive_in_posix_form() {
    let out = generated_on_windows();
    for rule in [
        "Read(//c/Users/me/.ssh)",
        "Edit(//c/Users/me/.moat)",
        "Edit(//**/bin/moat.exe)",
        "Read(//**/.env)",
    ] {
        assert!(has(&out, rule), "{rule}: {:?}", out.deny_rules);
    }
    assert!(
        !out.deny_rules.iter().any(|r| r.contains("C:")),
        "{:?}",
        out.deny_rules
    );
}

#[test]
fn rule_paths_anchor_at_the_filesystem_root() {
    assert_eq!(
        rule_path("/Users/me/.ssh").as_deref(),
        Some("//Users/me/.ssh")
    );
    assert_eq!(rule_path("/**/.env").as_deref(), Some("//**/.env"));
    assert_eq!(rule_path("D:/x/y").as_deref(), Some("//d/x/y"));
    assert_eq!(
        rule_path("//srv/share/x"),
        None,
        "no documented UNC spelling"
    );
    assert_eq!(rule_path("relative"), None);
}

/// The `moat` binary's literal paths join the rules once, on every OS, in the
/// same spelling as the policy's.
#[test]
fn the_binary_paths_become_edit_rules_once() {
    let mut mac = generated(DEFAULT_POLICY);
    let paths = ["/opt/tools/moatd".to_owned(), "/opt/tools".to_owned()];
    let before = mac.deny_rules.len();
    deny_edit(&mut mac, &paths);
    deny_edit(&mut mac, &paths);
    assert_eq!(mac.deny_rules.len(), before + 2, "{:?}", mac.deny_rules);
    assert!(has(&mac, "Edit(//opt/tools/moatd)") && has(&mac, "Edit(//opt/tools)"));

    let mut windows = generated_on_windows();
    deny_edit(
        &mut windows,
        &[
            "C:/Tools/moat/moat.exe".to_owned(),
            "//server/share/moat.exe".to_owned(),
        ],
    );
    assert!(has(&windows, "Edit(//c/Tools/moat/moat.exe)"));
    assert!(!windows.deny_rules.iter().any(|r| r.contains("server")));
}
