//! A `.git` below an allowed directory, and the nested-`.git` allowance
//! `sandbox sync` reports for it.

use openmoat_core::Policy;

use super::super::generate_with;
use super::{mode, render};
use crate::sandbox::lower_for_hosts;

/// `moat allow --dir` leaves `.git` out of its write grant: the directory is
/// writable, its own `.git` read-only, and the nested `**/.git/**` is no deny
/// glob, which would make every `.git` below it unreadable.
#[test]
fn an_allowed_directory_keeps_its_git_read_only_and_readable() {
    let policy = Policy::parse(
        "version: 1\nallow:\n  - id: approved-1\n    fs.read: ['/w/lib', '/w/lib/**']\n    \
         fs.write: ['/w/lib', '/w/lib/**', '!/w/lib/.git/**', '!/w/lib/**/.git/**']\n",
    )
    .expect("test policy lints");
    let ir = lower_for_hosts(&policy, "/Users/me", None, Vec::new(), false).expect("lowers");
    let out = generate_with(&ir, &["/Users/me".into()], None, |p| {
        p.starts_with("/w/lib")
    })
    .expect("generates");
    assert_eq!(mode(&out, &[], "/w/lib"), Some("write"), "{}", render(&out));
    assert_eq!(
        mode(&out, &[], "/w/lib/.git"),
        Some("read"),
        "{}",
        render(&out)
    );
    assert!(!render(&out).contains("/w/lib/**/.git"), "{}", render(&out));
    assert!(
        out.report
            .allowances
            .iter()
            .any(|a| a.rule == "codex.nested-git"),
        "{:?}",
        out.report.allowances
    );
}

/// Two allowed directories need the same nested-`.git` allowance; `sandbox sync`
/// lists it once.
#[test]
fn the_nested_git_allowance_is_reported_once() {
    let grant = |id: &str, dir: &str| {
        format!(
            "  - id: {id}\n    fs.read: ['{dir}', '{dir}/**']\n    fs.write: ['{dir}', \
             '{dir}/**', '!{dir}/.git/**', '!{dir}/**/.git/**']\n"
        )
    };
    let yaml = format!(
        "version: 1\nallow:\n{}{}",
        grant("approved-1", "/w/lib"),
        grant("approved-2", "/w/app")
    );
    let policy = Policy::parse(&yaml).expect("test policy lints");
    let ir = lower_for_hosts(&policy, "/Users/me", None, Vec::new(), false).expect("lowers");
    let out = generate_with(&ir, &["/Users/me".into()], None, |p| p.starts_with("/w/"))
        .expect("generates");
    let nested = out
        .report
        .allowances
        .iter()
        .filter(|a| a.rule == "codex.nested-git")
        .count();
    assert_eq!(nested, 1, "{:?}", out.report.allowances);
}
