//! `openmoat run`'s proxy decides hosts with the user policy and the
//! project's repository deny rules; a repository allow never widens it, even
//! once trusted. Both hosts are refused before any name is resolved, so the
//! test needs no network.

use super::confined::{ran, retried};
use super::*;
use crate::common::stdout;

const REPO: &str = "version: 1\n\
    deny:\n  - id: no-npm\n    net: [registry.npmjs.org]\n\
    allow:\n  - id: extra\n    net: [repo-only.example.com]\n";

#[test]
fn a_repository_deny_is_refused_by_the_runs_proxy_and_its_allow_is_not_used() {
    let (sb, project) = installed_with_secret();
    std::fs::create_dir_all(project.join(".moat")).unwrap();
    std::fs::write(project.join(".moat/policy.yaml"), REPO).unwrap();
    let trusted = sb.moat_as_person(&["trust", &project.to_string_lossy()]);
    assert_eq!(trusted.status.code(), Some(OK), "{}", text(&trusted));
    // `registry.npmjs.org` is allowed by the default policy; the repository denies it.
    let script = "curl -sS -m 30 -w ' npm=%{http_code}\\n' http://registry.npmjs.org/
         curl -sS -m 30 -w ' extra=%{http_code}\\n' http://repo-only.example.com/";
    let out = retried(|| run_sh(&sb, &project, script));
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    let printed = stdout(&out);
    assert!(printed.contains("npm=403"), "{shown}");
    assert!(printed.contains("repo:no-npm"), "{shown}");
    assert!(printed.contains("extra=403"), "{shown}");
    assert!(!printed.contains("repo:extra"), "{shown}");
}
