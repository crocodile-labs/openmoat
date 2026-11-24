//! `mint` secret sources and `helper:` (ADR-118), end to end, with no network:
//! the lint names the credential a mint starts from when the agent could read
//! it, a mint that would not narrow does not load, and the helper client asks
//! nothing outside `openmoat run`.

use std::fs;

use crate::common::{OK, Sandbox, USAGE, stderr, stdout, text};

const MINT: &str = "\nsecrets:\n  - id: gh-git\n    host: github.com\n    header: Authorization\n    \
                    helper: { git: { username: x-access-token } }\n    source:\n      mint:\n        \
                    github-app:\n          app: Iv23liExample\n          installation: 42\n          \
                    key: ~/apps/openmoat.pem\n          repositories: [openmoat]\n";

fn with_policy(sb: &Sandbox, extra: &str) {
    let policy = sb.home.join(".moat/policy.yaml");
    let text = fs::read_to_string(&policy).unwrap();
    fs::write(&policy, format!("{text}{extra}")).unwrap();
}

/// Attack: the App's private key sits where the agent can read it. The lint
/// names it.
#[test]
fn the_lint_names_the_key_a_mint_starts_from() {
    let sb = Sandbox::installed(&[]);
    with_policy(
        &sb,
        &format!("{MINT}          permissions: {{ contents: read }}\n"),
    );
    let lint = sb.moat(&["policy", "lint"]);
    assert!(
        text(&lint).contains("~/apps/openmoat.pem"),
        "{}",
        text(&lint)
    );
}

/// Attack: a mint without `permissions` would get every permission of the
/// App. The policy does not load.
#[test]
fn a_mint_that_would_not_narrow_does_not_load() {
    let sb = Sandbox::installed(&[]);
    with_policy(&sb, MINT);
    let lint = sb.moat(&["policy", "lint"]);
    assert_ne!(lint.status.code(), Some(OK), "{}", text(&lint));
    assert!(text(&lint).contains("permissions"), "{}", text(&lint));
}

/// Outside `openmoat run` there is no proxy to ask: the helper says so and
/// prints nothing a tool would take for a credential.
#[test]
fn the_helper_asks_nothing_outside_a_run() {
    let sb = Sandbox::installed(&[]);
    // The sandbox's environment is cleared: no proxy variables.
    let out = sb.moat(&["credential", "aws", "s3"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(stderr(&out).contains("openmoat run"), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
}
