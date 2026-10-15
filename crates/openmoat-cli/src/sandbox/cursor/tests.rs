use openmoat_core::{DEFAULT_POLICY, Policy};
use serde_json::{Value, json};

use super::*;
use crate::sandbox::{assert_golden, lower_for_hosts};

pub(super) fn generated(yaml: &str) -> Generated {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ir = lower_for_hosts(&policy, "/Users/me", None, Vec::new(), false).expect("lowers");
    generate(&ir, crate::sandbox::proxy_port(&policy)).expect("generates")
}

fn list(generated: &Generated, pointer: &str) -> Vec<String> {
    let value = Value::Object(generated.settings.clone());
    serde_json::from_value(value.pointer(pointer).cloned().unwrap_or(json!([]))).unwrap()
}

fn rules(report: &Report) -> Vec<&str> {
    let losses = report.losses.iter().map(|l| l.rule.as_str());
    losses
        .chain(report.allowances.iter().map(|a| a.rule.as_str()))
        .collect()
}

/// The file and report for the default policy, as a reviewer reads them.
#[test]
fn default_policy_matches_the_golden_settings() {
    let out = generated(DEFAULT_POLICY);
    let actual = serde_json::to_string_pretty(&json!({
        "sandbox.json": out.settings,
        "losses": out.report.losses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "allowances": out.report.allowances.iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
    .unwrap();
    assert_golden("cursor-default.json", &(actual + "\n"));
}

#[test]
fn the_sandbox_is_on_with_a_workspace_read_boundary() {
    let out = generated(DEFAULT_POLICY);
    assert_eq!(out.settings["type"], json!("workspace_readwrite"));
    assert_eq!(out.settings["readBoundary"], json!("workspace"));
    assert_eq!(out.settings["networkPolicy"]["default"], json!("deny"));
    assert_eq!(
        list(&out, "/additionalReadwritePaths"),
        Vec::<String>::new()
    );
}

#[test]
fn protected_paths_are_never_granted_and_a_root_holding_one_is_left_out() {
    let out = generated(DEFAULT_POLICY);
    let reads = list(&out, "/additionalReadPaths");
    for granted in ["/usr", "/Users/me/.gitconfig", "/Users/me/.rustup"] {
        assert!(reads.contains(&granted.to_owned()), "{granted}: {reads:?}");
    }
    assert!(
        reads
            .iter()
            .all(|p| !p.contains(".ssh") && !p.contains(".aws")),
        "{reads:?}"
    );
    assert!(
        !reads.contains(&"/Users/me/.cargo".to_owned()),
        "~/.cargo holds ~/.cargo/credentials, which sandbox.json cannot close"
    );
    let loss = out
        .report
        .losses
        .iter()
        .find(|l| l.message.contains("`/Users/me/.cargo` holds a denied path"));
    assert!(loss.is_some(), "{:?}", out.report.losses);
}

#[test]
fn what_cannot_be_denied_in_the_workspace_is_listed_as_wider() {
    let out = generated(DEFAULT_POLICY);
    let open = |rule: &str| {
        out.report
            .allowances
            .iter()
            .find(|a| a.rule == rule)
            .map(|a| a.patterns.clone())
            .unwrap_or_default()
    };
    assert!(open("cursor.reads-in-workspace").contains(&"**/.env".to_owned()));
    let writes = open("cursor.writes-in-workspace");
    assert!(
        writes.contains(&"**/.cursor/hooks.json".to_owned()),
        "{writes:?}"
    );
    for rule in [
        "cursor.unsandboxed",
        "cursor.network-defaults",
        "cursor.project-file",
        "cursor.workspace",
    ] {
        assert!(rules(&out.report).contains(&rule), "{rule}");
    }
}

#[test]
fn network_lists_domains_and_leaves_addresses_denied() {
    let out = generated(DEFAULT_POLICY);
    let allow = list(&out, "/networkPolicy/allow");
    assert!(allow.contains(&"github.com".to_owned()), "{allow:?}");
    assert!(allow.iter().all(|h| domain(h)));
    let deny = list(&out, "/networkPolicy/deny");
    assert!(
        deny.contains(&"metadata.google.internal".to_owned()),
        "{deny:?}"
    );
    assert!(!deny.iter().any(|h| h.starts_with("169.254")));
}

#[test]
fn a_policy_proxy_port_is_reported_as_wider() {
    let out = generated("version: 1\nsandbox:\n  proxy_port: 18555\n");
    assert!(rules(&out.report).contains(&"cursor.proxy"));
    assert!(!rules(&generated(DEFAULT_POLICY).report).contains(&"cursor.proxy"));
}

#[test]
fn a_literal_write_grant_outside_the_project_is_kept_unless_a_deny_is_below_it() {
    let out = generated(
        "version: 1\nallow:\n  - id: docker\n    fs.read: [\"/data/**\"]\n    fs.write: \
         [\"/data/**\", \"/Users/me/**\"]\n",
    );
    let writes = list(&out, "/additionalReadwritePaths");
    assert!(writes.contains(&"/data".to_owned()), "{writes:?}");
    assert!(
        !writes.contains(&"/Users/me".to_owned()),
        "the home directory holds ~/.ssh, which stays denied"
    );
}

/// `moat allow --dir` leaves `.git` out of its write grant; sandbox.json cannot
/// deny inside a grant, so the grant is kept and the `.git` listed as wider
/// (Cursor itself keeps hooks and config unwritable).
#[test]
fn an_allowed_directory_with_its_git_left_out_is_still_granted() {
    let out = generated(
        "version: 1\nallow:\n  - id: approved-1\n    fs.read: ['/w/lib', '/w/lib/**']\n    \
         fs.write: ['/w/lib', '/w/lib/**', '!/w/lib/.git/**', '!/w/lib/**/.git/**']\n",
    );
    let writes = list(&out, "/additionalReadwritePaths");
    assert!(writes.contains(&"/w/lib".to_owned()), "{writes:?}");
    let wider = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "cursor.writes-in-workspace")
        .expect("the .git is listed");
    assert!(
        wider.patterns.iter().any(|p| p == "/w/lib/.git/**"),
        "{wider:?}"
    );
}
