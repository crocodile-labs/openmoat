//! `moat allowed` and `moat secret list`: read-only listings that need no
//! terminal, in text and JSON. A secret's value never appears.

use std::process::Output;

use crate::common::{OK, Sandbox, json, output, text};

fn add_secret(sb: &Sandbox, args: &[&str]) -> Output {
    let mut cmd = sb.command();
    cmd.args(["secret", "add"])
        .args(args)
        .env("MOAT_ASSUME_TTY", "1");
    output(&mut cmd, Some("y\n"))
}

#[test]
fn allowed_lists_rules_grants_and_trust_without_a_terminal() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let empty = json(&sb.moat(&["allowed", "--format", "json"]));
    assert_eq!(empty["rules"], serde_json::json!([]));
    assert_eq!(empty["session_grants"], serde_json::json!([]));
    assert_eq!(empty["trusted_repos"], serde_json::json!([]));

    // A permanent site rule and a session grant, as a person makes them.
    let site = sb.moat_as_person(&["allow", "--site", "docs.rs"]);
    assert_eq!(site.status.code(), Some(OK), "{}", text(&site));
    let (verdict, _) = sb.guard_bash("s1", &sb.project(), "npm install left-pad");
    assert_eq!(verdict, "ask");
    let grant = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(grant.status.code(), Some(OK), "{}", text(&grant));

    let out = sb.moat(&["allowed", "--format", "json"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let doc = json(&out);
    let rules = doc["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .any(|r| r["net"] == serde_json::json!(["docs.rs"])),
        "{doc}"
    );
    let grants = doc["session_grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1, "{doc}");
    assert_eq!(grants[0]["session_id"], "s1");
    assert_eq!(grants[0]["what"], "run \"npm install left-pad\"");
    assert!(grants[0]["expires_at_ms"].as_i64() > grants[0]["granted_at_ms"].as_i64());

    let shown = text(&sb.moat(&["allowed"]));
    assert!(
        shown.contains("docs.rs") && shown.contains("moat allow --remove"),
        "{shown}"
    );
    assert!(shown.contains("npm install left-pad"), "{shown}");
}

#[test]
fn secret_list_names_where_a_value_comes_from_never_the_value() {
    let sb = Sandbox::installed(&[".claude"]);
    let none = json(&sb.moat(&["secret", "list", "--format", "json"]));
    assert_eq!(none["secrets"], serde_json::json!([]));

    let added = add_secret(&sb, &["gh"]);
    assert_eq!(added.status.code(), Some(OK), "{}", text(&added));

    let out = sb.moat(&["secret", "list", "--format", "json"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let doc = json(&out);
    let gh = &doc["secrets"][0];
    assert_eq!(gh["id"], "gh");
    assert_eq!(gh["host"], "api.github.com");
    assert_eq!(gh["header"], "Authorization");
    assert_eq!(gh["source"]["env"], "GITHUB_TOKEN");
    assert!(gh["source_exposed"].is_boolean(), "{doc}");
    assert!(gh.get("value").is_none(), "{doc}");

    let shown = text(&sb.moat(&["secret", "list"]));
    assert!(
        shown.contains("gh") && shown.contains("env GITHUB_TOKEN"),
        "{shown}"
    );
}
