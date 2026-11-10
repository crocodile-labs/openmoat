//! Each MCP server shown as protected or unprotected, with why, and an
//! unprotected local server counted against `require.run: full-boundary`
//! (ADR-077). OpenMoat reads the definitions and starts nothing.

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, json as parse, text};

const SERVERS: &str = r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-server"]}}}"#;

fn installed() -> Sandbox {
    let sb = Sandbox::bare(&[".claude"]);
    std::fs::write(sb.home.join(".claude.json"), SERVERS).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    sb
}

fn require_strict(sb: &Sandbox) {
    let path = sb.home.join(".moat/policy.yaml");
    let mut policy = std::fs::read_to_string(&path).unwrap();
    policy.push_str("\nrequire:\n  run: full-boundary\n");
    std::fs::write(&path, policy).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
}

fn status(sb: &Sandbox) -> Value {
    parse(&sb.moat(&["status", "--format", "json"]))
}

fn server<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["mcp_servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not listed: {report}"))
}

#[test]
fn an_unwrapped_server_is_shown_as_unprotected_with_why() {
    let sb = installed();
    let report = status(&sb);
    let gh = server(&report, "gh");
    assert_eq!(gh["protected"], false, "{gh}");
    assert!(
        gh["why"].as_str().unwrap().contains("openmoat mcp wrap gh"),
        "{gh}"
    );
    let shown = text(&sb.moat(&["doctor"]));
    assert!(shown.contains("`gh`"), "{shown}");
    assert!(shown.contains("unprotected"), "{shown}");
}

/// Without the setting the row is there and fails nothing.
#[test]
fn without_the_requirement_nothing_counts_against_it() {
    let sb = installed();
    assert_eq!(status(&sb)["run_boundary"], Value::Null);
}

#[test]
fn an_unprotected_local_server_fails_the_requirement() {
    let sb = installed();
    require_strict(&sb);
    let report = status(&sb);
    let boundary = &report["run_boundary"];
    assert_eq!(boundary["met"], false, "{boundary}");
    assert!(
        boundary["mcp"][0].as_str().unwrap().contains("`gh`"),
        "{boundary}"
    );
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains("cannot refuse"), "{}", text(&out));
}

#[cfg(unix)]
#[test]
fn a_wrapped_accepted_server_is_protected_and_does_not_fail_it() {
    let sb = Sandbox::bare(&[".claude"]);
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    sb.define_wrapped("marker", &["--server", "marker", "--", "true"]);
    let before = status(&sb);
    assert_eq!(server(&before, "marker")["protected"], false, "{before}");
    sb.accept_mcp();
    require_strict(&sb);
    let report = status(&sb);
    let marker = server(&report, "marker");
    assert_eq!(marker["protected"], true, "{marker}");
    assert_eq!(marker["fails_requirement"], false, "{marker}");
    assert_eq!(report["run_boundary"].get("mcp"), None, "{report}");
}
