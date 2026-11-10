use serde_json::json;

use super::*;

const PROXIED: [&str; 7] = [
    "mcp",
    "proxy",
    "--server",
    "gh",
    "--sandbox",
    "--",
    "server",
];

fn wrapped(sandboxed: bool) -> Value {
    let args: Vec<&str> = PROXIED
        .iter()
        .copied()
        .filter(|a| sandboxed || *a != "--sandbox")
        .collect();
    json!({"command": "/usr/local/bin/openmoat", "args": args})
}

fn judge(entry: &Value, accepted: bool, set_up: bool) -> (bool, String) {
    judged(shape_of(entry), "gh", accepted, set_up, "Claude Code")
}

#[test]
fn a_wrapped_accepted_server_is_protected() {
    let (protected, why) = judge(&wrapped(true), true, true);
    assert!(protected, "{why}");
    assert!(why.contains("OS sandbox"), "{why}");
}

#[test]
fn a_wrapped_server_without_the_sandbox_says_so() {
    let (protected, why) = judge(&wrapped(false), true, true);
    assert!(protected, "{why}");
    assert!(why.contains("outside the OS sandbox"), "{why}");
}

#[test]
fn an_unaccepted_wrapped_server_is_unprotected() {
    let (protected, why) = judge(&wrapped(true), false, true);
    assert!(!protected, "{why}");
    assert!(why.contains("openmoat mcp accept gh"), "{why}");
}

#[test]
fn an_unwrapped_local_server_is_unprotected_and_names_the_fix() {
    let entry = json!({"command": "npx", "args": ["server"]});
    assert_eq!(shape_of(&entry), Shape::Local);
    let (protected, why) = judge(&entry, true, true);
    assert!(!protected, "{why}");
    assert!(why.contains("openmoat mcp wrap gh"), "{why}");
}

#[test]
fn a_remote_server_depends_on_its_definition_being_accepted() {
    let entry = json!({"type": "http", "url": "https://example.test/mcp"});
    assert_eq!(shape_of(&entry), Shape::Remote);
    assert!(judge(&entry, true, true).0);
    assert!(!judge(&entry, false, true).0);
}

/// A shape OpenMoat cannot read is never called protected.
#[test]
fn an_unknown_shape_is_unprotected() {
    let entry = json!({"cmd": "server", "enabled": true});
    assert_eq!(shape_of(&entry), Shape::Unknown);
    assert!(!judge(&entry, true, true).0);
}

#[test]
fn a_server_of_an_agent_not_set_up_is_unprotected() {
    let (protected, why) = judge(&wrapped(true), true, false);
    assert!(!protected, "{why}");
    assert!(why.contains("not set up"), "{why}");
}

fn server(entry: Value) -> servers::Server {
    servers::Server {
        id: "/f#/x".to_owned(),
        host: Host::ClaudeCode,
        file: PathBuf::from("/f"),
        pointer: "/x".to_owned(),
        name: "gh".to_owned(),
        entry,
    }
}

/// Only a local server left unprotected, of a set-up agent, fails the
/// requirement: a remote one runs nothing here, and an agent OpenMoat is not
/// set up for is not one this requirement can speak for.
#[test]
fn which_servers_fail_the_requirement() {
    let local = json!({"command": "npx"});
    let remote = json!({"url": "https://example.test/mcp"});
    let unknown = json!({"cmd": "server"});
    let cases = [
        (local.clone(), true, true, true),
        (local, true, false, false),
        (wrapped(true), false, true, true),
        (wrapped(true), true, true, false),
        (remote, false, true, false),
        (unknown, true, true, true),
    ];
    for (entry, accepted, set_up, fails) in cases {
        let status = status_of(Host::ClaudeCode, server(entry.clone()), accepted, set_up);
        assert_eq!(status.fails_requirement, fails, "{entry} {status:?}");
    }
}

#[test]
fn nothing_is_accepted_without_pins() {
    let unpinned = Review::default();
    assert!(!accepted(&unpinned, "/f#/x"));
    let pinned = Review {
        pinned: true,
        ..Review::default()
    };
    assert!(accepted(&pinned, "/f#/x"));
}

#[test]
fn the_description_says_protected_or_unprotected() {
    let line = status_of(
        Host::ClaudeCode,
        server(json!({"command": "npx"})),
        true,
        true,
    )
    .describe();
    assert!(
        line.contains("`gh` (Claude Code, /f): unprotected"),
        "{line}"
    );
}
