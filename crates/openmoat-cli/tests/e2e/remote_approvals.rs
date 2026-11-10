//! Remote approvals (ADR-078) as the guard sees them: no channel changes
//! nothing; a review is sent as a signed request; an answer signed with the
//! machine's key and given by an allowlisted approver lets that exact call run
//! once; a deny is never sent. No network and no token: the answer is written
//! here as `openmoat approvals listen` would write it.

use std::path::{Path, PathBuf};

use std::fmt::Write as _;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::common::{OK, Sandbox, USAGE, bash_payload, hook_output, text};

const COMMAND: &str = "npm install left-pad-pro";
const APPROVER: &str = "4242";
/// Made for this test; no real key.
const KEY_HEX: &str = "8f2c1d4e5a6b7c8d9e0f112233445566778899aabbccddeeff00112233445566";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// HMAC-SHA-256 (RFC 2104) of `domain || message`, as the binary signs.
fn mac(domain: &[u8], message: &[u8]) -> String {
    let key: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&KEY_HEX[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(&key);
    let pad = |byte: u8| block.iter().map(|b| b ^ byte).collect::<Vec<u8>>();
    let mut inner = Sha256::new();
    inner.update(pad(0x36));
    inner.update(domain);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(pad(0x5c));
    outer.update(inner.finalize());
    hex(&outer.finalize())
}

fn remote(sb: &Sandbox) -> PathBuf {
    sb.home.join(".moat").join("remote")
}

fn write_private(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
}

/// A connected channel, as `openmoat approvals connect` and `allow` leave it.
fn connect(sb: &Sandbox) {
    write_private(&remote(sb).join("approval.key"), &format!("{KEY_HEX}\n"));
    // Signed as the binary encodes its settings: fields in declaration order.
    let unsigned = format!(
        r#"{{"version":1,"channel":"telegram","approvers":["{APPROVER}"],"expiry_s":300,"mac":""}}"#
    );
    let mut settings: Value = serde_json::from_str(&unsigned).unwrap();
    settings["mac"] = Value::from(mac(b"openmoat-remote-settings-v1\n", unsigned.as_bytes()));
    write_private(&remote(sb).join("channel.json"), &settings.to_string());
}

fn requests(sb: &Sandbox) -> Vec<Value> {
    let Ok(dir) = std::fs::read_dir(remote(sb).join("requests")) else {
        return Vec::new();
    };
    dir.map(|e| serde_json::from_str(&std::fs::read_to_string(e.unwrap().path()).unwrap()).unwrap())
        .collect()
}

/// The answer `listen` writes for `request`, by `approver`.
fn answer(sb: &Sandbox, request: &Value, verdict: &str, approver: &str) {
    let unsigned = format!(
        r#"{{"version":1,"id":{},"digest":{},"verdict":"{verdict}","approver":"{approver}","channel":"telegram","answered_ms":{},"expires_ms":{},"mac":""}}"#,
        request["id"], request["digest"], request["created_ms"], request["expires_ms"]
    );
    let mut signed: Value = serde_json::from_str(&unsigned).unwrap();
    signed["mac"] = Value::from(mac(b"openmoat-remote-answer-v1\n", unsigned.as_bytes()));
    let id = request["id"].as_str().unwrap();
    write_private(
        &remote(sb).join("answers").join(format!("{id}.json")),
        &signed.to_string(),
    );
}

fn decide(sb: &Sandbox, command: &str) -> Value {
    hook_output(&sb.guard("claude-code", &bash_payload("s1", &sb.project(), command)))
}

#[test]
fn with_no_channel_a_review_is_unchanged() {
    let sb = Sandbox::installed_with_review(&[".claude"]);
    let d = decide(&sb, COMMAND);
    assert_eq!(d["permissionDecision"], "ask", "{d}");
    assert!(!remote(&sb).exists());
    let status = sb.moat(&["approvals", "status"]);
    assert_eq!(status.status.code(), Some(OK));
    assert!(
        text(&status).contains("no channel connected"),
        "{}",
        text(&status)
    );
}

#[test]
fn approvals_commands_need_a_person() {
    let sb = Sandbox::installed(&[".claude"]);
    for args in [
        &["approvals", "allow", "1"][..],
        &["approvals", "listen"],
        &["approvals", "test"],
        &["approvals", "connect", "telegram"],
        &["approvals", "disconnect"],
    ] {
        let out = sb.moat(args);
        assert_eq!(out.status.code(), Some(USAGE), "{args:?}");
        assert!(
            text(&out).contains("must be run by a person"),
            "{}",
            text(&out)
        );
    }
    // And the agent's own shell call of one is denied by the policy.
    let d = decide(&sb, "openmoat approvals allow 666");
    assert_eq!(d["permissionDecision"], "deny", "{d}");
}

#[cfg(unix)] // the key's owner-only mode is what `key_file` checks
#[test]
fn an_approved_call_runs_once_and_only_that_call() {
    let sb = Sandbox::installed_with_review(&[".claude"]);
    connect(&sb);
    let d = decide(&sb, COMMAND);
    assert_eq!(d["permissionDecision"], "ask", "{d}");
    let sent = requests(&sb);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["host"], "claude-code");
    assert_eq!(sent[0]["session"], "s1");

    // Someone not on the list: still a review.
    answer(&sb, &sent[0], "approve", "666");
    assert_eq!(decide(&sb, COMMAND)["permissionDecision"], "ask");
    std::fs::remove_dir_all(remote(&sb).join("answers")).unwrap();

    answer(&sb, &sent[0], "approve", APPROVER);
    // Another command is not approved by it.
    assert_eq!(
        decide(&sb, "npm install left-pad-pro2")["permissionDecision"],
        "ask"
    );
    let d = decide(&sb, COMMAND);
    assert_eq!(d["permissionDecision"], "allow", "{d}");
    // Once: the next try is a new request.
    assert_eq!(decide(&sb, COMMAND)["permissionDecision"], "ask");
    let show = text(&sb.moat(&["show", "--format", "json"]));
    assert!(show.contains("approved-remote"), "{show}");

    // `status` reads it all without a terminal and shows no credential.
    let status = text(&sb.moat(&["approvals", "status"]));
    assert!(status.contains("approvers: 4242"), "{status}");
}

#[cfg(unix)]
#[test]
fn a_deny_is_never_sent_for_approval() {
    let sb = Sandbox::installed_with_review(&[".claude"]);
    connect(&sb);
    let d = decide(&sb, "cat ~/.ssh/id_rsa");
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    assert_eq!(requests(&sb), Vec::<Value>::new());
}
