//! `openmoat guard --plugin` for pi, which runs OpenMoat through an extension
//! of `init`'s (ADR-099, ADR-042): the package stands aside only once
//! `init`'s own extension has reported loading. A call the package decided is
//! recorded for pi too, but never counts as that report, so the package does
//! not stand aside for an extension that never loaded, and `openmoat status`
//! does not say it loaded.

use std::fs;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, json as parse, stdout, text};

const AGENT_DIR: &str = ".pi/agent";
const HOST: &str = "pi";

/// A read of an SSH key, which the default policy denies.
fn secret_read(sb: &Sandbox) -> String {
    crate::pi::payload(sb, "read", &json!({ "path": sb.home.join(".ssh/id_rsa") }))
}

fn plugin_guard(sb: &Sandbox) -> std::process::Output {
    sb.moat_stdin(&["guard", "--host", HOST, "--plugin"], &secret_read(sb))
}

fn stood_aside(sb: &Sandbox) -> Value {
    let path = sb.home.join(format!(".moat/plugins/{HOST}.json"));
    let record: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    record["stood_aside"].clone()
}

fn plugin_state(sb: &Sandbox) -> Value {
    let doc = parse(&sb.moat(&["status", "--format", "json"]));
    doc["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["host"] == HOST)
        .unwrap_or_else(|| panic!("no {HOST} in {doc}"))["state"]
        .clone()
}

#[test]
fn the_package_s_own_decisions_never_make_it_stand_aside() {
    let sb = Sandbox::installed(&[AGENT_DIR]);
    // `init`'s extension has not reported loading: the package decides.
    let out = plugin_guard(&sb);
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert_eq!(stood_aside(&sb), false);
    // Its decision is no report either: the next call is decided too, and
    // `status` still says `init`'s extension has not loaded.
    let out = plugin_guard(&sb);
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert_eq!(stood_aside(&sb), false);
    assert_eq!(plugin_state(&sb), "not-yet");

    // Once `init`'s extension reports loading, the package stands aside.
    let out = sb.moat(&["guard", "--heartbeat", "--host", HOST]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let out = plugin_guard(&sb);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(stdout(&out), "", "pi's no decision is no output");
    assert_eq!(stood_aside(&sb), true);
}
