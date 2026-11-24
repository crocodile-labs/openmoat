//! The remote MCP gateway (ADR-127) through the real binary: `openmoat mcp
//! remote` refuses a server no person named, and a URL other than the one
//! `openmoat mcp login` pinned; a pinned server whose address the policy does
//! not name is never connected to, and the agent's request is answered with
//! OpenMoat's error instead of waiting; `--forget` undoes the pin. No test
//! here opens a connection.

#![cfg(unix)]

use serde_json::Value;

use crate::common::{FAILED, OK, Sandbox, stdout, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

const LIST: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n";
const URL: &str = "http://127.0.0.1:9/mcp";

fn remote(sb: &Sandbox, url: &str) -> std::process::Output {
    sb.moat_stdin(&["mcp", "remote", "--server", "local", "--url", url], LIST)
}

fn answer(out: &std::process::Output) -> Value {
    let line = stdout(out);
    let first = line.lines().next().unwrap_or_default();
    serde_json::from_str(first).unwrap_or_else(|e| panic!("{e}: {}", text(out)))
}

#[test]
fn a_server_no_person_named_is_refused_with_the_command_to_name_it() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let out = remote(&sb, URL);
    assert_eq!(out.status.code(), Some(FAILED), "{}", text(&out));
    let message = answer(&out)["error"]["message"].to_string();
    assert!(message.contains("openmoat mcp login local"), "{message}");
}

#[test]
fn login_pins_the_url_and_forget_undoes_it() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let pinned = sb.moat_approving(&["mcp", "login", "local", "--url", URL, "--no-token"]);
    assert_eq!(pinned.status.code(), Some(OK), "{}", text(&pinned));
    assert!(stdout(&pinned).contains("--forget"), "{}", text(&pinned));

    // another URL for the same name is refused, naming the pinned one
    let moved = remote(&sb, "http://127.0.0.1:10/mcp");
    assert_eq!(moved.status.code(), Some(FAILED), "{}", text(&moved));
    let message = answer(&moved)["error"]["message"].to_string();
    assert!(message.contains("127.0.0.1:9"), "{message}");

    // the pinned URL is admitted, but a loopback address no allow rule names
    // is never connected to: the request gets OpenMoat's error at once
    let refused = remote(&sb, URL);
    assert_eq!(refused.status.code(), Some(OK), "{}", text(&refused));
    let reply = answer(&refused);
    assert_eq!(reply["id"], 1, "{reply}");
    assert_eq!(reply["error"]["code"], -32603, "{reply}");
    assert!(
        reply["error"]["message"].to_string().contains("127.0.0.1"),
        "{reply}"
    );

    let forgot = sb.moat_as_person(&["mcp", "login", "local", "--url", URL, "--forget"]);
    assert_eq!(forgot.status.code(), Some(OK), "{}", text(&forgot));
    let again = remote(&sb, URL);
    assert_eq!(again.status.code(), Some(FAILED), "{}", text(&again));
}

#[test]
fn login_refuses_a_url_it_never_sends_to_with_an_example() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let out = sb.moat_approving(&[
        "mcp",
        "login",
        "x",
        "--url",
        "https://user:pw@mcp.example.com/mcp",
    ]);
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    let all = text(&out);
    assert!(
        all.contains("for example `openmoat mcp login x --url https://"),
        "{all}"
    );
    assert!(all.contains("docs/USAGE.md"), "{all}");
}
