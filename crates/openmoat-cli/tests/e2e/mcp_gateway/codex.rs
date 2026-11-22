//! A Codex MCP proxy's calls that name their hook session and call in
//! `_meta` (ADR-107) through the real binary: each takes only its own allowed
//! decision, and a decision whose audit write failed leaves none behind.

use serde_json::{Value, json};

use super::{Gateway, answer};
use crate::common::{OK, output, text};

#[test]
fn attributed_codex_requests_reach_stdio_only_with_their_own_exact_ticket() {
    let gw = Gateway::for_host(Some("codex"));
    let policy_path = gw.sb.home.join(".moat/policy.yaml");
    let policy = std::fs::read_to_string(&policy_path).unwrap();
    assert!(policy.contains("\nallow:\n"));
    std::fs::write(
        &policy_path,
        policy.replacen(
            "\nallow:\n",
            "\nallow:\n  - id: witness-search\n    mcp: [mcp__docs__search]\n",
            1,
        ),
    )
    .unwrap();
    let accepted = gw.sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&accepted).contains("re-pinned"), "{}", text(&accepted));

    let arguments = json!({"q": "same query"});
    for session in ["thread-a", "thread-b"] {
        let output = gw.sb.guard(
            "codex",
            &json!({
                "session_id": session, "cwd": gw.sb.project(),
                "hook_event_name": "PreToolUse", "tool_name": "mcp__docs__search",
                "tool_use_id": "same-call", "tool_input": arguments,
            })
            .to_string(),
        );
        assert_eq!(output.status.code(), Some(OK), "{}", text(&output));
    }
    let request = |id: u64, thread: &str, call_id: &str, args: &Value| {
        json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "search", "arguments": args,
                "_meta": {"threadId": thread, "callId": call_id}}
        })
        .to_string()
    };
    // Induce a late audit failure in the isolated database, after the call's
    // decision row can be written but before the guard can answer the host.
    let fault = output(
        std::process::Command::new("python3").args([
            "-I",
            "-c",
            "import sqlite3, sys\nwith sqlite3.connect(sys.argv[1]) as db:\n db.execute(\"CREATE TRIGGER reject_run_link BEFORE INSERT ON events WHEN NEW.host = 'moat-run' BEGIN SELECT RAISE(ABORT, 'isolated audit write failure'); END\")",
            gw.sb.home.join(".moat/audit.db").to_str().unwrap(),
        ]),
        None,
    );
    assert!(fault.status.success(), "{}", text(&fault));
    let failed = output(
        gw.sb
            .command()
            .env("MOAT_RUN_SESSION", "run-mcp-audit-test")
            .args(["guard", "--host", "codex"]),
        Some(
            &json!({
                "session_id": "thread-failed", "cwd": gw.sb.project(),
                "hook_event_name": "PreToolUse", "tool_name": "mcp__docs__search",
                "tool_use_id": "same-call", "tool_input": arguments,
            })
            .to_string(),
        ),
    );
    assert_eq!(failed.status.code(), Some(2), "{}", text(&failed));
    assert!(
        text(&failed).contains("isolated audit write failure"),
        "{}",
        text(&failed)
    );
    let response = gw.session(
        "answer",
        &[
            request(1, "thread-unseen", "same-call", &arguments),
            request(2, "thread-b", "wrong-call", &arguments),
            request(3, "thread-b", "same-call", &json!({"q": "changed"})),
            request(4, "thread-b", "same-call", &arguments),
            request(5, "thread-b", "same-call", &arguments),
            request(6, "thread-a", "same-call", &arguments),
            request(7, "thread-failed", "same-call", &arguments),
        ],
    );
    for id in [1, 2, 3, 5, 7] {
        assert_eq!(
            answer(&response, id)["error"]["code"],
            -32001,
            "request {id} must be refused"
        );
    }
    for id in [4, 6] {
        assert_eq!(
            answer(&response, id)["result"]["content"][0]["text"],
            "called search"
        );
    }
    let calls = gw.calls();
    assert_eq!(
        calls.iter().map(|v| v["id"].as_u64()).collect::<Vec<_>>(),
        [Some(4), Some(6)]
    );
}
