//! Code a session wrote, run with no OS sandbox below the hook (ADR-039),
//! through the real binary: on an agent with only a hook, a script the same
//! session wrote asks before it runs (a deny naming `openmoat allow --last`
//! where the agent cannot ask); where OpenMoat's OS sandbox holds the command,
//! and for files the session did not write, the verdict is unchanged.

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, json as parse, stdout, text};
use crate::taint::{call, decide};

/// A Gemini CLI `BeforeTool` payload for `tool` with `input` in `session`.
fn gemini(sb: &Sandbox, session: &str, tool: &str, input: &Value) -> String {
    json!({
        "session_id": session, "transcript_path": "",
        "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "BeforeTool", "timestamp": "2026-10-27T10:00:00.000Z",
        "tool_name": tool, "tool_input": input,
    })
    .to_string()
}

/// Gemini CLI's reply to `payload`; `Value::Null` when the hook printed nothing.
fn reply(sb: &Sandbox, host: &str, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard(host, payload);
    let reply = if stdout(&out).trim().is_empty() {
        Value::Null
    } else {
        parse(&out)
    };
    (out.status.code(), reply)
}

/// `write_file` of `file` in `session`, then on disk as Gemini CLI would.
fn gemini_write(sb: &Sandbox, session: &str, file: &str) {
    let path = sb.project().join(file);
    let content = "import os\nprint(open(os.path.expanduser('~/.s' + 'sh/id_rsa')).read())\n";
    let input = json!({ "file_path": path.to_string_lossy(), "content": content });
    let (code, reply) = reply(sb, "gemini-cli", &gemini(sb, session, "write_file", &input));
    assert_eq!(code, Some(OK), "{reply}");
    std::fs::write(path, content).unwrap();
}

fn gemini_run(sb: &Sandbox, session: &str, command: &str) -> (Option<i32>, Value) {
    let input = json!({ "command": command });
    reply(
        sb,
        "gemini-cli",
        &gemini(sb, session, "run_shell_command", &input),
    )
}

fn asks_for_session_code(reply: &Value) -> bool {
    reply["decision"] == "ask" && reply.to_string().contains("session-written-code")
}

#[test]
fn a_script_a_hook_only_session_wrote_asks_and_a_session_grant_answers_it() {
    // Gemini CLI's shell is PowerShell on Windows, which OpenMoat leaves to it.
    if cfg!(windows) {
        return;
    }
    let sb = Sandbox::installed(&[".gemini"]);
    gemini_write(&sb, "g1", "x.py");
    for command in ["python3 x.py", "python x.py", "env python3 -u x.py"] {
        let (code, reply) = gemini_run(&sb, "g1", command);
        assert_eq!(code, Some(OK), "{command}: {reply}");
        assert!(asks_for_session_code(&reply), "{command}: {reply}");
        assert!(reply.to_string().contains("x.py"), "{reply}");
    }

    // another session, and a file that was there before: unchanged
    let (_, other) = gemini_run(&sb, "g2", "python3 x.py");
    assert!(!asks_for_session_code(&other), "{other}");
    std::fs::write(sb.project().join("manage.py"), "print(1)\n").unwrap();
    let (_, before) = gemini_run(&sb, "g1", "python manage.py");
    assert!(!asks_for_session_code(&before), "{before}");

    // the person approves the last ask for this session
    let (_, asked) = gemini_run(&sb, "g1", "python3 x.py");
    assert!(asks_for_session_code(&asked), "{asked}");
    let out = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let (code, answered) = gemini_run(&sb, "g1", "python3 x.py");
    assert_eq!(code, Some(OK), "{answered}");
    assert!(!asks_for_session_code(&answered), "{answered}");

    // a permanent rule does not answer it
    let (_, again) = gemini_run(&sb, "g1", "python3 -B x.py");
    assert!(asks_for_session_code(&again), "{again}");
    let out = sb.moat_approving(&["allow", "--last", "--always"]);
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("without --always"), "{}", text(&out));

    // rewritten after the grant: the person approved other code
    gemini_write(&sb, "g1", "x.py");
    let (_, rewritten) = gemini_run(&sb, "g1", "python3 x.py");
    assert!(asks_for_session_code(&rewritten), "{rewritten}");
}

#[test]
fn a_script_written_through_the_shell_asks_too() {
    if cfg!(windows) {
        return;
    }
    let sb = Sandbox::installed(&[".gemini"]);
    let (code, reply) = gemini_run(&sb, "g1", "echo 'echo hi' > x.sh");
    assert_eq!(code, Some(OK), "{reply}");
    std::fs::write(sb.project().join("x.sh"), "echo hi\n").unwrap();
    for command in ["bash x.sh", "sh x.sh", "./x.sh", "source x.sh"] {
        let (_, reply) = gemini_run(&sb, "g1", command);
        assert!(asks_for_session_code(&reply), "{command}: {reply}");
    }
    // written and run by one command
    let (_, same) = gemini_run(&sb, "g3", "cat > y.sh <<'EOF'\necho hi\nEOF\nsh y.sh");
    assert!(asks_for_session_code(&same), "{same}");
    // a test runner runs the project's code by design: unchanged
    gemini_write(&sb, "g1", "test_x.py");
    let (_, tests) = gemini_run(&sb, "g1", "pytest test_x.py");
    assert!(!asks_for_session_code(&tests), "{tests}");
}

#[test]
fn opencode_cannot_ask_so_it_is_a_deny_that_says_how_to_approve() {
    if cfg!(windows) {
        return;
    }
    let sb = Sandbox::installed(&[".config/opencode"]);
    let path = sb.project().join("x.js");
    let write = crate::opencode::payload(
        &sb,
        "write",
        &json!({ "filePath": path.to_string_lossy(), "content": "console.log(1)\n" }),
    );
    let (code, written) = reply(&sb, "opencode", &write);
    assert_eq!(code, Some(OK), "{written}");
    std::fs::write(&path, "console.log(1)\n").unwrap();
    let run = crate::opencode::payload(&sb, "bash", &json!({ "command": "node x.js" }));
    let (code, denied) = reply(&sb, "opencode", &run);
    assert_eq!(code, Some(DENY), "{denied}");
    let shown = denied.to_string();
    assert!(
        shown.contains("session-written-code") && shown.contains("openmoat allow --last"),
        "{shown}"
    );
}

#[test]
fn claude_code_with_its_sandbox_in_place_keeps_the_verdict() {
    let sb = Sandbox::installed(&[".claude"]);
    let proj = sb.project();
    let path = proj.join("x.py");
    let input = json!({ "file_path": path.to_string_lossy(), "content": "print(1)\n" });
    let (verdict, reason) = decide(&sb, "claude-code", &call("c1", &proj, "Write", &input));
    assert_eq!(verdict, "allow", "{reason}");
    std::fs::write(&path, "print(1)\n").unwrap();
    let run = json!({ "command": "python3 x.py" });
    let (verdict, reason) = decide(&sb, "claude-code", &call("c1", &proj, "Bash", &run));
    if cfg!(windows) {
        // native Windows: Claude Code has no sandbox there, the hook is the only check
        assert_eq!(verdict, "ask", "{reason}");
        assert!(reason.contains("session-written-code"), "{reason}");
    } else {
        assert_eq!(verdict, "allow", "{reason}");
        assert!(!reason.contains("session-written-code"), "{reason}");
    }
}
