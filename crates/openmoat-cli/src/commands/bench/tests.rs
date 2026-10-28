mod in_process;

use std::path::Path;

use openmoat_hosts::Host;

use super::hook::Reply;
use super::hosts::{self, Answer, Place};
use super::scenario::{CATEGORIES, Call, scenarios};

fn exited(code: i32, stdout: &str, stderr: &str) -> Reply {
    Reply::Exited {
        code: Some(code),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    }
}

fn shell() -> Call {
    Call::Shell("ls".to_owned())
}

fn pre_tool_use(decision: &str) -> String {
    format!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"{decision}"}}}}"#
    )
}

#[test]
fn claude_code_reads_permission_decision_legacy_decision_and_exit_2() {
    let read = |reply: &Reply| hosts::classify(Host::ClaudeCode, &shell(), reply);
    assert_eq!(read(&exited(0, &pre_tool_use("allow"), "")), Answer::Allow);
    assert_eq!(read(&exited(0, &pre_tool_use("ask"), "")), Answer::Ask);
    assert_eq!(read(&exited(0, &pre_tool_use("deny"), "")), Answer::Deny);
    assert_eq!(
        read(&exited(0, r#"{"decision":"block"}"#, "")),
        Answer::Deny
    );
    assert_eq!(
        read(&exited(0, r#"{"decision":"approve"}"#, "")),
        Answer::Allow
    );
    assert_eq!(read(&exited(2, "", "")), Answer::Deny);
    assert_eq!(read(&exited(0, "", "")), Answer::Passthrough);
    assert_eq!(read(&exited(0, "not json", "")), Answer::Passthrough);
    assert_eq!(read(&exited(1, &pre_tool_use("deny"), "")), Answer::Error);
    assert_eq!(read(&Reply::TimedOut), Answer::Error);
    assert_eq!(read(&Reply::NotStarted("gone".into())), Answer::Error);
}

#[test]
fn codex_cannot_ask_and_blocks_on_exit_2_only_with_a_reason() {
    let read = |reply: &Reply| hosts::classify(Host::Codex, &shell(), reply);
    assert_eq!(read(&exited(0, &pre_tool_use("allow"), "")), Answer::Allow);
    assert_eq!(
        read(&exited(0, &pre_tool_use("ask"), "")),
        Answer::Passthrough
    );
    assert_eq!(read(&exited(0, &pre_tool_use("deny"), "")), Answer::Deny);
    assert_eq!(read(&exited(2, "", "blocked")), Answer::Deny);
    assert_eq!(read(&exited(2, "", " \n")), Answer::Error);
    assert_eq!(read(&exited(0, "", "")), Answer::Passthrough);
    assert_eq!(read(&exited(101, "", "panic")), Answer::Error);
}

#[test]
fn cursor_reads_permission_and_asks_only_for_shell_and_mcp() {
    let read = |call: &Call, reply: &Reply| hosts::classify(Host::Cursor, call, reply);
    let permission = |word: &str| exited(0, &format!(r#"{{"permission":"{word}"}}"#), "");
    let file = Call::Write("a".to_owned());
    let read_file = Call::Read("a".to_owned());
    assert_eq!(read(&shell(), &permission("allow")), Answer::Allow);
    assert_eq!(read(&shell(), &permission("ask")), Answer::Ask);
    assert_eq!(read(&shell(), &permission("deny")), Answer::Deny);
    assert_eq!(read(&file, &permission("ask")), Answer::Passthrough);
    assert_eq!(read(&read_file, &permission("ask")), Answer::Error);
    assert_eq!(read(&shell(), &exited(2, "", "")), Answer::Deny);
    assert_eq!(read(&shell(), &exited(0, "", "")), Answer::Error);
    assert_eq!(read(&shell(), &exited(1, "", "")), Answer::Error);
}

#[test]
fn openclaw_reads_each_guard_reply_as_the_verdict_it_carries() {
    use openmoat_core::Verdict;
    let read = |reply: &Reply| hosts::classify(Host::OpenClaw, &shell(), reply);
    let seen = |verdict| hosts::seen(Host::OpenClaw, &shell(), verdict);
    // `moat guard --host openclaw`: nothing for defer, else the decision as JSON.
    let allow = exited(0, r#"{"decision":"allow","reason":"r"}"#, "");
    let ask = exited(0, r#"{"decision":"ask","reason":"r"}"#, "");
    let deny = exited(2, r#"{"decision":"deny","reason":"r"}"#, "");
    // The plugin returns no decision for an allow, so OpenClaw's own checks run.
    assert_eq!(read(&allow), Answer::Passthrough);
    assert_eq!(read(&allow), seen(Verdict::Allow));
    assert_eq!(read(&exited(0, "", "")), seen(Verdict::Defer));
    assert_eq!(read(&ask), Answer::Ask);
    assert_eq!(read(&ask), seen(Verdict::Ask));
    assert_eq!(read(&deny), Answer::Deny);
    assert_eq!(read(&deny), seen(Verdict::Deny));
    assert!(seen(Verdict::Allow).meets(Answer::Allow));
    assert_eq!(read(&exited(0, "not json", "")), Answer::Error);
    assert_eq!(read(&exited(2, "", "")), Answer::Error);
    assert_eq!(read(&Reply::TimedOut), Answer::Error);
}

#[test]
fn an_ask_reaches_hosts_that_cannot_ask_as_a_deny() {
    use openmoat_core::Verdict;
    let file = Call::Edit("a".to_owned());
    assert_eq!(
        hosts::seen(Host::ClaudeCode, &shell(), Verdict::Ask),
        Answer::Ask
    );
    assert_eq!(
        hosts::seen(Host::Codex, &shell(), Verdict::Ask),
        Answer::Deny
    );
    assert_eq!(
        hosts::seen(Host::Cursor, &shell(), Verdict::Ask),
        Answer::Ask
    );
    assert_eq!(hosts::seen(Host::Cursor, &file, Verdict::Ask), Answer::Deny);
    assert!(Answer::Passthrough.meets(Answer::Allow));
    assert!(!Answer::Passthrough.meets(Answer::Deny));
    assert!(!Answer::Error.meets(Answer::Allow));
}

#[test]
fn every_scenario_file_is_bundled_valid_and_runs_on_some_host() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("moatbench");
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    files.sort();
    let bundled: Vec<_> = CATEGORIES.iter().map(|(c, _)| (*c).to_owned()).collect();
    assert_eq!(files, bundled, "add new scenario files to CATEGORIES");
    let at = Place {
        home: Path::new("/home/u"),
        project: Path::new("/home/u/proj"),
        session: "s",
        call_id: "c",
    };
    for (_, scenario) in scenarios().unwrap() {
        let runs = Host::ALL.iter().any(|&host| {
            scenario
                .steps
                .iter()
                .all(|step| hosts::payload(host, &step.call().unwrap(), &at).is_some())
        });
        assert!(runs, "{}: no host can run it", scenario.id);
    }
}

#[test]
fn an_error_reply_names_its_cause() {
    let reply = exited(
        1,
        "{\"decision\":\n\"allow\"}",
        "moat: audit log unavailable\r\n",
    );
    assert_eq!(
        reply.cause(),
        r#"exit 1, stdout "{\"decision\": \"allow\"}", stderr "moat: audit log unavailable""#
    );
    assert!(Reply::TimedOut.cause().starts_with("no exit within"));
    assert_eq!(
        Reply::NotStarted("gone".into()).cause(),
        "could not start: gone"
    );
}

#[test]
fn the_time_limit_is_past_the_guards_own_budget() {
    assert!(super::hook::TIMEOUT.as_secs() > crate::install::GUARD_BUDGET_S);
}
