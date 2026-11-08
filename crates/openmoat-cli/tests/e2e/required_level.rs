//! The protection level a policy requires (`require:`, ADR-064): below it,
//! every call of the agent is denied with `protection-required`; at it, the
//! call gets its usual decision. A repository policy can raise the level and
//! never lower it, and the policy cannot be changed past the lock.
//!
//! Gemini CLI is the hook-only agent on every OS: OpenMoat writes no sandbox
//! for it, so `hook-and-os-sandbox` is not met outside `openmoat run`.

use std::fs;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, USAGE, fixture, json as parse, output, stdout, text};

const SANDBOX_REQUIRED: &str = "require:\n  protection: hook-and-os-sandbox\n";

/// `sb` with `section` added to the user policy and re-pinned as a person
/// would (`openmoat doctor --accept` at a terminal).
fn require(sb: &Sandbox, section: &str) {
    let path = sb.home.join(".moat/policy.yaml");
    let mut policy = fs::read_to_string(&path).unwrap();
    policy.push('\n');
    policy.push_str(section);
    fs::write(&path, policy).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
}

/// A Gemini CLI write of a file in the project, which the default policy allows.
fn write_in_project(sb: &Sandbox) -> String {
    let file = sb.project().join("src/main.rs");
    json!({
        "session_id": "gem-1", "transcript_path": "",
        "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "BeforeTool", "timestamp": "2026-11-07T10:00:00.000Z",
        "tool_name": "write_file",
        "tool_input": { "file_path": file.to_string_lossy(), "content": "fn main() {}\n" },
    })
    .to_string()
}

/// The exit code and Gemini CLI's reply; `Value::Null` when it printed nothing.
fn gemini(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("gemini-cli", payload);
    let reply = if stdout(&out).trim().is_empty() {
        Value::Null
    } else {
        parse(&out)
    };
    (out.status.code(), reply)
}

/// The `required` entry `openmoat status --format json` gives `host`.
fn required(sb: &Sandbox, host: &str) -> Value {
    let out = sb.moat(&["status", "--format", "json"]);
    let agents = parse(&out)["agents"].as_array().unwrap().clone();
    let agent = agents.iter().find(|a| a["host"] == host).unwrap();
    agent["required"].clone()
}

fn assert_required_deny(code: Option<i32>, reply: &Value, by: &str) {
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny", "{reply}");
    let reason = reply["reason"].as_str().unwrap();
    for part in [
        "protection-required",
        "below the protection level the policy requires",
        &format!("{by} requires hook + OS sandbox for Gemini CLI"),
        "this call has hook only",
        "to meet it, ",
    ] {
        assert!(reason.contains(part), "{part:?} in {reason}");
    }
}

#[test]
fn below_the_required_level_every_call_is_denied_and_status_says_why() {
    let sb = Sandbox::installed(&[".gemini"]);
    let write = write_in_project(&sb);
    assert_eq!(gemini(&sb, &write).1, json!({ "decision": "allow" }));
    require(&sb, SANDBOX_REQUIRED);

    let (code, reply) = gemini(&sb, &write);
    assert_required_deny(code, &reply, "your policy");
    // A tool OpenMoat does not govern, which the host decides otherwise.
    let (code, reply) = gemini(&sb, &fixture("gemini-cli/write_todos.json"));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("protection-required"),
        "{reply}"
    );

    let shown = required(&sb, "gemini-cli");
    assert_eq!(shown["level"], "hook-and-os-sandbox", "{shown}");
    assert_eq!(shown["by"], "your policy", "{shown}");
    assert_eq!(shown["met"], false, "{shown}");
    assert!(shown["fix"].is_string(), "{shown}");
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        stdout(&out).contains("required: hook + OS sandbox (your policy), not met"),
        "{}",
        text(&out)
    );
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let home = text(&output(&mut sb.command(), Some("")));
    assert!(
        home.contains("Gemini CLI (hook only, below the required hook + OS sandbox)"),
        "{home}"
    );
    // The audit log has the deny under its rule id.
    // `status`, `doctor` and the home screen above add their own rows.
    let shown = stdout(&sb.moat(&["show", "--limit", "50"]));
    assert!(shown.contains("protection-required"), "{shown}");
}

#[test]
fn at_the_required_level_a_call_gets_its_usual_decision() {
    let sb = Sandbox::installed(&[".gemini"]);
    let write = write_in_project(&sb);
    // The hook alone meets `hook-only`; an agent's own level takes the place
    // of `protection` for it.
    require(
        &sb,
        "require:\n  protection: hook-and-os-sandbox\n  agents:\n    gemini-cli: hook-only\n",
    );
    assert_eq!(
        gemini(&sb, &write),
        (Some(OK), json!({ "decision": "allow" }))
    );
    let shown = required(&sb, "gemini-cli");
    assert_eq!(shown["level"], "hook-only", "{shown}");
    assert_eq!(shown["met"], true, "{shown}");
    let out = sb.moat(&["status"]);
    assert!(
        stdout(&out).contains("required: hook only (your policy), met"),
        "{}",
        text(&out)
    );
    // A deny of the policy's own stays that deny.
    if !cfg!(windows) {
        let (code, reply) = gemini(&sb, &fixture("gemini-cli/run_shell_command.json"));
        assert_eq!(code, Some(DENY), "{reply}");
        assert!(
            reply["reason"].to_string().contains("secrets-paths"),
            "{reply}"
        );
    }
}

/// Claude Code's own sandbox, as OpenMoat writes it, meets `hook-and-os-sandbox`.
#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
#[test]
fn an_agent_in_its_own_sandbox_meets_the_sandbox_level() {
    let sb = Sandbox::installed(&[".claude"]);
    require(&sb, SANDBOX_REQUIRED);
    let (verdict, reason) = sb.guard_bash("s1", &sb.project(), "git status --short");
    assert_eq!(verdict, "allow", "{reason}");
    assert_eq!(required(&sb, "claude-code")["met"], true);
}

/// Attack: a repository policy that tries to lower the level the user requires,
/// for every agent or for this one, changes nothing, trusted or not.
#[test]
fn a_repository_policy_cannot_lower_the_required_level() {
    let sb = Sandbox::installed(&[".gemini"]);
    require(&sb, SANDBOX_REQUIRED);
    let project = sb.project();
    fs::create_dir_all(project.join(".moat")).unwrap();
    let lower =
        "version: 1\nrequire:\n  protection: hook-only\n  agents:\n    gemini-cli: hook-only\n";
    fs::write(project.join(".moat/policy.yaml"), lower).unwrap();
    let (code, reply) = gemini(&sb, &write_in_project(&sb));
    assert_required_deny(code, &reply, "your policy");
    let out = sb.moat_approving(&["trust", &project.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let (code, reply) = gemini(&sb, &write_in_project(&sb));
    assert_required_deny(code, &reply, "your policy");
}

/// A repository policy can raise the level, and needs no trust to.
#[test]
fn a_repository_policy_raises_the_required_level() {
    let sb = Sandbox::installed(&[".gemini"]);
    let project = sb.project();
    fs::create_dir_all(project.join(".moat")).unwrap();
    let raise = format!("version: 1\n{SANDBOX_REQUIRED}");
    fs::write(project.join(".moat/policy.yaml"), raise).unwrap();
    let (code, reply) = gemini(&sb, &write_in_project(&sb));
    assert_required_deny(code, &reply, "the repository policy");
    // An agent id OpenMoat does not know is no requirement silently dropped.
    let typo = "version: 1\nrequire:\n  agents:\n    gemini: hook-and-os-sandbox\n";
    fs::write(project.join(".moat/policy.yaml"), typo).unwrap();
    let (code, reply) = gemini(&sb, &write_in_project(&sb));
    assert_eq!(code, Some(DENY), "{reply}");
    let reason = reply["reason"].to_string();
    assert!(reason.contains("kernel-error"), "{reason}");
    assert!(
        reason.contains("`gemini` is not an agent OpenMoat knows"),
        "{reason}"
    );
}

/// Attack: taking the requirement out of the policy is a change to a pinned
/// file, so every call is denied (`kernel-integrity`) until a person re-pins.
#[test]
fn removing_the_requirement_without_a_person_is_caught_by_the_lock() {
    let sb = Sandbox::installed(&[".gemini"]);
    require(&sb, SANDBOX_REQUIRED);
    let path = sb.home.join(".moat/policy.yaml");
    let policy = fs::read_to_string(&path).unwrap();
    fs::write(&path, policy.replace(SANDBOX_REQUIRED, "")).unwrap();
    let (code, reply) = gemini(&sb, &write_in_project(&sb));
    assert_eq!(code, Some(DENY), "{reply}");
    let reason = reply["reason"].to_string();
    assert!(reason.contains("kernel-integrity"), "{reason}");
    assert!(!reason.contains("protection-required"), "{reason}");
}

/// `openmoat run` refuses a program it cannot bring to the level: one that
/// is no agent OpenMoat knows has no hook of OpenMoat's.
#[cfg(unix)]
#[test]
fn run_refuses_a_program_below_the_required_level() {
    // Outside `/tmp` on Linux, as every home `openmoat run` tests use.
    let parent = if cfg!(target_os = "linux") {
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
    } else {
        std::env::temp_dir()
    };
    let sb = Sandbox::installed_in(&parent, &[".gemini"]);
    require(&sb, "require:\n  protection: hook-only\n");
    let project = sb.project();
    let out = output(
        sb.command()
            .current_dir(&project)
            .args(["run", "--", "/bin/sh", "-c", "echo ran"]),
        None,
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let said = text(&out);
    assert!(
        said.contains("your policy requires hook only of every agent"),
        "{said}"
    );
    assert!(said.contains("is no agent OpenMoat knows"), "{said}");
    assert!(!stdout(&out).contains("ran"), "{said}");
}
