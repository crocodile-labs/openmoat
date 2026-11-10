//! `openmoat init` offers to run the agents' stdio MCP servers through
//! `openmoat mcp proxy`, and a definition that appears later is held and
//! reported (ADR-076). No server is ever started here: a definition's command
//! would leave a marker file.

use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, output, stdout, text};

const SERVERS: &str = r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-server"]}}}"#;

fn bare_with_servers() -> Sandbox {
    let sb = Sandbox::bare(&[".claude"]);
    std::fs::write(sb.home.join(".claude.json"), SERVERS).unwrap();
    sb
}

/// `openmoat init --hosts claude-code` by a person who answers `answers`.
fn init_answering(sb: &Sandbox, answers: &str) -> Output {
    output(
        sb.command()
            .args(["init", "--hosts", "claude-code"])
            .env("MOAT_ASSUME_TTY", "1"),
        Some(answers),
    )
}

fn args_of_gh(sb: &Sandbox) -> Value {
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".claude.json")).unwrap())
            .unwrap();
    file["mcpServers"]["gh"]["args"].clone()
}

fn wrapped(sb: &Sandbox) -> bool {
    args_of_gh(sb).as_array().is_some_and(|a| {
        a.first().and_then(Value::as_str) == Some("mcp")
            && a.get(1).and_then(Value::as_str) == Some("proxy")
    })
}

fn mcp_payload(server: &str, cwd: &Path) -> String {
    json!({"session_id": "s", "cwd": cwd.to_string_lossy(), "hook_event_name": "PreToolUse",
        "tool_name": format!("mcp__{server}__x"), "tool_input": {}, "tool_use_id": "t"})
    .to_string()
}

#[test]
fn a_person_is_asked_and_a_yes_wraps_and_a_guard_still_works() {
    let sb = bare_with_servers();
    let out = init_answering(&sb, "y\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let said = text(&out);
    assert!(
        said.contains("Run them through OpenMoat? [Y/n/d]"),
        "{said}"
    );
    assert!(said.contains("`gh` (Claude Code"), "{said}");
    assert!(wrapped(&sb), "{said}");
    assert!(
        sb.home.join(".claude.json.moat-mcp-backup").exists(),
        "backed up before the first change"
    );
    // The change was re-pinned as a person's: no drift, and the rule set holds.
    let payload = mcp_payload("gh", &sb.home);
    let guard = sb.guard("claude-code", &payload);
    assert_eq!(guard.status.code(), Some(OK), "{}", text(&guard));
    // Undo.
    let undone = sb.moat_as_person(&["mcp", "unwrap", "gh"]);
    assert_eq!(undone.status.code(), Some(OK), "{}", text(&undone));
    assert!(!wrapped(&sb), "{}", text(&undone));
}

#[test]
fn a_no_is_kept_and_not_asked_again_and_the_server_stays_reported() {
    let sb = bare_with_servers();
    let out = init_answering(&sb, "n\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!wrapped(&sb), "{}", text(&out));
    assert!(text(&out).contains("left as they are"), "{}", text(&out));
    // The record did not leave the lock behind.
    let payload = mcp_payload("gh", &sb.home);
    let guard = sb.guard("claude-code", &payload);
    assert_eq!(guard.status.code(), Some(OK), "{}", text(&guard));

    let again = init_answering(&sb, "");
    assert_eq!(again.status.code(), Some(OK), "{}", text(&again));
    assert!(
        !text(&again).contains("Run them through OpenMoat?"),
        "{}",
        text(&again)
    );
    let said = stdout(&sb.moat(&["status"]));
    assert!(said.contains("starts outside OpenMoat"), "{said}");
}

#[test]
fn the_diff_is_shown_on_request_and_nothing_changes_before_the_answer() {
    let sb = bare_with_servers();
    let before = std::fs::read_to_string(sb.home.join(".claude.json")).unwrap();
    let out = init_answering(&sb, "d\nn\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("(after openmoat init)"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("mcp"), "{}", text(&out));
    assert_eq!(
        std::fs::read_to_string(sb.home.join(".claude.json")).unwrap(),
        before,
        "the diff changed the file"
    );
}

#[test]
fn nobody_at_a_terminal_and_the_opt_out_rewrite_nothing() {
    // `--yes` and no terminal: an existing server is reported, never rewritten.
    let sb = bare_with_servers();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!wrapped(&sb), "{}", text(&out));
    assert!(!text(&out).contains("Run them through"), "{}", text(&out));
    assert!(
        stdout(&sb.moat(&["status"])).contains("starts outside OpenMoat"),
        "reported"
    );

    // A person who opts out is not asked.
    let sb = bare_with_servers();
    let out = sb.moat_as_person(&["init", "--hosts", "claude-code", "--no-mcp-proxy"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!wrapped(&sb), "{}", text(&out));
    assert!(!text(&out).contains("Run them through"), "{}", text(&out));
}

/// A file OpenMoat does not rewrite is named and does not stop `init`.
#[cfg(unix)]
#[test]
fn a_yaml_definition_is_named_and_left() {
    let sb = Sandbox::bare(&[".hermes"]);
    let path = sb.home.join(".hermes/config.yaml");
    let original = "mcp_servers:\n  files:\n    command: npx\n";
    std::fs::write(&path, original).unwrap();
    let out = output(
        sb.command()
            .args(["init", "--hosts", "hermes"])
            .env("MOAT_ASSUME_TTY", "1"),
        Some("y\n"),
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("is YAML"), "{}", text(&out));
    let after = std::fs::read_to_string(&path).unwrap();
    assert!(after.contains("command: npx"), "{after}");
    assert!(!after.contains("mcp proxy"), "{after}");
}

/// The planted definition's server command would leave this file.
fn marker(project: &Path) -> PathBuf {
    project.join("planted-ran")
}

fn plant(project: &Path, relative: &str) {
    let script = format!("touch '{}'", marker(project).display());
    let file = project.join(relative);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(
        file,
        json!({"mcpServers": {"planted": {"command": "sh", "args": ["-c", script]}}}).to_string(),
    )
    .unwrap();
}

fn status_in(sb: &Sandbox, project: &Path) -> Value {
    let out = output(
        sb.command()
            .args(["status", "--format", "json"])
            .current_dir(project),
        None,
    );
    serde_json::from_str(&stdout(&out)).unwrap_or_else(|e| panic!("{e}: {}", text(&out)))
}

/// A definition a cloned project plants is reported by the hosts whose
/// project file it is, its tool calls are denied until accepted, and
/// reporting it runs nothing.
#[test]
fn a_planted_project_definition_is_reported_and_held_and_never_run_by_openmoat() {
    for id in ["claude-code", "cursor", "copilot-cli", "gemini-cli"] {
        let host: openmoat_hosts::Host = id.parse().unwrap();
        let sb = Sandbox::bare(&[&crate::hosts::dir_of(host)]);
        let out = sb.moat(&["init", "--yes", "--hosts", id]);
        assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
        let project = sb.project();
        let relative = host.spec().mcp.as_ref().unwrap().project_files[0].0;
        plant(&project, relative);

        let status = status_in(&sb, &project);
        let changes = status["mcp_changes"].to_string();
        assert!(changes.contains("planted"), "{id}: {status}");
        assert!(
            status["mcp_outside"].to_string().contains("planted"),
            "{id}: {status}"
        );
        let doctor = output(sb.command().args(["doctor"]).current_dir(&project), None);
        assert!(text(&doctor).contains("planted"), "{id}: {}", text(&doctor));
        assert!(
            !marker(&project).exists(),
            "{id}: reporting a definition started it"
        );
    }
}

#[test]
fn a_planted_definitions_tool_call_is_denied_and_an_accepted_one_passes() {
    let sb = Sandbox::bare(&[".claude"]);
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let project = sb.project();
    plant(&project, ".mcp.json");

    let denied = sb.guard("claude-code", &mcp_payload("planted", &project));
    assert_eq!(denied.status.code(), Some(DENY), "{}", text(&denied));
    assert!(
        text(&denied).contains("mcp-server-changed"),
        "{}",
        text(&denied)
    );
    assert!(!marker(&project).exists(), "the guard started it");

    // The person's own decision: accepted from the project, it passes.
    let accepted = output(
        sb.command()
            .args(["mcp", "accept"])
            .current_dir(&project)
            .env("MOAT_ASSUME_TTY", "1"),
        Some("y\n"),
    );
    assert_eq!(accepted.status.code(), Some(OK), "{}", text(&accepted));
    let passed = sb.guard("claude-code", &mcp_payload("planted", &project));
    assert_eq!(passed.status.code(), Some(OK), "{}", text(&passed));
    assert!(
        !text(&passed).contains("mcp-server-changed"),
        "{}",
        text(&passed)
    );
    assert_eq!(
        status_in(&sb, &project)["mcp_changes"],
        json!([]),
        "nothing waits for acceptance"
    );
}
