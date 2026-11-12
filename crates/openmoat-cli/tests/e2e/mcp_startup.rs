//! MCP servers start only from a definition a person accepted (ADR-049):
//! `openmoat mcp proxy` refuses a new or changed one before it runs anything;
//! `openmoat mcp wrap` sandboxes by default and keeps a server's choice; and
//! `openmoat status` and `doctor` name servers that start outside OpenMoat.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use serde_json::{Value, json};

#[cfg(unix)]
use crate::common::stderr;
use crate::common::{OK, Sandbox, output, stdout, text};

const SERVERS: &str = r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-server"]}}}"#;

fn installed() -> Sandbox {
    let sb = Sandbox::bare(&[".claude"]);
    std::fs::write(sb.home.join(".claude.json"), SERVERS).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    sb
}

#[cfg(unix)]
fn initialize() -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}}})
    .to_string()
        + "\n"
        + &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string()
        + "\n"
}

#[cfg(unix)]
/// What follows `mcp proxy` for a server that creates `marker` when it runs.
fn marking(marker: &Path) -> Vec<String> {
    let script = format!("touch '{}'; cat >/dev/null", marker.display());
    ["--server", "marker", "--", "sh", "-c", &script]
        .map(str::to_owned)
        .to_vec()
}

#[cfg(unix)]
fn proxy(sb: &Sandbox, line: &[String]) -> std::process::Output {
    output(
        sb.command().args(["mcp", "proxy"]).args(line),
        Some(&initialize()),
    )
}

#[cfg(unix)]
fn define(sb: &Sandbox, line: &[String]) {
    let args: Vec<&str> = line.iter().map(String::as_str).collect();
    sb.define_wrapped("marker", &args);
}

#[cfg(unix)]
/// The proxy refused: exit 1, the agent got error -32001 naming `openmoat mcp
/// accept marker`, the server never ran.
fn assert_refused(out: &std::process::Output, marker: &Path, why: &str) {
    assert_eq!(out.status.code(), Some(1), "{}", text(out));
    let answer: Value = serde_json::from_str(stdout(out).lines().next().unwrap()).unwrap();
    assert_eq!(answer["id"], 1, "{answer}");
    assert_eq!(answer["error"]["code"], -32001, "{answer}");
    let message = answer["error"]["message"].as_str().unwrap();
    assert!(message.contains(why), "{message}");
    assert!(stderr(out).contains(why), "{}", stderr(out));
    assert!(!marker.exists(), "the server ran: {}", marker.display());
}

// protection: mcp claude-code linux,macos
#[cfg(unix)]
#[test]
fn an_unaccepted_definition_never_starts_and_an_accepted_one_does() {
    let sb = installed();
    let marker = sb.home.join("ran");
    let line = marking(&marker);
    define(&sb, &line);

    let out = proxy(&sb, &line);
    assert_refused(&out, &marker, "openmoat mcp accept marker");
    assert!(stderr(&out).contains("is new"), "{}", stderr(&out));
    let audit = sb.moat(&["show", "--recent", "5", "--format", "json"]);
    assert!(text(&audit).contains("mcp__marker"), "{}", text(&audit));
    assert!(
        text(&audit).contains("mcp-server-changed"),
        "{}",
        text(&audit)
    );

    sb.accept_mcp();
    let out = proxy(&sb, &line);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(marker.exists(), "the accepted server started");
}

#[cfg(unix)]
#[test]
fn a_changed_definition_never_starts() {
    let sb = installed();
    let marker = sb.home.join("ran");
    let line = marking(&marker);
    define(&sb, &line);
    sb.accept_mcp();
    // A changed command line in the file, and the proxy started with it.
    let mut changed = line.clone();
    changed[5] = format!("{}; echo changed", changed[5]);
    define(&sb, &changed);
    let out = proxy(&sb, &changed);
    assert_refused(&out, &marker, "openmoat mcp accept marker");
    assert!(stderr(&out).contains("changed"), "{}", stderr(&out));
    // The old command line is no definition's any more.
    assert_refused(&proxy(&sb, &line), &marker, "is new");
    // Only an environment variable added.
    define(&sb, &line);
    sb.accept_mcp();
    let path = sb.home.join(".claude.json");
    let mut root: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    root["mcpServers"]["marker"]["env"] = json!({"NODE_OPTIONS": "--require ./x.js"});
    std::fs::write(&path, root.to_string()).unwrap();
    let out = output(
        sb.command()
            .args(["mcp", "proxy"])
            .args(&line)
            .env("NODE_OPTIONS", "--require ./x.js"),
        Some(&initialize()),
    );
    assert_refused(&out, &marker, "env.NODE_OPTIONS");
}

#[cfg(unix)]
#[test]
fn a_command_line_no_definition_gives_never_starts() {
    let sb = installed();
    let marker = sb.home.join("ran");
    assert_refused(&proxy(&sb, &marking(&marker)), &marker, "is new");
}

#[cfg(unix)]
#[test]
fn a_drifted_lock_starts_nothing() {
    let sb = installed();
    let marker = sb.home.join("ran");
    let line = marking(&marker);
    define(&sb, &line);
    sb.accept_mcp();
    let policy = sb.home.join(".moat/policy.yaml");
    let now = std::fs::read_to_string(&policy).unwrap();
    std::fs::write(&policy, now + "\n# tampered\n").unwrap();
    assert_refused(&proxy(&sb, &line), &marker, "drift");
}

/// The `args` of `name` in `~/.claude.json`.
fn args_of(sb: &Sandbox, name: &str) -> Value {
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".claude.json")).unwrap())
            .unwrap();
    file["mcpServers"][name]["args"].clone()
}

fn sandboxed(sb: &Sandbox, name: &str) -> bool {
    args_of(sb, name)
        .as_array()
        .unwrap()
        .iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--sandbox")
}

#[test]
fn wrap_sandboxes_by_default_and_a_rewrap_keeps_the_choice() {
    let sb = installed();
    let out = sb.moat_as_person(&["mcp", "wrap", "gh"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        sandboxed(&sb, "gh") || text(&out).contains("without `openmoat run`'s sandbox"),
        "sandboxed by default, or told why not: {}",
        text(&out)
    );

    let out = sb.moat_as_person(&["mcp", "wrap", "--no-sandbox", "gh"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!sandboxed(&sb, "gh"), "{}", args_of(&sb, "gh"));
    let out = sb.moat_as_person(&["mcp", "wrap", "gh"]);
    assert!(
        text(&out).contains("no stdio MCP server to wrap"),
        "{}",
        text(&out)
    );
    assert!(!sandboxed(&sb, "gh"), "the choice is kept");

    let out = sb.moat_as_person(&["mcp", "wrap", "--sandbox", "gh"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(sandboxed(&sb, "gh"), "{}", args_of(&sb, "gh"));
    sb.moat_as_person(&["mcp", "wrap", "gh"]);
    assert!(sandboxed(&sb, "gh"), "the choice is kept");
    assert_eq!(
        args_of(&sb, "gh"),
        json!([
            "mcp",
            "proxy",
            "--server",
            "gh",
            "--host",
            "claude-code",
            "--sandbox",
            "--",
            "npx",
            "-y",
            "gh-server"
        ])
    );
    // Each switch was re-pinned as a person's change.
    let payload = json!({"session_id": "s", "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "mcp__gh__x", "tool_input": {},
        "tool_use_id": "t"});
    let out = sb.guard("claude-code", &payload.to_string());
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
}

#[test]
fn status_and_doctor_name_servers_that_start_outside_openmoat() {
    let sb = installed();
    let status = sb.moat(&["status"]);
    assert_eq!(
        status.status.code(),
        Some(OK),
        "a warning only: {}",
        text(&status)
    );
    let said = stdout(&status);
    assert!(said.contains("`gh` (Claude Code,"), "{said}");
    assert!(said.contains("starts outside OpenMoat"), "{said}");
    let doctor = sb.moat(&["doctor"]);
    assert!(
        crate::common::squash(&stdout(&doctor)).contains("! MCP servers `gh`"),
        "{}",
        text(&doctor)
    );

    sb.moat_as_person(&["mcp", "wrap", "--no-sandbox", "gh"]);
    let said = stdout(&sb.moat(&["status"]));
    assert!(said.contains("without the sandbox"), "{said}");
    assert!(!said.contains("starts outside OpenMoat"), "{said}");

    // A project's server, which Claude Code starts without asking.
    let project: PathBuf = sb.project();
    std::fs::write(
        project.join(".mcp.json"),
        r#"{"mcpServers": {"helper": {"command": "sh", "args": ["-c", "id"]}}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(project.join(".claude")).unwrap();
    std::fs::write(
        project.join(".claude/settings.local.json"),
        r#"{"enabledMcpjsonServers": ["helper"]}"#,
    )
    .unwrap();
    for args in [
        ["status", "--format", "json"],
        ["doctor", "--format", "json"],
    ] {
        let out = output(sb.command().args(args).current_dir(&project), None);
        let said = stdout(&out);
        assert!(said.contains("is a project's server"), "{said}");
        assert!(said.contains("without asking"), "{said}");
        assert!(said.contains("enabledMcpjsonServers"), "{said}");
    }
}
