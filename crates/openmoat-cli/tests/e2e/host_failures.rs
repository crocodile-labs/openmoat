//! Our side of the host failure matrix (`docs/THREAT_MODEL.md` §5 "When the
//! hook fails", #337), per host payload shape: what `guard` cannot read is
//! denied with exit 2 in the host's own format; a tool OpenMoat does not govern
//! is allowed and recorded; a guard that cannot decide in time denies before the
//! host's timeout; a hook whose binary is gone is reported as `not protected`.

use std::fs;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::common::{DENY, Sandbox, USAGE, fixture, json, stderr, text};

/// One host payload shape: how `guard` is run for it and where its verdict is.
struct Shape {
    name: &'static str,
    /// `--host` of the hook that receives it.
    hook: &'static str,
    /// Set by the host for its hooks (`cn` sets `CONTINUE_PROJECT_DIR`).
    env: Option<&'static str>,
    /// A payload this host sends for a governed tool.
    governed: &'static str,
    /// The same payload for a tool OpenMoat does not know, naming a secret path.
    unknown_tool: Value,
    /// A valid payload for an event the adapter does not handle.
    unknown_event: Value,
}

fn shapes() -> [Shape; 5] {
    let pre_tool_use = |tool: &str| {
        json!({"session_id": "s", "cwd": "/p", "hook_event_name": "PreToolUse",
               "tool_name": tool, "tool_input": {"file_path": "~/.ssh/id_rsa"}})
    };
    let post_tool_use = json!({"session_id": "s", "hook_event_name": "PostToolUse",
                               "tool_name": "Bash", "tool_input": {"command": "ls"}});
    [
        Shape {
            name: "claude-code",
            hook: "claude-code",
            env: None,
            governed: "claude-code/bash.json",
            unknown_tool: pre_tool_use("FutureTool"),
            unknown_event: post_tool_use.clone(),
        },
        Shape {
            name: "codex",
            hook: "codex",
            env: None,
            governed: "codex/pretooluse-shell.json",
            unknown_tool: pre_tool_use("future_tool"),
            unknown_event: post_tool_use.clone(),
        },
        Shape {
            name: "cursor",
            hook: "cursor",
            env: None,
            governed: "cursor/preToolUse-write.json",
            unknown_tool: json!({"conversation_id": "s", "hook_event_name": "preToolUse",
                "workspace_roots": ["/p"], "tool_name": "FutureTool",
                "tool_input": {"file_path": "~/.ssh/id_rsa"}}),
            unknown_event: json!({"hook_event_name": "afterFileEdit", "file_path": "/p/x"}),
        },
        Shape {
            name: "continue",
            hook: "claude-code",
            env: Some("CONTINUE_PROJECT_DIR"),
            governed: "continue/pretooluse-bash.json",
            unknown_tool: pre_tool_use("FutureTool"),
            unknown_event: post_tool_use,
        },
        // OpenMoat's OpenClaw plugin: an unknown tool is `tool.unknown`, which
        // the default policy leaves to OpenClaw (no output).
        Shape {
            name: "openclaw",
            hook: "openclaw",
            env: None,
            governed: "openclaw/exec.json",
            unknown_tool: json!({"hook_event_name": "before_tool_call", "toolName": "future_tool",
                "params": {"path": "~/.ssh/id_rsa"}, "sessionId": "s", "cwd": "/p"}),
            unknown_event: json!({"hook_event_name": "after_tool_call", "toolName": "exec",
                "params": {"command": "ls"}}),
        },
    ]
}

impl Shape {
    fn command(&self, sb: &Sandbox) -> Command {
        let mut cmd = sb.command();
        cmd.args(["guard", "--host", self.hook]);
        if let Some(var) = self.env {
            cmd.env(var, &sb.home);
        }
        cmd
    }

    fn guard(&self, sb: &Sandbox, payload: &str) -> Output {
        crate::common::output(&mut self.command(sb), Some(payload))
    }

    /// The verdict in the host's response document.
    fn verdict(&self, out: &Output) -> String {
        let doc = json(out);
        let verdict = match self.hook {
            "cursor" => &doc["permission"],
            "openclaw" => &doc["decision"],
            _ => &doc["hookSpecificOutput"]["permissionDecision"],
        };
        verdict.as_str().unwrap_or_default().to_owned()
    }
}

fn assert_denied(shape: &Shape, out: &Output, what: &str) {
    let name = shape.name;
    assert_eq!(
        out.status.code(),
        Some(DENY),
        "{name} {what}: {}",
        text(out)
    );
    assert_eq!(shape.verdict(out), "deny", "{name} {what}: {}", text(out));
    assert!(
        stderr(out).contains("kernel-error"),
        "{name} {what}: {}",
        text(out)
    );
}

#[test]
fn payloads_guard_cannot_read_are_denied_in_each_hosts_format() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    for shape in shapes() {
        let governed = fixture(shape.governed);
        let truncated = &governed[..governed.len() / 2];
        for (what, payload) in [
            ("empty", ""),
            ("not JSON", "not json"),
            ("truncated", truncated),
            ("an array", "[1]"),
            ("an empty object", "{}"),
        ] {
            assert_denied(&shape, &shape.guard(&sb, payload), what);
        }
        let event = shape.unknown_event.to_string();
        assert_denied(&shape, &shape.guard(&sb, &event), "unknown event");
    }
}

/// A tool OpenMoat does not know is recorded with rule `ungoverned` and left
/// to the host: no output, so the host's own prompt and permission rules
/// decide it, as if no hook had answered. An unknown name can still reach
/// `guard` through a matcher that also matches it. Cursor's `preToolUse` sends
/// every tool, and there an unknown tool that names a path is checked as
/// reading it (one that names none asks, `cursor.rs`).
#[test]
fn an_unknown_tool_is_left_to_the_host_unless_cursor_sees_a_path() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    for shape in shapes() {
        let out = shape.guard(&sb, &shape.unknown_tool.to_string());
        if shape.name == "cursor" {
            assert_eq!(out.status.code(), Some(2), "cursor: {}", text(&out));
            assert_eq!(shape.verdict(&out), "deny", "cursor: {}", text(&out));
            assert!(
                text(&out).contains("secrets-paths"),
                "cursor: {}",
                text(&out)
            );
        } else {
            assert_eq!(out.status.code(), Some(0), "{}: {}", shape.name, text(&out));
            assert!(out.stdout.is_empty(), "{}: {}", shape.name, text(&out));
        }
    }
    // OpenClaw's unknown tool is `default.tool.unknown`, not `ungoverned`.
    let shown = sb.moat(&["show", "--recent", "5"]);
    assert_eq!(
        text(&shown).matches("(ungoverned)").count(),
        3,
        "{}",
        text(&shown)
    );
}

/// A host that times the hook out runs the call (most do), so `guard` denies on
/// its own first: here its payload never ends, and it answers within its budget.
#[test]
fn a_guard_that_cannot_decide_in_time_denies_before_the_host_times_out() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    let budget = Duration::from_secs(30);
    let started = Instant::now();
    let running: Vec<_> = shapes()
        .into_iter()
        .map(|shape| {
            let mut child = shape
                .command(&sb)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let open_stdin = child.stdin.take();
            (shape, child, open_stdin)
        })
        .collect();
    for (shape, child, open_stdin) in running {
        let out = child.wait_with_output().unwrap();
        drop(open_stdin);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= budget,
            "{}: answered after {elapsed:?}",
            shape.name
        );
        assert!(
            elapsed < budget * 3,
            "{}: answered after {elapsed:?}",
            shape.name
        );
        assert_denied(&shape, &out, "stuck");
        assert!(
            stderr(&out).contains("no decision within 30 s"),
            "{}",
            text(&out)
        );
    }
    // Not in the audit log, which may be what hangs: one line each in a side
    // file, owner-only, which `moat doctor` reports without failing.
    let log = sb.home.join(".moat/guard-hangs.log");
    let lines = fs::read_to_string(&log).unwrap();
    assert_eq!(lines.lines().count(), shapes().len(), "{lines}");
    // Each line names the phase the guard was stuck in, and how long it ran.
    for line in lines.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 4, "{line}");
        assert_eq!(fields[2], "stdin", "{line}");
        assert!(fields[3].parse::<u128>().unwrap() >= 30_000, "{line}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let doctor = sb.moat(&["doctor"]);
    assert!(
        text(&doctor).contains("! guard            5 call(s) denied with no decision within 30 s"),
        "{}",
        text(&doctor)
    );
    assert!(
        text(&doctor).contains("most while reading the tool call (phase stdin)"),
        "{}",
        text(&doctor)
    );
    assert_eq!(doctor.status.code(), Some(0), "{}", text(&doctor));
}

/// The hook command names a binary that no longer exists (an upgrade removed
/// it): every host but Cursor would run the call, so `status` and `doctor` say so.
#[test]
fn a_hook_whose_binary_is_gone_is_not_protected() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    let escaped = |path: &str| {
        serde_json::to_string(path)
            .unwrap()
            .trim_matches('"')
            .to_owned()
    };
    let binary = escaped(env!("CARGO_BIN_EXE_openmoat"));
    let gone = escaped(&sb.home.join("gone/moat").to_string_lossy());
    for file in [
        ".claude/settings.json",
        ".codex/hooks.json",
        ".cursor/hooks.json",
    ] {
        let path = sb.home.join(file);
        let edited = fs::read_to_string(&path).unwrap().replace(&binary, &gone);
        assert!(edited.contains(&gone), "{file}");
        fs::write(&path, edited).unwrap();
    }

    let status = sb.moat(&["status", "--format", "json"]);
    // OpenClaw has no directory in this sandbox, so it is `not-found`.
    let agents: Vec<Value> = json(&status)["agents"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a["level"] != "not-found")
        .collect();
    assert_eq!(agents.len(), 3, "{}", text(&status));
    for agent in &agents {
        assert_eq!(agent["level"], "not-protected", "{agent}");
        assert_eq!(agent["reason"], "hook out of date", "{agent}");
    }
    for args in [["status"], ["doctor"]] {
        let out = sb.moat(&args);
        assert_eq!(out.status.code(), Some(USAGE), "{args:?}: {}", text(&out));
        assert_eq!(
            text(&out).matches("which does not exist").count(),
            3,
            "{}",
            text(&out)
        );
        assert!(
            text(&out).contains("not protected"),
            "{args:?}: {}",
            text(&out)
        );
    }
}

/// An install from before a tool joined the matcher: the hook is out of date
/// until `moat init` rewrites the matcher in place and re-pins the hook file.
#[test]
fn moat_init_adds_a_new_tool_to_an_installed_matcher() {
    let sb = Sandbox::installed(&[".claude"]);
    let path = sb.home.join(".claude/settings.json");
    let old = fs::read_to_string(&path).unwrap().replace("|WebSearch", "");
    fs::write(&path, old).unwrap();
    let status = json(&sb.moat(&["status", "--format", "json"]));
    assert_eq!(
        status["agents"][0]["reason"], "hook out of date",
        "{status}"
    );

    // The hook file drifted from the lock, so the repair is a person's.
    assert_eq!(sb.moat_as_person(&["init", "--yes"]).status.code(), Some(0));
    let settings: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let matcher = settings["hooks"]["PreToolUse"][0]["matcher"]
        .as_str()
        .unwrap();
    assert!(matcher.split('|').any(|m| m == "WebSearch"), "{matcher}");
    let out = sb.guard("claude-code", &fixture("claude-code/websearch.json"));
    assert_eq!(
        out.status.code(),
        Some(0),
        "the re-pinned hook file: {}",
        text(&out)
    );
    assert!(text(&out).contains("default.web.search"), "{}", text(&out));
}
