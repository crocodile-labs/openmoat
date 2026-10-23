//! Our side of the host failure matrix (`docs/THREAT_MODEL.md` §5 "When the
//! hook fails", #337), per host payload shape: what `guard` cannot read is
//! denied with exit 2 in the host's own format; a tool OpenMoat does not govern
//! is allowed and recorded; a guard that cannot decide in time denies before the
//! host's timeout; a hook whose binary is gone is reported as `not protected`.

use std::fs;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::common::{DENY, Sandbox, USAGE, fixture, json, stderr, text};
use crate::hosts::rows::{Row, rows};
use crate::hosts::{assert_reason, guard, verdict};

/// `moat guard` for `row`'s hook, its input not yet written.
fn command(row: &Row, sb: &Sandbox) -> Command {
    let mut cmd = sb.command();
    cmd.args(["guard", "--host", row.hook]);
    if let Some(var) = row.env {
        cmd.env(var, &sb.home);
    }
    cmd
}

fn assert_denied(row: &Row, out: &Output, what: &str) {
    let name = row.id;
    assert_eq!(
        out.status.code(),
        Some(DENY),
        "{name} {what}: {}",
        text(out)
    );
    assert_eq!(verdict(row, out), "deny", "{name} {what}: {}", text(out));
    assert!(
        stderr(out).contains("kernel-error"),
        "{name} {what}: {}",
        text(out)
    );
    assert_reason(row, out, "kernel-error", what);
}

#[test]
fn payloads_guard_cannot_read_are_denied_in_each_hosts_format() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    for row in rows() {
        let governed = fixture(row.governed);
        let truncated = &governed[..governed.len() / 2];
        for (what, payload) in [
            ("empty", ""),
            ("not JSON", "not json"),
            ("truncated", truncated),
            ("an array", "[1]"),
            ("an empty object", "{}"),
        ] {
            assert_denied(&row, &guard(&row, &sb, payload), what);
        }
        let event = (row.unknown_event)().to_string();
        assert_denied(&row, &guard(&row, &sb, &event), "unknown event");
    }
}

/// A tool OpenMoat does not know is recorded with rule `ungoverned` and left
/// to the host: no output, so the host's own prompt and permission rules
/// decide it, as if no hook had answered. An unknown name can still reach
/// `guard` through a matcher that also matches it. The hosts whose row says
/// `checks_unknown_tools` send every tool, and there an unknown tool is checked for the
/// paths, URLs and commands its arguments name: one naming a secret is denied,
/// even where the host runs a call OpenMoat makes no decision on (pi).
#[test]
fn an_unknown_tool_naming_a_secret_is_denied_where_openmoat_sees_it() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    for row in rows() {
        let out = guard(&row, &sb, &(row.unknown_tool)().to_string());
        if row.checks_unknown_tools {
            let name = row.id;
            assert_eq!(out.status.code(), Some(2), "{name}: {}", text(&out));
            assert_eq!(verdict(&row, &out), "deny", "{name}: {}", text(&out));
            assert!(
                text(&out).contains("secrets-paths"),
                "{name}: {}",
                text(&out)
            );
        } else {
            assert_eq!(out.status.code(), Some(0), "{}: {}", row.id, text(&out));
            assert!(out.stdout.is_empty(), "{}: {}", row.id, text(&out));
        }
    }
    // Where OpenMoat checks an unknown tool it is not `ungoverned`. One row
    // per host: older rows would fall off a shorter list.
    let recent = rows().len().to_string();
    let left = rows().iter().filter(|r| !r.checks_unknown_tools).count();
    let shown = sb.moat(&["show", "--recent", &recent]);
    assert_eq!(
        text(&shown).matches("(ungoverned)").count(),
        left,
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
    let running: Vec<_> = rows()
        .into_iter()
        .map(|row| {
            let mut child = command(&row, &sb)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let open_stdin = child.stdin.take();
            (row, child, open_stdin)
        })
        .collect();
    for (row, child, open_stdin) in running {
        let out = child.wait_with_output().unwrap();
        drop(open_stdin);
        let elapsed = started.elapsed();
        assert!(elapsed >= budget, "{}: answered after {elapsed:?}", row.id);
        assert!(
            elapsed < budget * 3,
            "{}: answered after {elapsed:?}",
            row.id
        );
        assert_denied(&row, &out, "stuck");
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
    assert_eq!(lines.lines().count(), rows().len(), "{lines}");
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
    let denied = format!(
        "! guard            {} call(s) denied with no decision within 30 s",
        rows().len()
    );
    assert!(text(&doctor).contains(&denied), "{}", text(&doctor));
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
    // OpenClaw and pi have no directory in this sandbox, so they are `not-found`.
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
