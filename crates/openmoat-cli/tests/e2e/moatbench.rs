//! `moat bench`: the `MoatBench` scenarios against OpenMoat itself, which must
//! meet every expectation (`docs/MOATBENCH.md`), and against fake hooks that allow
//! or deny everything.
//!
//! `cargo run -p openmoat -- bench` prints the scorecard.

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, json, stderr, stdout};

/// Run `moat bench` with `args` in an isolated home; exits 0 whatever the scores.
fn bench(sb: &Sandbox, args: &[&str]) -> (Value, String) {
    let out = sb.moat(&[&["bench", "--format", "json"], args].concat());
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    (json(&out), stderr(&out))
}

/// A hook script in the sandbox; `unix` and `windows` are its body for `sh` and `cmd`.
fn fake_hook(sb: &Sandbox, name: &str, unix: &str, windows: &str) -> String {
    let path = if cfg!(windows) {
        let path = sb.home.join(format!("{name}.cmd"));
        std::fs::write(&path, format!("@echo off\r\n{windows}\r\n")).unwrap();
        path
    } else {
        let path = sb.home.join(format!("{name}.sh"));
        std::fs::write(&path, format!("#!/bin/sh\n{unix}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    };
    path.to_string_lossy().into_owned()
}

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn moatbench_mini_openmoat_meets_every_expectation() {
    let sb = Sandbox::bare(&[]);
    let (report, _) = bench(&sb, &[]);
    println!("{report:#}");
    assert_eq!(report["target"], "openmoat");
    // The names first, on one line: a CI annotation shows only that line.
    let mismatches = names(&report["mismatches"]);
    assert!(mismatches.is_empty(), "{mismatches:?}\n{report:#}");
    let false_positives = names(&report["false_positives"]);
    assert!(
        false_positives.is_empty(),
        "{false_positives:?}\n{report:#}"
    );
    let benign = &report["categories"]["benign"];
    assert!(benign["runs"].as_u64().unwrap() > 0);
    assert_eq!(benign["allowed"], benign["runs"]);
    let attacks = &report["categories"]["exfiltration"];
    assert_eq!(attacks["allowed"], 0, "{report:#}");
    assert!(report.get("hook_failure").is_none());
    assert!(
        !sb.home.join(".moat").exists(),
        "the throwaway home is not the caller's"
    );
}

#[test]
fn moatbench_hook_that_allows_everything_shows_the_attacks_it_lets_through() {
    let sb = Sandbox::bare(&[]);
    let allow =
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#;
    let hook = fake_hook(
        &sb,
        "allow-all",
        &format!("cat >/dev/null\necho '{allow}'"),
        &format!("echo {allow}"),
    );
    let (report, err) = bench(
        &sb,
        &["--hook", &hook, "--host", "claude-code", "--verbose"],
    );
    assert_eq!(report["hosts"], serde_json::json!(["claude-code"]));
    assert!(names(&report["false_positives"]).is_empty(), "{report:#}");
    let mismatches = names(&report["mismatches"]);
    assert!(
        mismatches.iter().any(|m| m.starts_with(
            "readme-injection-posts-ssh-key (claude-code): step 1: expected deny, got allow"
        )),
        "{mismatches:#?}"
    );
    assert_eq!(report["categories"]["exfiltration"]["blocked"], 0);
    assert_eq!(report["known_gaps"], serde_json::json!([]));
    let failure = report["hook_failure"][0]["behaviour"].as_str().unwrap();
    assert!(failure.contains("runs the call"), "{failure}");
    // --verbose shows what the hook gets, and nothing of the caller's environment.
    assert!(err.contains("\"hook_event_name\":\"PreToolUse\""), "{err}");
    assert!(
        err.contains("environment (nothing else is passed)"),
        "{err}"
    );
    assert!(
        !err.contains("MOAT_HOME") && !err.contains("CLAUDE_CONFIG_DIR"),
        "{err}"
    );
}

#[test]
fn moatbench_hook_that_denies_everything_blocks_attacks_and_work() {
    let sb = Sandbox::bare(&[]);
    let hook = fake_hook(
        &sb,
        "deny-all",
        "echo denied >&2\nexit 2",
        "echo denied 1>&2\r\nexit /b 2",
    );
    let out = sb.moat(&["bench", "--hook", &hook, "--host", "codex"]);
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("MoatBench mini: "), "{text}");
    assert!(
        text.contains(
            "hook failure (host behaviour from docs/THREAT_MODEL.md §5, not tested here):"
        ),
        "{text}"
    );
    assert!(text.contains("  codex: runs the call when"), "{text}");
    let (report, _) = bench(&sb, &["--hook", &hook, "--host", "codex"]);
    let attacks = &report["categories"]["exfiltration"];
    assert_eq!(attacks["blocked"], attacks["runs"], "{report:#}");
    assert!(!names(&report["false_positives"]).is_empty(), "{report:#}");
}

#[test]
fn moatbench_hook_needs_a_host() {
    let sb = Sandbox::bare(&[]);
    let out = sb.moat(&["bench", "--hook", "true"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", stderr(&out));
}
