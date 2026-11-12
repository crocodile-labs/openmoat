//! `moat bench`: the `MoatBench` scenarios against OpenMoat itself, which must
//! meet every expectation (`docs/MOATBENCH.md`), and against fake hooks that allow
//! or deny everything.
//!
//! `cargo run -p openmoat -- bench` prints the scorecard.

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, json, output, stderr, stdout};

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

/// `moat bench --report` on one host, with the throwaway home below the
/// target directory.
fn report(sb: &Sandbox, format: &str) -> std::process::Output {
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let dir = scratch.path().to_string_lossy().into_owned();
    output(
        sb.command()
            .env("MOAT_CLAUDE_VERSION", "2.1.295")
            .args(["bench", "--report", "--host", "claude-code"])
            .args(["--scratch-dir", &dir, "--format", format]),
        None,
    )
}

/// One line for a failed run: the exit code, the first line of stderr and the
/// rows that are not PASS or NOT TESTED HERE, since a CI annotation shows only
/// a message's first line.
fn why_failed(out: &std::process::Output) -> String {
    let err = stderr(out);
    let first = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let rows: Vec<String> = serde_json::from_slice::<Value>(&out.stdout)
        .ok()
        .and_then(|r| r["rows"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter(|r| r["status"] != "pass" && r["status"] != "not-tested-here")
        .map(|r| format!("{}/{}: {}", r["promise"], r["layer"], r["reason"]))
        .collect();
    format!(
        "exit {:?}; stderr: {first}; failed rows: {}",
        out.status.code(),
        rows.join(" | ")
    )
}

/// Whether every OS row must have run the attack here.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn os_rows_must_run() -> bool {
    crate::run::netns_required()
}

/// No backend: `openmoat run` refuses here, so no OS row can run.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn os_rows_must_run() -> bool {
    false
}

/// A GitHub annotation naming a promise whose OS row was not run, so the next
/// run shows the reason in the Checks API. Written to the stream itself: the
/// test harness keeps what `println!` prints in a test that passes.
fn annotate_not_tested(promise: &str, reason: &str) {
    use std::io::Write as _;

    let reason = reason
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    let line =
        format!("::warning title=proof report::{promise}: OS sandbox not tested here: {reason}");
    let _ = writeln!(std::io::stdout(), "{line}");
}

/// The rows of `report` for `promise` at `layer`.
fn rows<'a>(report: &'a Value, promise: &str, layer: &str) -> Vec<&'a Value> {
    report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["promise"] == promise && r["layer"] == layer)
        .collect()
}

#[test]
fn moatbench_report_answers_every_promise_per_layer() {
    let sb = Sandbox::bare(&[]);
    let out = report(&sb, "json");
    let report = json(&out);
    println!("{report:#}");
    assert_eq!(
        out.status.code(),
        Some(OK),
        "{}\n{report:#}",
        why_failed(&out)
    );
    assert_eq!(report["format"], "openmoat-bench-report-v1");
    assert_eq!(report["openmoat"], env!("CARGO_PKG_VERSION"));
    assert_ne!(report["os"].as_str().unwrap(), "");
    assert_eq!(report["hosts"][0]["id"], "claude-code");
    // The hook rows are OpenMoat's model of the host, not a run of the
    // program named like it: no host version is reported beside them.
    assert_eq!(
        report["hosts"][0],
        serde_json::json!({"id": "claude-code", "evidence": "model"})
    );
    assert_eq!(report["summary"]["fail"], 0, "{report:#}");
    for promise in [
        "read-ssh-key",
        "build-script-reads-agent-login",
        "mcp-steers-write",
        "exfil-allowed-host",
        "turn-off-openmoat",
    ] {
        for layer in ["policy", "host-model"] {
            let found = rows(&report, promise, layer);
            assert_eq!(found.len(), 1, "{promise} {layer}");
            assert_eq!(found[0]["status"], "pass", "{promise} {layer}: {report:#}");
            assert_ne!(found[0]["reproduce"], serde_json::json!([]));
        }
    }
    let network = rows(&report, "exfil-allowed-host", "network");
    assert_eq!(network[0]["status"], "pass", "{report:#}");
    // OpenMoat's side of a failed hook is exercised; the host's needs the host.
    let failed = rows(&report, "hook-fails-closed", "host-model");
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["status"], "pass", "{report:#}");
    let real = rows(&report, "hook-fails-closed", "real-host");
    assert_eq!(real.len(), 1);
    assert_eq!(real[0]["status"], "not-tested-here");
    assert!(
        real[0]["reason"]
            .as_str()
            .unwrap()
            .contains("needs the real host"),
        "{report:#}"
    );
    // The OS rows ran the attack, or say why not; never a pass without a run.
    // CI's macOS jobs run Seatbelt and its Linux jobs Landlock in a network
    // namespace, so there they must pass; a stock-Linux run may report
    // NOT TESTED HERE with its reason.
    let must_run = os_rows_must_run();
    for promise in [
        "read-ssh-key",
        "build-script-reads-agent-login",
        "turn-off-openmoat",
    ] {
        let os = rows(&report, promise, "os-sandbox");
        assert_eq!(os.len(), 1, "{promise}");
        let status = os[0]["status"].as_str().unwrap();
        // The reason first: a CI annotation shows only the first line.
        let reason = os[0]["reason"]
            .as_str()
            .unwrap_or_default()
            .replace('\n', " ");
        if must_run {
            assert_eq!(status, "pass", "{promise}: {reason}\n{report:#}");
        } else if status != "pass" {
            assert_eq!(status, "not-tested-here", "{promise}: {reason}\n{report:#}");
            assert_ne!(os[0]["reason"].as_str().unwrap(), "");
            eprintln!("{promise}: OS sandbox not tested here: {}", os[0]["reason"]);
            if cfg!(target_os = "linux") && std::env::var_os("CI").is_some() {
                annotate_not_tested(promise, &reason);
            }
        }
        if cfg!(windows) {
            assert_eq!(status, "not-tested-here");
        }
    }
    assert!(
        !sb.home.join(".moat").exists(),
        "the throwaway home is not the caller's"
    );
}

#[test]
fn moatbench_report_in_markdown_and_text() {
    let sb = Sandbox::bare(&[]);
    let out = report(&sb, "markdown");
    let json_run = report(&sb, "json");
    assert_eq!(out.status.code(), Some(OK), "{}", why_failed(&json_run));
    let markdown = stdout(&out);
    assert!(
        markdown.starts_with("# MoatBench proof report\n"),
        "{markdown}"
    );
    assert!(
        markdown.contains("| Promise | Layer | Check | Status | Why | Reproduce |"),
        "{markdown}"
    );
    assert!(
        markdown.contains("`readme-injection-posts-ssh-key`"),
        "{markdown}"
    );
    assert!(markdown.contains("**NOT TESTED HERE**"), "{markdown}");
    assert!(
        markdown.contains("| host model (golden payloads) |")
            && markdown.contains("- **hosts**: claude-code (model, not run)")
            && !markdown.contains("| host hook |"),
        "{markdown}"
    );
    let text = stdout(&report(&sb, "text"));
    assert!(text.starts_with("MoatBench proof report\n"), "{text}");
    assert!(
        text.contains("can an agent read ~/.ssh/id_rsa? [read-ssh-key]"),
        "{text}"
    );
    assert!(text.contains("NOT TESTED HERE is not a pass."), "{text}");
}

#[test]
fn moatbench_report_refuses_what_it_cannot_do() {
    let sb = Sandbox::bare(&[]);
    // Markdown is the proof report's; --hook tests another hook, not OpenMoat.
    let out = sb.moat(&["bench", "--format", "markdown"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", stderr(&out));
    let out = sb.moat(&["bench", "--report", "--hook", "true", "--host", "codex"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", stderr(&out));
    // The throwaway home is never the caller's home or above it.
    let home = sb.home.to_string_lossy().into_owned();
    let out = sb.moat(&[
        "bench",
        "--report",
        "--host",
        "codex",
        "--scratch-dir",
        &home,
    ]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("is your home directory"),
        "{}",
        stderr(&out)
    );
}
