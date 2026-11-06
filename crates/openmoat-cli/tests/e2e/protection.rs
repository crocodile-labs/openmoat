//! Each agent's protection level in `moat status` (text and JSON), `moat doctor`
//! and the home screen (#334).

use std::fs;

use serde_json::Value;

use crate::common::{OK, Sandbox, json, output, squash, stdout, text};

/// The `agents` entry of `moat status --format json` for `host`.
fn agent(sb: &Sandbox, host: &str) -> Value {
    let out = sb.moat(&["status", "--format", "json"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    json(&out)["agents"]
        .as_array()
        .and_then(|agents| agents.iter().find(|a| a["host"] == host).cloned())
        .unwrap_or_else(|| panic!("{host} missing: {}", text(&out)))
}

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
#[test]
fn each_agent_reports_its_level_and_gaps() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    let status = squash(&stdout(&sb.moat(&["status"])));
    // `!` instead of `✔` where something else names the agent: an advisory
    // for the version on the search path, Linux's TIOCSTI warning for Codex.
    for name in ["Claude Code", "Codex", "Cursor"] {
        let line = format!(" {name} hook + OS sandbox\n");
        assert!(status.contains(&line), "{line:?} in {status}");
        assert!(!status.contains(&format!("✗ {name}")), "{status}");
    }
    // The known gaps, with every check, only with --verbose.
    assert!(!status.contains("known gaps"), "{status}");
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let doctor = squash(&stdout(&out));
    assert!(doctor.contains(" Codex hook + OS sandbox\n"), "{doctor}");
    assert!(doctor.contains(" Cursor hook + OS sandbox\n"), "{doctor}");
    assert!(!doctor.contains("known gaps:"), "{doctor}");
    let verbose = squash(&stdout(&sb.moat(&["doctor", "--verbose"])));
    for line in [
        "· Claude Code known gaps: file tools, WebFetch and MCP servers run outside the OS sandbox",
        "· Codex known gaps: web search, hosted tools, code mode's `exec`/`wait` and \
         `request_permissions` are not hooked; what `write_stdin` types into a running command \
         is not hooked",
        "· Cursor known gaps: commands Cursor runs outside its sandbox",
        "· Codex protection: hook + OS sandbox",
        "· Cursor protection: hook + OS sandbox",
    ] {
        assert!(verbose.contains(line), "{line:?} in {verbose}");
    }

    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "hook-and-os-sandbox", "{claude}");
    assert_eq!(claude["reason"], Value::Null, "{claude}");
    assert_eq!(claude["name"], "Claude Code");
    let gaps = claude["gaps"].as_str().unwrap();
    assert!(
        gaps.contains("MCP servers") && !gaps.contains("WebSearch"),
        "{gaps}"
    );
    let cursor = agent(&sb, "cursor");
    assert_eq!(cursor["level"], "hook-and-os-sandbox", "{cursor}");

    let home = text(&output(&mut sb.command(), Some("")));
    assert!(
        home.contains(
            "Protecting Claude Code (hook + OS sandbox), Codex (hook + OS sandbox), Cursor (hook + OS sandbox)"
        ),
        "{home}"
    );
}

#[test]
fn a_drifted_sandbox_is_hook_only_and_says_which() {
    let sb = Sandbox::installed(&[".codex"]);
    let path = sb.home.join(".codex/config.toml");
    let weakened = fs::read_to_string(&path).unwrap().replace(
        "default_permissions = \"moat\"",
        "default_permissions = \":workspace\"",
    );
    fs::write(&path, weakened).unwrap();
    let codex = agent(&sb, "codex");
    assert_eq!(codex["level"], "hook-only", "{codex}");
    let reason = codex["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("sandbox: default_permissions is not \"moat\""),
        "{reason}"
    );
    let status = squash(&stdout(&sb.moat(&["status"])));
    assert!(
        status.contains("! Codex hook only (sandbox: default_permissions"),
        "{status}"
    );
    assert!(
        status.contains("✗ Codex sandbox: default_permissions"),
        "the drift needs the person: {status}"
    );
}

#[test]
fn a_missing_hook_is_not_protected_and_absent_agents_keep_their_line() {
    let sb = Sandbox::installed(&[".claude"]);
    fs::write(sb.home.join(".claude/settings.json"), "{}").unwrap();
    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "not-protected", "{claude}");
    assert_eq!(claude["reason"], "hook missing", "{claude}");
    assert_eq!(agent(&sb, "codex")["level"], "not-found");

    let status = squash(&stdout(&sb.moat(&["status"])));
    assert!(
        status.contains("✗ Claude Code not protected (hook missing)\n"),
        "{status}"
    );
    assert!(
        status.contains("✗ Claude Code hook missing → openmoat init\n"),
        "{status}"
    );
    // agents with no folder share one line
    let not_found = status
        .lines()
        .find(|l| l.starts_with(" – Not installed: "))
        .expect(&status);
    assert!(not_found.contains("Codex"), "{status}");
    assert!(!not_found.contains("Claude Code"), "{status}");
    assert!(!status.contains("host not found"), "{status}");
    assert!(!status.contains("✗ Codex"), "{status}");
    assert!(!status.contains("known gaps"), "{status}");

    let home = text(&output(&mut sb.command(), Some("")));
    assert!(home.contains("No agent is protected"), "{home}");
}

/// A Claude Code older than 2.1.295 gets no `onFailure` and `doctor` says the
/// call then runs when the hook fails; once Claude Code is updated the hook is
/// out of date until `moat init` adds the key.
#[test]
fn an_older_claude_code_gets_no_on_failure_until_it_is_updated() {
    let sb = Sandbox::bare(&[".claude"]);
    let old = |args: &[&str]| {
        output(
            sb.command()
                .args(args)
                .env("MOAT_CLAUDE_CODE_VERSION", "2.1.200 (Claude Code)"),
            None,
        )
    };
    let out = old(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let settings = sb.home.join(".claude/settings.json");
    let handler = || -> Value {
        let doc: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        doc["hooks"]["PreToolUse"][0]["hooks"][0].clone()
    };
    assert!(handler().get("onFailure").is_none(), "{}", handler());
    let doctor = stdout(&old(&["doctor"]));
    assert!(doctor.contains("no `onFailure: \"block\"`"), "{doctor}");
    assert_eq!(agent(&sb, "claude-code")["reason"], "hook out of date");

    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(handler()["onFailure"], "block");
    let doctor = stdout(&sb.moat(&["doctor"]));
    assert!(!doctor.contains("onFailure"), "{doctor}");
}

/// The Claude Code extension for VS Code bundles its own Claude Code and puts
/// no `claude` on `PATH`: `init` reads the extension's version from VS Code's
/// `extensions.json` and writes `onFailure` for it, and `doctor` and `status`
/// name the copy. An older copy beside it leaves the key out, as an older
/// `claude` on `PATH` does.
#[test]
fn the_vs_code_extensions_claude_code_gets_on_failure() {
    for (versions, blocks) in [
        (&["2.1.318"][..], true),
        (&["2.1.318", "2.1.200"][..], false),
    ] {
        let sb = Sandbox::bare(&[".claude"]);
        let extensions = sb.home.join(".vscode/extensions");
        let entries: Vec<Value> = versions
            .iter()
            .map(|version| {
                let folder = format!("anthropic.claude-code-{version}-darwin-arm64");
                fs::create_dir_all(extensions.join(&folder)).unwrap();
                serde_json::json!({"identifier": {"id": "anthropic.claude-code"},
                    "version": version, "relativeLocation": folder})
            })
            .collect();
        fs::write(
            extensions.join("extensions.json"),
            Value::from(entries).to_string(),
        )
        .unwrap();
        // No `claude` on `PATH`: only the extension's copies.
        let no_cli = |args: &[&str]| {
            output(
                sb.command().args(args).env("MOAT_CLAUDE_CODE_VERSION", ""),
                None,
            )
        };
        let out = no_cli(&["init", "--yes"]);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        let settings = sb.home.join(".claude/settings.json");
        let doc: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        let handler = &doc["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(
            handler.get("onFailure").is_some(),
            blocks,
            "{versions:?}: {handler}"
        );
        // each copy is a detail line, shown with `--verbose`; a warning shows either way
        let doctor = stdout(&no_cli(&["doctor", "--verbose"]));
        for version in versions {
            let copy = format!("Claude Code {version} bundled by the VS Code extension");
            assert!(doctor.contains(&copy), "{doctor}");
        }
        assert_eq!(
            doctor.contains("no `onFailure: \"block\"`"),
            !blocks,
            "{doctor}"
        );
        let status = squash(&stdout(&no_cli(&["status"])));
        assert!(
            status.contains("bundled by the VS Code extension"),
            "{status}"
        );
    }
}

/// #327: Claude Code's sandbox cannot run on native Windows, so its hook is all
/// OpenMoat gives it there.
#[cfg(windows)]
#[test]
fn claude_code_on_native_windows_is_hook_only() {
    let sb = Sandbox::installed(&[".claude"]);
    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "hook-only", "{claude}");
    assert!(
        claude["reason"]
            .as_str()
            .unwrap()
            .starts_with("sandbox not available on native Windows"),
        "{claude}"
    );
    let status = squash(&stdout(&sb.moat(&["status"])));
    assert!(
        status.contains(" Claude Code hook only (sandbox not available"),
        "{status}"
    );
    let home = text(&output(&mut sb.command(), Some("")));
    assert!(
        home.contains("Protecting Claude Code (hook only)"),
        "{home}"
    );
}

/// Where each of `parts` first starts in `out`, which must have them all, in
/// this order.
fn in_order(out: &str, parts: &[&str]) {
    let mut at = 0;
    for part in parts {
        let found = out[at..]
            .find(part)
            .unwrap_or_else(|| panic!("{part:?} after byte {at} in {out}"));
        at += found + part.len();
    }
}

#[test]
fn status_and_doctor_print_their_sections_in_order() {
    let sb = Sandbox::installed(&[".codex"]);
    let status = squash(&stdout(&sb.moat(&["status"])));
    // `status` names the agents found (here Codex) one per line, the agents
    // with no folder on one line, then OpenMoat's own state.
    in_order(
        &status,
        &[
            " · status\n",
            "\nAgents\n",
            " Codex hook + OS sandbox\n",
            " – Not installed: ",
            "\nOpenMoat\n",
            "✔ Policy ",
            "✔ Lock ",
            " MCP servers ",
            "· Approvals ",
            "✔ Audit log ",
        ],
    );
    let doctor = squash(&stdout(&sb.moat(&["doctor"])));
    in_order(
        &doctor,
        &[
            " · doctor\n",
            "\nAgents\n",
            " Codex hook + OS sandbox\n",
            " – Not installed: ",
            "\nOpenMoat\n",
            "✔ Policy ",
            "✔ Lock ",
            "✔ Audit log ",
        ],
    );
    // No problem: the last line says so (a warning may still need a look).
    let last = doctor.lines().last().unwrap_or_default();
    assert!(
        last.ends_with("known gaps per agent: openmoat doctor --verbose"),
        "{doctor}"
    );
    // Every check, the agents not found included, with --verbose.
    let verbose = squash(&stdout(&sb.moat(&["doctor", "--verbose"])));
    in_order(
        &verbose,
        &[
            "\nEvery check\n",
            "✔ State directory ",
            "✔ Policy lints",
            "✔ Lock ",
            "✔ Environment ",
            "· Claude Code host not found",
            "✔ Codex hook installed",
            "✔ Audit log ",
        ],
    );
}

#[test]
fn status_and_doctor_report_a_missing_lock_and_audit_log() {
    let sb = Sandbox::installed(&[".codex"]);
    fs::remove_file(sb.home.join(".moat/policy.lock")).unwrap();
    fs::remove_file(sb.home.join(".moat/audit.db")).unwrap();
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    let status = squash(&stdout(&out));
    for line in [
        "✗ Lock missing → openmoat init\n",
        "· Approvals no active session grants\n",
        "✗ Audit log missing → openmoat init\n",
    ] {
        assert!(status.contains(line), "{line:?} in {status}");
    }
    in_order(&status, &["Needs your attention", "✗ Lock", "\nAgents\n"]);
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    let doctor = squash(&stdout(&out));
    assert!(
        doctor.contains("✗ Lock missing → openmoat init\n"),
        "{doctor}"
    );
    assert!(doctor.contains("✗ Audit log "), "{doctor}");
    in_order(&doctor, &["Needs your attention", "✗ Lock", "\nAgents\n"]);
    assert!(
        doctor
            .lines()
            .last()
            .is_some_and(|l| l.contains(" need you · `openmoat init` re-installs and re-pins")),
        "{doctor}"
    );
}

/// `moat doctor --format json`: the same rows as the text, one document, and
/// the same exit code; nothing else on stdout.
#[test]
fn doctor_prints_its_checks_as_one_json_document() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["doctor", "--format", "json"]);
    let doc = json(&out);
    let checks = doc["checks"].as_array().expect("checks");
    assert!(!checks.is_empty(), "{}", text(&out));
    assert_eq!(
        doc["healthy"],
        out.status.code() == Some(OK),
        "{}",
        text(&out)
    );
    assert!(
        checks
            .iter()
            .any(|c| c["status"] == "ok" && c["name"] == "state directory"),
        "{}",
        text(&out)
    );
    assert!(
        checks
            .iter()
            .all(|c| ["ok", "problem", "warning", "note"]
                .contains(&c["status"].as_str().unwrap_or(""))),
        "{}",
        text(&out)
    );
    let refused = sb.moat(&["doctor", "--format", "json", "--accept"]);
    assert_ne!(refused.status.code(), Some(OK), "json never accepts");
}

/// `moat status --format json` also says whether a policy update waits for
/// `moat policy upgrade` and which pinned files changed, for tools such as the
/// menu bar app that show them.
#[test]
fn status_json_reports_a_waiting_update_and_lock_drift() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["status", "--format", "json"]);
    let doc = json(&out);
    assert!(doc["policy_update"].is_null(), "{}", text(&out));
    assert_eq!(doc["lock_drift"], serde_json::json!([]), "{}", text(&out));

    let policy = sb.home.join(".moat/policy.yaml");
    let edited = fs::read_to_string(&policy).unwrap() + "\n# edited by hand\n";
    fs::write(&policy, edited).unwrap();
    let doc = json(&sb.moat(&["status", "--format", "json"]));
    let drift = doc["lock_drift"].as_array().unwrap();
    assert!(
        drift
            .iter()
            .any(|d| d.as_str().unwrap().contains("policy.yaml")),
        "{doc}"
    );
}
