//! Tool arguments an agent controls, spelled so a host reads one file while a
//! careless adapter would hand the guard another: each must still reach the
//! host as the deny (or ask) the plain spelling gets.

use openmoat_core::Verdict;
use openmoat_hosts::Host;
use serde_json::json;

use super::payloads::{copilot, gemini, openclaw, opencode, pi};
use super::{Route, decide, pre_tool_use};

/// The verdict `host` receives for `payload`, and the rules behind it.
fn received(host: Host, payload: &serde_json::Value) -> (Verdict, Vec<String>) {
    let (_, decision) = decide(host, &payload.to_string()).unwrap();
    (decision.verdict, decision.rules)
}

/// OpenClaw expands a `~` `workdir` itself; a relative file name in the
/// command is then in the home directory, not below a directory named `~`.
#[test]
fn openclaw_exec_in_a_home_workdir_is_decided_there() {
    for workdir in ["~/.ssh", "~/.ssh/"] {
        let payload = openclaw(
            "exec",
            &json!({"command": "cat id_rsa", "workdir": workdir}),
        );
        let (verdict, rules) = received(Host::OpenClaw, &payload);
        assert_eq!(verdict, Verdict::Deny, "{workdir}: {rules:?}");
        assert!(rules.iter().any(|r| r == "secrets-paths"), "{rules:?}");
    }
}

/// Claude Code's `Artifact` uploads local files to a claude.ai page, where
/// the page's own script can send them on: a secret source is denied as a
/// read, also when it is relative to `root`.
#[test]
fn claude_code_artifact_upload_of_a_secret_is_denied() {
    for input in [
        json!({"file_path": "/p/index.html", "files": {"k.txt": "/Users/me/.ssh/id_rsa"}}),
        json!({"file_path": "/p/index.html", "root": "/Users/me/.ssh", "files": {"k": "id_rsa"}}),
        json!({"url": "u", "asset": true, "file_paths": ["/Users/me/.aws/credentials"]}),
    ] {
        let payload = pre_tool_use(Route::ClaudeCode, "Artifact", &input);
        let (verdict, rules) = received(Host::ClaudeCode, &payload);
        assert_eq!(verdict, Verdict::Deny, "{input}: {rules:?}");
        assert!(rules.iter().any(|r| r == "secrets-paths"), "{rules:?}");
    }
}

/// A glob pattern whose `..` climbs out of the searched directory, also after
/// a wildcard (`*/..`), reads where it lands: every host's search and glob
/// tools are denied a secret directory reached that way.
#[test]
fn glob_patterns_that_climb_to_a_secret_are_denied() {
    let climbs = [
        "../Users/me/.ssh/*",
        "*/../../Users/me/.ssh/*",
        "/p/*/../../Users/me/.ssh/id_rsa",
    ];
    for pattern in climbs {
        let payloads = [
            (
                Host::ClaudeCode,
                pre_tool_use(Route::ClaudeCode, "Glob", &json!({"pattern": pattern})),
            ),
            (
                Host::GeminiCli,
                gemini("glob", &json!({"pattern": pattern})),
            ),
            (
                Host::GeminiCli,
                gemini("read_many_files", &json!({"include": [pattern]})),
            ),
            (
                Host::CopilotCli,
                copilot("glob", &json!({"pattern": pattern})),
            ),
            (Host::Pi, pi("find", &json!({"pattern": pattern}))),
            (
                Host::OpenCode,
                opencode("glob", &json!({"pattern": pattern})),
            ),
        ];
        for (host, payload) in payloads {
            let (verdict, rules) = received(host, &payload);
            assert_eq!(verdict, Verdict::Deny, "{host:?} {pattern}: {rules:?}");
            assert!(rules.iter().any(|r| r == "secrets-paths"), "{rules:?}");
        }
    }
}
