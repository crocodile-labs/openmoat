//! The fail-safe tail of the hook commands `init` writes (ADR-109): run by a
//! real POSIX shell, a guard that is missing or killed exits 2 with a reason,
//! the block every host with the tail reads; the guard's own answers pass.

use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

use openmoat_hosts::Host;
use serde_json::Value;

use crate::common::{Sandbox, text};
use crate::hosts::{dir_of, hook_file};

/// The marker of the tail in a command `init` wrote.
const TAIL: &str = "; s=$?;";

fn commands(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) if s.contains(TAIL) => out.push(s.clone()),
        Value::Array(list) => list.iter().for_each(|v| commands(v, out)),
        Value::Object(map) => map.values().for_each(|v| commands(v, out)),
        _ => {}
    }
}

/// `command` run by `sh` with `binary` in place of the installed one.
fn run(command: &str, installed: &str, binary: &str) -> std::process::Output {
    let command = command.replacen(installed, binary, 1);
    Command::new("sh")
        .args(["-c", &command])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn a_missing_or_killed_guard_exits_two_and_its_answers_pass() {
    let installed = env!("CARGO_BIN_EXE_openmoat");
    let dir = tempfile::tempdir().unwrap();
    let fake = |name: &str, body: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    };
    let killed = fake("killed", "kill -9 $$");
    let allows = fake("allows", "echo '{}'");
    let denies = fake("denies", "echo '{\"deny\":1}'; exit 2");
    let missing = dir.path().join("gone/openmoat").display().to_string();
    let mut seen = Vec::new();
    // The agents ADR-109 gives the tail.
    let expected = [Host::Codex, Host::GeminiCli, Host::QwenCode, Host::Crush];
    for host in expected {
        let sb = Sandbox::bare(&[&dir_of(host)]);
        let out = sb.moat(&["init", "--yes", "--hosts", host.id()]);
        assert_eq!(out.status.code(), Some(0), "{host}: {}", text(&out));
        let Ok(file) = std::fs::read_to_string(hook_file(&sb, host)) else {
            continue;
        };
        let Ok(root) = serde_json::from_str::<Value>(&file) else {
            continue;
        };
        let mut found = Vec::new();
        commands(&root, &mut found);
        for command in found.iter().filter(|c| c.contains(installed)) {
            if !seen.contains(&host) {
                seen.push(host);
            }
            for binary in [&missing, &killed] {
                let out = run(command, installed, binary);
                assert_eq!(
                    out.status.code(),
                    Some(2),
                    "{host} {binary}: {}",
                    text(&out)
                );
                assert!(text(&out).contains("the call is blocked"), "{}", text(&out));
            }
            let out = run(command, installed, &allows);
            assert_eq!(out.status.code(), Some(0), "{host}: {}", text(&out));
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "{}");
            let out = run(command, installed, &denies);
            assert_eq!(out.status.code(), Some(2), "{host}: {}", text(&out));
            assert!(String::from_utf8_lossy(&out.stdout).contains("deny"));
        }
    }
    assert_eq!(
        seen, expected,
        "the hook commands that carry the fail-safe tail"
    );
}
