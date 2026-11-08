//! Payloads captured from a real agent (`host/<module>/fixtures/captured-*.json`),
//! as the weekly latest-agents job copies them from `openmoat guard`'s stdin
//! (`scripts/ci/latest-agents/README.md`, "Captured payloads") and
//! `check.py scrub` writes them: each one parses with its own adapter into a
//! hook event, so an agent release that changes its payload fails here once
//! its capture is committed, not only in the fixtures built from its source.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::Host;

fn host_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/host")
}

/// The host whose adapter lives in `src/host/<module>`: its id with `-` as
/// `_`, or its id plus `_cli` (`continue` lives in `continue_cli`).
fn host_of(module: &str) -> Option<Host> {
    Host::EVERY.into_iter().find(|host| {
        let id = host.id().replace('-', "_");
        id == module || format!("{id}_cli") == module
    })
}

/// Every captured payload, with the host whose fixtures folder holds it.
fn captured() -> Vec<(Host, PathBuf)> {
    let mut found = Vec::new();
    for entry in fs::read_dir(host_dir()).unwrap().flatten() {
        let fixtures = entry.path().join("fixtures");
        if !fixtures.is_dir() {
            continue;
        }
        let module = entry.file_name().to_string_lossy().into_owned();
        let host = host_of(&module).unwrap_or_else(|| panic!("no host for src/host/{module}"));
        for file in fs::read_dir(&fixtures).unwrap().flatten() {
            let path = file.path();
            let name = file.file_name().to_string_lossy().into_owned();
            if name.starts_with("captured-") && path.extension().is_some_and(|e| e == "json") {
                found.push((host, path));
            }
        }
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

#[test]
fn every_fixtures_folder_belongs_to_a_host() {
    for entry in fs::read_dir(host_dir()).unwrap().flatten() {
        if entry.path().join("fixtures").is_dir() {
            let module = entry.file_name().to_string_lossy().into_owned();
            assert!(
                host_of(&module).is_some(),
                "src/host/{module}/fixtures has no host"
            );
        }
    }
}

#[test]
fn every_captured_payload_parses_with_its_adapter() {
    for (host, path) in captured() {
        let text = fs::read_to_string(&path).unwrap();
        // A tool call is read as an action; another event (a session start,
        // a tool's result) parses with none.
        host.parse_request(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let home = [
            "/Users/runner",
            "/home/runner",
            "/private/var",
            "/tmp/latest-",
        ];
        assert!(
            !home.iter().any(|h| text.contains(h)),
            "{}: not scrubbed (`check.py scrub`): a runner path is left",
            path.display()
        );
    }
}
