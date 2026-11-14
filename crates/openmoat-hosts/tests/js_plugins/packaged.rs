//! The extension of pi's package (`plugins/pi/openmoat.js`, harness
//! `packaged.mjs`, ADR-099): it runs the binary the policy lock pins (off the
//! search path) with `--plugin` and no state directory, for its heartbeat and
//! each call, passes a deny on, blocks a call when the lock names no program
//! it can run, and without a lock or an `openmoat` blocks the call naming the
//! install command. The harness's stand-in runs through its `#!` line: Unix only.
#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use openmoat_hosts::{NOT_INSTALLED, PLUGIN_FLAG};

#[test]
fn the_pi_package_runs_openmoat_from_the_search_path_and_blocks_without_it() {
    let Some(node) = super::node() else {
        eprintln!("skipping the pi package test: `node` is not on PATH");
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(node)
        .arg(root.join("tests/js_plugins/packaged.mjs"))
        .arg(root.join("../../plugins/pi/openmoat.js"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "packaged harness failed: {}\n{stdout}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        report["argv"],
        serde_json::json!(["guard", "--host", "pi", PLUGIN_FLAG]),
        "{report}"
    );
    assert_eq!(
        report["heartbeats"],
        serde_json::json!([["guard", "--heartbeat", "--host", "pi", PLUGIN_FLAG]]),
        "{report}"
    );
    assert_eq!(report["denied"], "blocked: moat: deny [x]", "{report}");
    // No lock and nothing on the search path: blocked. A machine with
    // OpenMoat in a folder its installers use runs that one instead, whose
    // guard finds no lock in the scratch home and denies, naming `openmoat init`.
    let missing = report["missing"].as_str().unwrap();
    assert!(
        missing.starts_with("blocked: ")
            && (missing.contains(NOT_INSTALLED) || missing.contains("openmoat init")),
        "{missing}"
    );
    let unusable = report["unusable"].as_str().unwrap();
    assert!(
        unusable.starts_with("blocked: OpenMoat blocked this call: ")
            && unusable.contains(openmoat_hosts::LOCK_UNUSABLE),
        "{unusable}"
    );
}
