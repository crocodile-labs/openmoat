//! The extension of pi's package (`plugins/pi/openmoat.js`, harness
//! `packaged.mjs`, ADR-095): it runs the `openmoat` on the search path with
//! `--plugin` and no state directory, for its heartbeat and each call, passes
//! a deny on, and with no `openmoat` blocks the call naming the install
//! command. The harness's stand-in runs through its `#!` line: Unix only.
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
    let missing = report["missing"].as_str().unwrap();
    assert!(
        missing.starts_with("blocked: OpenMoat blocked this call: ")
            && missing.contains(NOT_INSTALLED),
        "{missing}"
    );
}
