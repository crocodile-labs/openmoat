//! OpenMoat's JavaScript plugins (`src/host/<module>/integration/`) run under
//! Node, each against a stand-in for its host and for `openmoat guard`
//! (`common.mjs` and a harness per plugin): what each outcome of the guard
//! becomes in the host, that every failure blocks, and that the plugin reports
//! loading (`--heartbeat`). OpenClaw's adds the ordering of plugins.
//!
//! Each test skips, saying why, when `node` is not on the search path.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod openclaw;
mod opencode;
mod pi;

/// `node` on the search path.
fn node() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["node.exe"]
    } else {
        &["node"]
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|path| path.is_file())
}

/// The report `tests/js_plugins/<harness>.mjs` prints for the plugin at
/// `src/host/<plugin>`, or `None` (said on stderr) without `node`.
fn report(harness: &str, plugin: &str) -> Option<Value> {
    let Some(node) = node() else {
        eprintln!("skipping the {harness} plugin test: `node` is not on PATH");
        return None;
    };
    Some(run(&node, harness, plugin))
}

fn run(node: &Path, harness: &str, plugin: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(node)
        .arg(root.join(format!("tests/js_plugins/{harness}.mjs")))
        .arg(root.join("src/host").join(plugin))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{harness} harness failed: {}\n{stdout}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

/// The entry of `report[list]` whose `key` is `name`.
fn entry<'a>(report: &'a Value, list: &str, key: &str, name: &str) -> &'a Value {
    report[list]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r[key] == name)
        .unwrap_or_else(|| panic!("no {list} entry {name}: {report}"))
}

/// The heartbeats the plugin sent: `guard --heartbeat --host <id>`, once.
fn assert_one_heartbeat(report: &Value, id: &str) {
    assert_eq!(
        report["heartbeats"],
        serde_json::json!([["--heartbeat", "--host", id]]),
        "{report}"
    );
}
